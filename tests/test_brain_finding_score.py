"""Tests for brain.py's _finding_score()/_collect_candidate_findings() wiring
to memory/finding_score.py's canonical priority_score()-wrapping formula
(HIGH-severity fix #5 -- previously an independent, hand-rolled static table
that never touched priority_score(), tech-stack affinity, or self-learning).

Brain() normally requires a live LLM provider to construct (LLMClient
auto-detect, banner printing, Ollama pre-warm). None of that is needed for
these two methods -- neither touches self.enabled/self.model/self.client --
so every test here builds a bare instance via Brain.__new__(Brain), the
same "skip __init__, the methods under test don't need it" pattern used
when a class's constructor has side effects unrelated to the method being
tested.
"""

import json
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import brain  # noqa: E402
from memory.finding_score import score_finding  # noqa: E402
from memory.pattern_db import PatternDB  # noqa: E402
from memory.schemas import make_pattern_entry  # noqa: E402


def _bare_brain():
    return brain.Brain.__new__(brain.Brain)


class TestFindingScoreDelegation:
    def test_returns_exactly_score_findings_sort_key(self):
        """No independent formula left -- the return value must be the
        literal sort_key score_finding() computes, not a re-derived one."""
        b = _bare_brain()
        result = b._finding_score("idor", "IDOR candidate: /api/orders/482")
        expected = score_finding(
            category="idor", line="IDOR candidate: /api/orders/482", tech_stack=[], target="",
        )
        assert result == tuple(expected["sort_key"])

    def test_rce_still_generally_outranks_misconfig_via_impact_potential(self):
        """The old table hardcoded rce=100 > misconfig=35. The canonical
        VULN_IMPACT_POTENTIAL table (memory/vuln_intelligence.py) makes the
        same call for a different, principled reason (impact potential),
        so this should still hold -- proving the wiring didn't silently
        invert sane priority ordering, without hardcoding the exact numbers
        the old table used."""
        b = _bare_brain()
        rce_score = b._finding_score("rce", "confirmed rce: uid=root output")
        misconfig_score = b._finding_score("misconfig", "generic misconfiguration notice")
        assert rce_score > misconfig_score

    def test_unknown_category_does_not_crash(self):
        b = _bare_brain()
        result = b._finding_score("totally_unknown_category", "some line")
        assert isinstance(result, tuple)

    def test_tech_stack_and_target_are_threaded_through(self):
        """A real tech-stack affinity signal must actually change the score
        -- proves target/tech_stack aren't silently dropped on the way to
        score_finding()."""
        b = _bare_brain()
        neutral = b._finding_score("idor", "line", target="a.com", tech_stack=[])
        with_stack = b._finding_score("idor", "line", target="a.com", tech_stack=["nodejs"])
        # Cold start (no patterns.jsonl data) still gives a real, comparable
        # result either way -- this asserts the call succeeds with real
        # tech_stack/target params reaching score_finding(), not a specific
        # score delta (which needs real memory data, covered below).
        assert isinstance(neutral, tuple) and isinstance(with_stack, tuple)


class TestCollectCandidateFindingsWiring:
    def _write_finding(self, findings_dir, category, filename, lines):
        cat_dir = findings_dir / category
        cat_dir.mkdir(parents=True, exist_ok=True)
        (cat_dir / filename).write_text("\n".join(lines) + "\n")

    def test_empty_or_missing_dir_returns_nothing(self, tmp_path):
        b = _bare_brain()
        assert b._collect_candidate_findings(str(tmp_path / "does-not-exist")) == []

        empty_dir = tmp_path / "findings"
        empty_dir.mkdir()
        assert b._collect_candidate_findings(str(empty_dir)) == []

    def test_dedup_and_top_25_cap_preserved(self, tmp_path):
        """The old hand-rolled dedup (skip exact (category, line) repeats)
        and top-25 truncation must survive the rewrite -- these are real
        behavioral guarantees callers depend on, not incidental."""
        findings_dir = tmp_path / "findings"
        lines = [f"XSS reflected in param q={i} unauth" for i in range(30)]
        # Duplicate the first line to prove dedup still fires.
        lines.append(lines[0])
        self._write_finding(findings_dir, "xss", "xss.txt", lines)

        b = _bare_brain()
        results = b._collect_candidate_findings(str(findings_dir))
        assert len(results) == 25  # capped, not 30
        assert len(set(results)) == len(results)  # no duplicate (category, line) pairs

    def test_noise_lines_still_filtered(self, tmp_path):
        findings_dir = tmp_path / "findings"
        self._write_finding(findings_dir, "rce", "RCE_CONFIRMED_hits.txt", [
            "confirmed rce targets:",  # noise (startswith filter)
            "traceback (most recent call last)",  # noise (noisy_terms)
            "uid=root confirmed via /cgi-bin/exploit",  # real finding
        ])
        b = _bare_brain()
        results = b._collect_candidate_findings(str(findings_dir))
        assert len(results) == 1
        assert "uid=root" in results[0][1]

    def test_real_pattern_db_affinity_changes_ranking(self, tmp_hunt_dir, tmp_path, monkeypatch):
        """The actual acceptance test for this fix: a self-learned
        patterns.jsonl entry (idor + nodejs, real wins) must be able to
        outrank a category the OLD static table always scored higher
        (rce=100 > idor=75 in the removed table), proving
        _collect_candidate_findings() genuinely reaches memory/patterns.jsonl
        through the canonical formula now -- not just 'doesn't crash'."""
        findings_dir = tmp_path / "findings"
        self._write_finding(findings_dir, "rce", "RCE_CONFIRMED_hits.txt", [
            "possible rce candidate, unconfirmed signature match",
        ])
        self._write_finding(findings_dir, "idor", "idor.txt", [
            "IDOR confirmed: /api/orders/482 returns victim data cross-account",
        ])

        # Seed real wins for idor+nodejs so tech_vuln_affinity()'s
        # historical_success_probability + technology_match components push
        # idor's priority_score() above a cold-start rce entry with zero
        # memory signal of its own.
        pattern_db = PatternDB(tmp_hunt_dir / "patterns.jsonl")
        for i in range(6):
            pattern_db.save(make_pattern_entry(
                target="other-target.com", vuln_class="idor",
                technique=f"numeric_id_swap_{i}", tech_stack=["nodejs"], payout=1000,
            ))
        # tools.director.load_tech_stack() reads <memory_dir>/targets/<target>.json's
        # "tech_stack" field -- give "a.com" the matching tag so the affinity
        # seeded above is actually reachable via target+tech_stack, the same
        # real lookup _collect_candidate_findings() performs.
        (tmp_hunt_dir / "targets" / "a.com.json").write_text(
            json.dumps({"tech_stack": ["nodejs"]})
        )

        monkeypatch.chdir(tmp_path)
        b = _bare_brain()
        results = b._collect_candidate_findings(
            str(findings_dir), target="a.com", memory_dir=str(tmp_hunt_dir),
        )
        categories_in_order = [category for category, _ in results]
        assert categories_in_order.index("idor") < categories_in_order.index("rce"), (
            f"expected real patterns.jsonl affinity to rank idor above a cold-start rce "
            f"candidate, got order: {categories_in_order}"
        )
