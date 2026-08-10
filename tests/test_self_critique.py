"""Tests for tools/self_critique.py — Phase 7 Part B (the Self-Critique Gate)."""

import pytest

from memory.candidate import make_candidate
from memory.object_model import make_observation
from memory.identity import entity_id, object_id
from memory.vuln_intelligence import DEFAULT_DEDUP_PROBABILITY, MIN_SAMPLES_FOR_DEDUP_PROBABILITY, priority_score
from tools import self_critique as sc
from tools import lead_board as lb


def _candidate(**overrides):
    base = dict(
        source="manual",
        type_="idor",
        evidence=[{"type": "Observed-HTTP-Response", "detail": "d", "artifact": "a"}],
        rationale="attacker can read victim's order via /api/orders/:id",
        validation_plan={
            "steps": [{"method": "GET", "url": "https://example.com/api/orders/42"}],
            "expected": "403",
            "stop_condition": "retry fails -> not reproducible",
        },
        metadata={"target": "example.com"},
    )
    base.update(overrides)
    return make_candidate(**base)


class _FakeResponse:
    def __init__(self, status_code):
        self.status_code = status_code


class _MockFetcher:
    """Returns statuses[call_index] on each successive .request() call,
    regardless of method/url — enough to prove the reproducibility check
    genuinely calls the fetcher twice per step rather than checking once."""

    def __init__(self, statuses):
        self.statuses = list(statuses)
        self.calls = 0

    def request(self, method, url):
        status = self.statuses[self.calls]
        self.calls += 1
        return _FakeResponse(status)


class _RaisingFetcher:
    def request(self, method, url):
        raise RuntimeError("scope violation")


# ─── 1. Reproducibility ──────────────────────────────────────────────────

class TestReproducibility:
    def test_passing_case_reproduces_and_matches_expected(self):
        candidate = _candidate()
        fetcher = _MockFetcher([403, 403])
        result = sc.check_reproducibility(candidate, fetcher)
        assert result["status"] == "pass"
        assert fetcher.calls == 2

    def test_flaky_result_blocks(self):
        """Genuinely re-runs (not just checks once): a fetcher returning a
        DIFFERENT result on the 2nd call must BLOCK."""
        candidate = _candidate()
        fetcher = _MockFetcher([403, 200])
        result = sc.check_reproducibility(candidate, fetcher)
        assert result["status"] == "block"
        assert "non-reproducible" in result["reason"]
        assert fetcher.calls == 2

    def test_reproducible_but_not_matching_expected_blocks(self):
        candidate = _candidate()
        fetcher = _MockFetcher([200, 200])
        result = sc.check_reproducibility(candidate, fetcher)
        assert result["status"] == "block"
        assert "does not match" in result["reason"]

    def test_no_executable_steps_blocks(self):
        candidate = _candidate(validation_plan={
            "steps": ["retry as non-owner"], "expected": "403", "stop_condition": "x",
        })
        result = sc.check_reproducibility(candidate, _MockFetcher([403, 403]))
        assert result["status"] == "block"
        assert "no machine-executable" in result["reason"]

    def test_no_parseable_expected_blocks(self):
        candidate = _candidate(validation_plan={
            "steps": [{"method": "GET", "url": "https://example.com/x"}],
            "expected": "should be forbidden", "stop_condition": "x",
        })
        result = sc.check_reproducibility(candidate, _MockFetcher([403, 403]))
        assert result["status"] == "block"
        assert "no parseable HTTP status" in result["reason"]

    def test_fetcher_exception_blocks(self):
        candidate = _candidate()
        result = sc.check_reproducibility(candidate, _RaisingFetcher())
        assert result["status"] == "block"
        assert "request failed" in result["reason"]

    def test_no_fetcher_supplied_blocks_overall(self):
        candidate = _candidate()
        report = sc.self_critique(candidate, fetcher=None)
        repro = report["details"]["reproducibility"]
        assert repro["status"] == "block"
        assert report["overall"] == "block"


# ─── 2. Duplicate probability ────────────────────────────────────────────

class TestDuplicateProbability:
    def _outcomes(self, n_dup, n_total, vuln_class="idor"):
        outcomes = []
        for i in range(n_dup):
            outcomes.append({"target": "t", "vuln_class": vuln_class, "outcome": "duplicate", "platform": "hackerone"})
        for i in range(n_total - n_dup):
            outcomes.append({"target": "t", "vuln_class": vuln_class, "outcome": "accepted", "platform": "hackerone"})
        return outcomes

    def test_cold_start_passes(self):
        candidate = _candidate()
        result = sc.check_duplicate_probability(candidate, report_outcomes=[])
        assert result["status"] == "pass"
        assert result["details"]["dedup_probability"]["sample_size"] == 0

    def test_sample_backed_elevated_with_novel_impact_warns(self):
        assert MIN_SAMPLES_FOR_DEDUP_PROBABILITY == 5
        outcomes = self._outcomes(n_dup=4, n_total=5)  # 0.8 > 0.5, sample_size 5
        candidate = _candidate(metadata={
            "target": "example.com",
            "novel_impact_argument": "this chains into full account takeover, unlike prior reports",
        })
        result = sc.check_duplicate_probability(candidate, report_outcomes=outcomes)
        assert result["status"] == "warn"

    def test_sample_backed_elevated_without_novel_impact_blocks(self):
        outcomes = self._outcomes(n_dup=4, n_total=5)
        candidate = _candidate()  # default metadata has no novel_impact_argument field
        result = sc.check_duplicate_probability(candidate, report_outcomes=outcomes)
        assert result["status"] == "block"

    def test_sample_backed_elevated_with_blank_novel_impact_blocks(self):
        """A present-but-empty/whitespace-only field must not count as an
        argument -- BLOCK, not WARN, on the same elevated-probability case."""
        outcomes = self._outcomes(n_dup=4, n_total=5)
        candidate = _candidate(metadata={"target": "example.com", "novel_impact_argument": "   "})
        result = sc.check_duplicate_probability(candidate, report_outcomes=outcomes)
        assert result["status"] == "block"

    def test_low_probability_passes_even_with_samples(self):
        outcomes = self._outcomes(n_dup=1, n_total=5)  # 0.2, below DEFAULT_DEDUP_PROBABILITY
        candidate = _candidate()
        result = sc.check_duplicate_probability(candidate, report_outcomes=outcomes)
        assert result["status"] == "pass"

    def test_reuses_dedup_probability_not_a_new_formula(self):
        """The exact result dict is whatever memory.vuln_intelligence.dedup_probability()
        returns, unmodified — this check does not recompute the probability itself."""
        from memory.vuln_intelligence import dedup_probability
        outcomes = self._outcomes(n_dup=4, n_total=5)
        candidate = _candidate()
        expected = dedup_probability(vuln_class="idor", report_outcomes=outcomes)
        result = sc.check_duplicate_probability(candidate, report_outcomes=outcomes)
        assert result["details"]["dedup_probability"] == expected

    # ── HIGH-severity fix: a bare non-empty string is no longer enough to
    # defeat an elevated-duplicate-probability BLOCK; it must clear a real
    # minimum length (MIN_NOVEL_IMPACT_ARGUMENT_LENGTH, reused from
    # secrets_scanner.py's ENTROPY_MIN_LENGTH convention), and verbatim
    # reuse across Candidates for the same target is now flagged.

    def test_too_short_novel_impact_argument_blocks(self):
        assert sc.MIN_NOVEL_IMPACT_ARGUMENT_LENGTH == 20
        outcomes = self._outcomes(n_dup=4, n_total=5)
        candidate = _candidate(metadata={"target": "example.com", "novel_impact_argument": "yes it is novel"})
        assert len(candidate["metadata"]["novel_impact_argument"]) < sc.MIN_NOVEL_IMPACT_ARGUMENT_LENGTH
        result = sc.check_duplicate_probability(candidate, report_outcomes=outcomes)
        assert result["status"] == "block"
        assert "20 characters" in result["reason"]

    def test_exactly_min_length_novel_impact_argument_warns(self):
        outcomes = self._outcomes(n_dup=4, n_total=5)
        text = "x" * sc.MIN_NOVEL_IMPACT_ARGUMENT_LENGTH
        candidate = _candidate(metadata={"target": "example.com", "novel_impact_argument": text})
        result = sc.check_duplicate_probability(candidate, report_outcomes=outcomes)
        assert result["status"] == "warn"

    def test_verbatim_reuse_across_candidates_flagged_not_blocked(self):
        """Reuse is a signal to surface, never a hard BLOCK on its own —
        even outside the elevated-duplicate-probability path."""
        text = "this chains into full account takeover, unlike prior reports"
        candidate = _candidate(metadata={"target": "example.com", "novel_impact_argument": text})
        candidate["id"] = "cand-new"
        prior = [_candidate(metadata={"target": "example.com", "novel_impact_argument": text})]
        prior[0]["id"] = "cand-old"
        result = sc.check_duplicate_probability(candidate, report_outcomes=[], prior_candidates=prior)
        assert result["status"] == "warn"
        assert result["details"]["novel_impact_argument_reused_verbatim"] is True
        assert "reused" in result["reason"] or "not genuinely novel" in result["reason"]

    def test_verbatim_reuse_on_different_target_not_flagged(self):
        text = "this chains into full account takeover, unlike prior reports"
        candidate = _candidate(metadata={"target": "example.com", "novel_impact_argument": text})
        candidate["id"] = "cand-new"
        prior = [_candidate(metadata={"target": "other.com", "novel_impact_argument": text})]
        prior[0]["id"] = "cand-old"
        result = sc.check_duplicate_probability(candidate, report_outcomes=[], prior_candidates=prior)
        assert result["details"]["novel_impact_argument_reused_verbatim"] is False

    def test_different_novel_impact_argument_text_not_flagged_as_reused(self):
        candidate = _candidate(metadata={
            "target": "example.com", "novel_impact_argument": "a genuinely different justification here",
        })
        candidate["id"] = "cand-new"
        prior = [_candidate(metadata={
            "target": "example.com", "novel_impact_argument": "a completely unrelated justification text",
        })]
        prior[0]["id"] = "cand-old"
        result = sc.check_duplicate_probability(candidate, report_outcomes=[], prior_candidates=prior)
        assert result["details"]["novel_impact_argument_reused_verbatim"] is False

    def test_no_prior_candidates_never_flags_reuse(self):
        candidate = _candidate(metadata={
            "target": "example.com", "novel_impact_argument": "this chains into full account takeover",
        })
        result = sc.check_duplicate_probability(candidate, report_outcomes=[], prior_candidates=None)
        assert result["details"]["novel_impact_argument_reused_verbatim"] is False

    def test_elevated_and_reused_warns_with_reuse_note_not_block(self):
        outcomes = self._outcomes(n_dup=4, n_total=5)
        text = "this chains into full account takeover, unlike prior reports"
        candidate = _candidate(metadata={"target": "example.com", "novel_impact_argument": text})
        candidate["id"] = "cand-new"
        prior = [_candidate(metadata={"target": "example.com", "novel_impact_argument": text})]
        prior[0]["id"] = "cand-old"
        result = sc.check_duplicate_probability(candidate, report_outcomes=outcomes, prior_candidates=prior)
        assert result["status"] == "warn"
        assert result["details"]["novel_impact_argument_reused_verbatim"] is True


# ─── 3. Evidence completeness ─────────────────────────────────────────────

class TestEvidenceCompleteness:
    def test_complete_candidate_passes(self):
        result = sc.check_evidence_completeness(_candidate())
        assert result["status"] == "pass"

    def test_missing_evidence_blocks(self):
        candidate = _candidate()
        candidate["evidence"] = []
        result = sc.check_evidence_completeness(candidate)
        assert result["status"] == "block"
        assert "evidence" in result["details"]["missing"]

    def test_evidence_entry_bad_type_blocks(self):
        candidate = _candidate()
        candidate["evidence"] = [{"type": "Vibes", "detail": "d"}]
        result = sc.check_evidence_completeness(candidate)
        assert result["status"] == "block"
        assert "evidence[0].type" in result["details"]["missing"]

    def test_missing_steps_blocks(self):
        candidate = _candidate()
        candidate["validation_plan"]["steps"] = []
        result = sc.check_evidence_completeness(candidate)
        assert "validation_plan.steps" in result["details"]["missing"]

    def test_missing_expected_blocks(self):
        candidate = _candidate()
        candidate["validation_plan"]["expected"] = ""
        result = sc.check_evidence_completeness(candidate)
        assert "validation_plan.expected" in result["details"]["missing"]

    def test_missing_stop_condition_blocks(self):
        candidate = _candidate()
        candidate["validation_plan"]["stop_condition"] = ""
        result = sc.check_evidence_completeness(candidate)
        assert "validation_plan.stop_condition" in result["details"]["missing"]

    def test_missing_rationale_blocks(self):
        candidate = _candidate()
        candidate["rationale"] = ""
        result = sc.check_evidence_completeness(candidate)
        assert "rationale" in result["details"]["missing"]


# ─── 4. Business-impact cross-check ──────────────────────────────────────

ALICE = entity_id("User", "alice")
BOB = entity_id("User", "bob")
DOC1 = object_id("Document", "1")


class TestBusinessImpactCrossCheck:
    def test_object_model_source_always_warns(self):
        candidate = _candidate(source="object-model")
        result = sc.check_business_impact(candidate, observations=[])
        assert result["status"] == "warn"
        assert result["details"]["upgraded_impact"] is True

    def test_cold_start_empty_object_model_never_crashes(self):
        candidate = _candidate(metadata={"target": "example.com", "subject_id": BOB, "object_id": DOC1})
        result = sc.check_business_impact(candidate, observations=[])
        assert result["status"] == "pass"
        assert result["details"]["upgraded_impact"] is False

    def test_no_metadata_refs_passes_without_upgrade(self):
        candidate = _candidate()
        obs = [make_observation(ALICE, DOC1, "created",
                                 evidence=[{"type": "Observed-HTTP-Response", "detail": "d"}])]
        result = sc.check_business_impact(candidate, observations=obs)
        assert result["status"] == "pass"
        assert result["details"]["upgraded_impact"] is False

    def test_matching_violation_upgrades_to_warn(self):
        obs = [
            make_observation(ALICE, DOC1, "created",
                              evidence=[{"type": "Observed-HTTP-Response", "detail": "d"}]),
            make_observation(BOB, DOC1, "accessed",
                              evidence=[{"type": "Observed-HTTP-Response", "detail": "d"}],
                              outcome_status=200),
        ]
        candidate = _candidate(metadata={"target": "example.com", "subject_id": BOB, "object_id": DOC1})
        result = sc.check_business_impact(candidate, observations=obs)
        assert result["status"] == "warn"
        assert result["details"]["upgraded_impact"] is True

    def test_never_blocks_even_with_a_violation(self):
        obs = [
            make_observation(ALICE, DOC1, "created",
                              evidence=[{"type": "Observed-HTTP-Response", "detail": "d"}]),
            make_observation(BOB, DOC1, "accessed",
                              evidence=[{"type": "Observed-HTTP-Response", "detail": "d"}],
                              outcome_status=200),
        ]
        candidate = _candidate(metadata={"target": "example.com", "subject_id": BOB, "object_id": DOC1})
        result = sc.check_business_impact(candidate, observations=obs)
        assert result["status"] != "block"

    def test_never_touches_priority_score(self):
        """Regression test: calling check_business_impact() must not change
        what priority_score() returns for identical inputs — this module
        computes no priority/score of its own."""
        kwargs = dict(vuln_class="idor", tech_stack=["nodejs"], target="example.com")
        before = priority_score(**kwargs)

        obs = [
            make_observation(ALICE, DOC1, "created",
                              evidence=[{"type": "Observed-HTTP-Response", "detail": "d"}]),
            make_observation(BOB, DOC1, "accessed",
                              evidence=[{"type": "Observed-HTTP-Response", "detail": "d"}],
                              outcome_status=200),
        ]
        candidate = _candidate(metadata={"target": "example.com", "subject_id": BOB, "object_id": DOC1})
        sc.check_business_impact(candidate, observations=obs)

        after = priority_score(**kwargs)
        assert before == after


# ─── Combined gate ────────────────────────────────────────────────────────

class TestSelfCritique:
    def test_overall_pass_when_all_checks_pass(self):
        candidate = _candidate()
        fetcher = _MockFetcher([403, 403])
        report = sc.self_critique(candidate, fetcher=fetcher, report_outcomes=[], observations=[])
        assert report["overall"] == "pass"
        assert report["candidate_id"] == candidate["id"]
        assert len(report["checks"]) == 4

    def test_overall_block_when_any_check_blocks(self):
        candidate = _candidate()
        fetcher = _MockFetcher([403, 200])  # flaky -> reproducibility blocks
        report = sc.self_critique(candidate, fetcher=fetcher, report_outcomes=[], observations=[])
        assert report["overall"] == "block"

    def test_overall_warn_when_a_check_warns_and_none_block(self):
        candidate = _candidate(source="object-model")
        fetcher = _MockFetcher([403, 403])
        report = sc.self_critique(candidate, fetcher=fetcher, report_outcomes=[], observations=[])
        assert report["overall"] == "warn"

    def test_prior_candidates_threaded_through_to_duplicate_check(self):
        """self_critique()'s prior_candidates kwarg must actually reach
        check_duplicate_probability()'s reuse flag, not just exist unused."""
        text = "this chains into full account takeover, unlike prior reports"
        candidate = _candidate(metadata={"target": "example.com", "novel_impact_argument": text})
        candidate["id"] = "cand-new"
        prior = [_candidate(metadata={"target": "example.com", "novel_impact_argument": text})]
        prior[0]["id"] = "cand-old"
        fetcher = _MockFetcher([403, 403])
        report = sc.self_critique(
            candidate, fetcher=fetcher, report_outcomes=[], observations=[], prior_candidates=prior,
        )
        assert report["details"]["duplicate_probability"]["details"]["novel_impact_argument_reused_verbatim"] is True


# ─── CLI ───────────────────────────────────────────────────────────────────

class TestCLI:
    def _write_json(self, path, data):
        import json
        path.write_text(json.dumps(data))

    def _write_jsonl(self, path, entries):
        import json
        path.write_text("\n".join(json.dumps(e) for e in entries) + "\n")

    def test_cli_runs_without_fetcher_and_blocks_reproducibility(self, tmp_path, monkeypatch, capsys):
        import sys as _sys

        candidate_path = tmp_path / "candidate.json"
        self._write_json(candidate_path, _candidate())
        monkeypatch.setattr(_sys, "argv", [
            "self_critique.py", "--candidate", str(candidate_path), "--no-fetch",
        ])
        assert sc.main() == 1  # overall == "block" (no fetcher -> reproducibility blocks)
        out = capsys.readouterr().out
        import json as _json
        report = _json.loads(out)
        assert report["overall"] == "block"

    def test_cli_output_flag_writes_hash_bound_artifact(self, tmp_path, monkeypatch, capsys):
        """--output must persist the report via the SAME write_report_artifact()
        memory/finding_state.py's REPORT_READY check verifies against."""
        import sys as _sys

        candidate_path = tmp_path / "candidate.json"
        self._write_json(candidate_path, _candidate())
        report_path = tmp_path / "report.json"
        monkeypatch.setattr(_sys, "argv", [
            "self_critique.py", "--candidate", str(candidate_path), "--no-fetch",
            "--output", str(report_path),
        ])
        sc.main()
        out = capsys.readouterr().out
        assert report_path.exists()
        assert "self_critique_report_path=" in out
        assert "self_critique_report_hash=" in out

        from memory.finding_state import verify_report_artifact
        report_hash = [line for line in out.splitlines() if line.startswith("self_critique_report_hash=")][0].split("=", 1)[1]
        result = verify_report_artifact(report_path, report_hash, {"overall": "block"})
        assert result["ok"] is True

    def test_cli_prior_candidates_flag_flows_into_reuse_flag(self, tmp_path, monkeypatch, capsys):
        import sys as _sys
        import json as _json

        text = "this chains into full account takeover, unlike prior reports"
        candidate = _candidate(metadata={"target": "example.com", "novel_impact_argument": text})
        candidate["id"] = "cand-new"
        prior = _candidate(metadata={"target": "example.com", "novel_impact_argument": text})
        prior["id"] = "cand-old"

        candidate_path = tmp_path / "candidate.json"
        self._write_json(candidate_path, candidate)
        prior_path = tmp_path / "prior.jsonl"
        self._write_jsonl(prior_path, [prior])

        monkeypatch.setattr(_sys, "argv", [
            "self_critique.py", "--candidate", str(candidate_path), "--no-fetch",
            "--prior-candidates", str(prior_path),
        ])
        sc.main()
        report = _json.loads(capsys.readouterr().out)
        assert report["details"]["duplicate_probability"]["details"]["novel_impact_argument_reused_verbatim"] is True

    # -- Phase 12 fix: --from-lead-board (memory.candidate.lead_to_candidate_view
    # was real, tested, and zero-callers -- a confirmed finding whose evidence
    # originated as a plain lead-board lead had no path into this gate short of
    # hand-authoring a Candidate JSON from scratch) -----------------------------

    def test_cli_from_lead_board_converts_a_real_ledger_entry(self, tmp_path, monkeypatch, capsys):
        import sys as _sys
        import json as _json

        monkeypatch.setattr(lb, "LEADS_DIR", str(tmp_path / "leads"))
        lb.save_ledger("t.example", [{
            "id": "lb-real-lead", "target": "t.example", "skill": "hunt-idor",
            "priority": "high", "signal": "test", "why": "attacker can read victim's order",
            "evidence": "https://t.example/api/orders/42", "source": "url", "status": "new",
            "note": "", "created": lb.now_iso(), "last_seen": lb.now_iso(), "seen_count": 1,
        }])
        monkeypatch.setattr(_sys, "argv", [
            "self_critique.py", "--from-lead-board", "t.example", "lb-real-lead", "--no-fetch",
        ])
        assert sc.main() == 1  # no fetcher -> reproducibility blocks, same as --candidate path
        report = _json.loads(capsys.readouterr().out)
        assert report["overall"] == "block"
        # evidence_completeness also blocks here, but only on the fields a plain
        # lead-board lead genuinely never carries (validation_plan -- lead_to_
        # candidate_view() honestly leaves it empty rather than fabricating
        # steps). evidence/rationale are NOT in the missing list, proving the
        # conversion really carried the lead's own evidence/why over, not just
        # that main() didn't crash.
        missing = report["details"]["evidence_completeness"]["details"]["missing"]
        assert all(m.startswith("validation_plan.") for m in missing)
        assert "evidence" not in missing and "rationale" not in missing

    def test_cli_from_lead_board_unknown_lead_id_fails_loud_not_silent(self, tmp_path, monkeypatch, capsys):
        import sys as _sys

        monkeypatch.setattr(lb, "LEADS_DIR", str(tmp_path / "leads"))
        lb.save_ledger("t.example", [])
        monkeypatch.setattr(_sys, "argv", [
            "self_critique.py", "--from-lead-board", "t.example", "does-not-exist", "--no-fetch",
        ])
        assert sc.main() == 1
        assert "no lead 'does-not-exist'" in capsys.readouterr().err

    def test_cli_requires_exactly_one_of_candidate_or_from_lead_board(self, monkeypatch):
        import sys as _sys

        monkeypatch.setattr(_sys, "argv", ["self_critique.py", "--no-fetch"])
        with pytest.raises(SystemExit):
            sc.main()

    def test_cli_rejects_both_candidate_and_from_lead_board_together(self, tmp_path, monkeypatch):
        import sys as _sys
        import json as _json

        candidate_path = tmp_path / "candidate.json"
        candidate_path.write_text(_json.dumps(_candidate()))
        monkeypatch.setattr(_sys, "argv", [
            "self_critique.py", "--candidate", str(candidate_path),
            "--from-lead-board", "t.example", "lb-real-lead", "--no-fetch",
        ])
        with pytest.raises(SystemExit):
            sc.main()
