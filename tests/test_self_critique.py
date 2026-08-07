"""Tests for tools/self_critique.py — Phase 7 Part B (the Self-Critique Gate)."""

import pytest

from memory.candidate import make_candidate
from memory.object_model import make_observation
from memory.identity import entity_id, object_id
from memory.vuln_intelligence import DEFAULT_DEDUP_PROBABILITY, MIN_SAMPLES_FOR_DEDUP_PROBABILITY, priority_score
from tools import self_critique as sc


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
        candidate = _candidate(rationale="novel impact: this chains into full account takeover, unlike prior reports")
        result = sc.check_duplicate_probability(candidate, report_outcomes=outcomes)
        assert result["status"] == "warn"

    def test_sample_backed_elevated_without_novel_impact_blocks(self):
        outcomes = self._outcomes(n_dup=4, n_total=5)
        candidate = _candidate()  # default rationale has no "novel impact:" marker
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
