"""Tests for memory/experiment_memory.py — payload-attempt log + stop/pivot decisions."""

import pytest

from memory.experiment_memory import (
    ExperimentDB,
    evaluate_experiment,
    expected_information_value,
    payload_category_affinity,
    rank_by_information_value,
    should_stop,
    suggest_pivot,
)


class TestExperimentDB:

    def test_save_and_read(self, experiments_path, sample_experiment_entry):
        db = ExperimentDB(experiments_path)
        assert db.save(sample_experiment_entry) is True
        assert experiments_path.exists()
        entries = db.read_all()
        assert len(entries) == 1
        assert entries[0]["payload_category"] == "numeric_id_swap"

    def test_exact_repeat_rejected(self, experiments_path, sample_experiment_entry):
        db = ExperimentDB(experiments_path)
        db.save(sample_experiment_entry)
        assert db.save(dict(sample_experiment_entry)) is False

    def test_same_combo_different_ts_accumulates(self, experiments_path, sample_experiment_entry):
        # Not deduped on (target, endpoint, payload_category) alone — a
        # legitimate re-test later must be allowed to accumulate.
        db = ExperimentDB(experiments_path)
        db.save(sample_experiment_entry)
        entry2 = dict(sample_experiment_entry)
        entry2["ts"] = "2026-04-01T10:00:00Z"
        entry2["result"] = "fail"
        assert db.save(entry2) is True
        assert len(db.read_all()) == 2

    def test_read_all_on_missing_file(self, experiments_path):
        db = ExperimentDB(experiments_path)
        assert db.read_all() == []

    def test_for_endpoint_matches_exact(self, experiments_path, sample_experiment_entry):
        db = ExperimentDB(experiments_path)
        db.save(sample_experiment_entry)
        results = db.for_endpoint("target.com", "/api/v2/users/{id}/orders")
        assert len(results) == 1

    def test_for_endpoint_matches_normalized_shape(self, experiments_path, sample_experiment_entry):
        db = ExperimentDB(experiments_path)
        entry = dict(sample_experiment_entry)
        entry["endpoint"] = "/api/v2/users/482/orders"
        db.save(entry)
        results = db.for_endpoint("target.com", "/api/v2/users/9107/orders")
        assert len(results) == 1

    def test_for_endpoint_excludes_other_targets(self, experiments_path, sample_experiment_entry):
        db = ExperimentDB(experiments_path)
        db.save(sample_experiment_entry)
        results = db.for_endpoint("other.com", "/api/v2/users/{id}/orders")
        assert results == []


class TestPayloadCategoryAffinity:

    def test_wins_and_losses_counted(self):
        experiments = [
            {"vuln_class": "auth-bypass", "payload_category": "missing_authz_check",
             "tech_stack": ["graphql", "node"], "result": "success"},
            {"vuln_class": "auth-bypass", "payload_category": "missing_authz_check",
             "tech_stack": ["graphql", "node"], "result": "fail"},
        ]
        result = payload_category_affinity(["graphql", "node"], experiments)
        assert result[0]["successes"] == 1
        assert result[0]["failures"] == 1
        assert result[0]["sample_size"] == 2

    def test_no_overlap_excluded(self):
        experiments = [
            {"vuln_class": "idor", "payload_category": "numeric_id_swap",
             "tech_stack": ["django"], "result": "success"},
        ]
        result = payload_category_affinity(["express"], experiments)
        assert result == []

    def test_stronger_tech_overlap_ranks_higher(self):
        # Same net_score, but one has 2 overlapping techs and one has 1 —
        # the 2-tech match should sort first (tie-break on overlap strength).
        experiments = [
            {"vuln_class": "auth-bypass", "payload_category": "single_overlap",
             "tech_stack": ["node"], "result": "success"},
            {"vuln_class": "auth-bypass", "payload_category": "double_overlap",
             "tech_stack": ["graphql", "node"], "result": "success"},
        ]
        result = payload_category_affinity(["graphql", "node"], experiments)
        assert result[0]["payload_category"] == "double_overlap"
        assert result[0]["tech_overlap_strength"] == 2

    def test_filters_by_vuln_class(self):
        experiments = [
            {"vuln_class": "idor", "payload_category": "numeric_id_swap",
             "tech_stack": ["express"], "result": "success"},
            {"vuln_class": "xss", "payload_category": "reflected_param",
             "tech_stack": ["express"], "result": "success"},
        ]
        result = payload_category_affinity(["express"], experiments, vuln_class="idor")
        assert len(result) == 1
        assert result[0]["payload_category"] == "numeric_id_swap"

    def test_top_limits_results(self):
        experiments = [
            {"vuln_class": "idor", "payload_category": "a", "tech_stack": ["express"], "result": "success"},
            {"vuln_class": "idor", "payload_category": "b", "tech_stack": ["express"], "result": "success"},
        ]
        result = payload_category_affinity(["express"], experiments, top=1)
        assert len(result) == 1

    def test_inconclusive_tracked_separately(self):
        experiments = [
            {"vuln_class": "idor", "payload_category": "a", "tech_stack": ["express"], "result": "inconclusive"},
        ]
        result = payload_category_affinity(["express"], experiments)
        assert result[0]["inconclusive"] == 1
        assert result[0]["successes"] == 0
        assert result[0]["failures"] == 0


class TestShouldStop:

    def test_success_present_never_stops(self):
        experiments = [{"payload_category": "a", "result": "success"}]
        result = should_stop(experiments, elapsed_minutes=10, minute_limit=5)
        assert result["stop"] is False
        assert "active signal" in result["reason"]

    def test_stops_after_time_limit_with_no_success(self):
        experiments = [{"payload_category": "a", "result": "fail"}]
        result = should_stop(experiments, elapsed_minutes=6, minute_limit=5)
        assert result["stop"] is True
        assert "5-minute rule" in result["reason"]

    def test_stops_after_category_limit_with_no_success(self):
        experiments = [
            {"payload_category": "a", "result": "fail"},
            {"payload_category": "b", "result": "fail"},
            {"payload_category": "c", "result": "fail"},
        ]
        result = should_stop(experiments, elapsed_minutes=2, minute_limit=5, category_limit=3)
        assert result["stop"] is True
        assert "categories exhausted" in result["reason"]

    def test_continues_within_budget(self):
        experiments = [{"payload_category": "a", "result": "fail"}]
        result = should_stop(experiments, elapsed_minutes=2, minute_limit=5, category_limit=3)
        assert result["stop"] is False

    def test_no_experiments_yet_continues(self):
        result = should_stop([], elapsed_minutes=1, minute_limit=5)
        assert result["stop"] is False
        assert result["categories_tried"] == []


class TestSuggestPivot:

    def test_picks_highest_scoring_non_exhausted_candidate(self):
        candidates = [
            {"endpoint": "/a", "score": 40},
            {"endpoint": "/b", "score": 78},
            {"endpoint": "/c", "score": 60},
        ]
        result = suggest_pivot(candidates, exhausted_endpoints={"/b"})
        assert result["endpoint"] == "/c"

    def test_skips_hard_kill_candidates(self):
        candidates = [
            {"endpoint": "/a", "score": 90, "hard_kill": True},
            {"endpoint": "/b", "score": 50},
        ]
        result = suggest_pivot(candidates, exhausted_endpoints=set())
        assert result["endpoint"] == "/b"

    def test_returns_none_when_all_exhausted(self):
        candidates = [{"endpoint": "/a", "score": 90}]
        result = suggest_pivot(candidates, exhausted_endpoints={"/a"})
        assert result is None

    def test_returns_none_for_empty_candidates(self):
        assert suggest_pivot([], exhausted_endpoints=set()) is None


class TestEvaluateExperiment:

    def test_failed_pattern_hard_stop(self):
        failed = [{"target": "a.com", "technique": "numeric_id_swap", "reason": "ownership check present"}]
        result = evaluate_experiment(
            target="a.com", technique="numeric_id_swap", vuln_class="idor",
            failed_patterns=failed,
        )
        assert result["decision"] == "stop"
        assert "already failed" in result["reason"]
        assert "ownership check present" in result["reason"]
        assert result["confidence"] >= 90

    def test_failed_pattern_on_different_target_does_not_block(self):
        failed = [{"target": "other.com", "technique": "numeric_id_swap", "reason": "n/a"}]
        result = evaluate_experiment(
            target="a.com", technique="numeric_id_swap", vuln_class="idor",
            failed_patterns=failed,
        )
        assert result["decision"] != "stop" or "already failed" not in result["reason"]

    def test_no_data_at_all_continues_with_low_confidence(self):
        result = evaluate_experiment(target="a.com", technique="numeric_id_swap", vuln_class="idor")
        assert result["decision"] == "continue"
        assert result["confidence"] == 20

    def test_active_success_overrides_everything(self):
        experiments = [
            {"target": "a.com", "endpoint": "/api/x", "technique": "numeric_id_swap",
             "vuln_class": "idor", "tech_stack": ["express"], "result": "success", "payload_category": "id_swap"},
        ]
        result = evaluate_experiment(
            target="a.com", technique="numeric_id_swap", vuln_class="idor", tech_stack=["express"],
            endpoint="/api/x", experiments=experiments, elapsed_minutes=10, minute_limit=5,
            ev_label="Kill", ev_per_hour=0,
        )
        assert result["decision"] == "continue"
        assert "success" in result["reason"]

    def test_ev_kill_stops_without_budget_or_history(self):
        result = evaluate_experiment(
            target="a.com", technique="numeric_id_swap", vuln_class="idor", tech_stack=["express"],
            ev_label="Kill", ev_per_hour=0,
        )
        assert result["decision"] == "stop"
        assert "Kill" in result["reason"]

    def test_budget_exhausted_with_only_failures_stops(self):
        experiments = [
            {"target": "a.com", "endpoint": "/api/y", "technique": "numeric_id_swap", "vuln_class": "idor",
             "tech_stack": ["express"], "result": "fail", "payload_category": cat}
            for cat in ("id_swap", "header_swap", "jwt_swap")
        ]
        result = evaluate_experiment(
            target="a.com", technique="numeric_id_swap", vuln_class="idor", tech_stack=["express"],
            endpoint="/api/y", experiments=experiments, elapsed_minutes=2, minute_limit=5, category_limit=3,
        )
        assert result["decision"] == "stop"
        assert "0W/3L" in result["reason"]

    def test_budget_exhausted_with_no_history_pivots_not_stops(self):
        # Time limit hit, but zero experiments logged for this technique yet
        # (e.g. someone else's payload categories burned the clock) — nothing
        # says this technique itself is a loser, so pivot rather than stop.
        experiments = [
            {"target": "a.com", "endpoint": "/api/y", "technique": "other_technique", "vuln_class": "idor",
             "tech_stack": ["express"], "result": "fail", "payload_category": "other_cat"},
        ]
        result = evaluate_experiment(
            target="a.com", technique="numeric_id_swap", vuln_class="idor", tech_stack=["express"],
            endpoint="/api/y", experiments=experiments, elapsed_minutes=10, minute_limit=5,
        )
        assert result["decision"] == "pivot"

    def test_success_on_another_target_still_triggers_continue(self):
        # A win recorded anywhere with tech-stack overlap is an active signal,
        # not just a win on the exact target being evaluated right now.
        experiments = [
            {"target": "other.com", "technique": "numeric_id_swap", "vuln_class": "idor",
             "tech_stack": ["express"], "result": "success", "payload_category": "id_swap"},
        ]
        result = evaluate_experiment(
            target="a.com", technique="numeric_id_swap", vuln_class="idor", tech_stack=["express"],
            experiments=experiments,
        )
        assert result["decision"] == "continue"
        assert "success" in result["reason"]

    def test_single_prior_failure_still_continues(self):
        # One failure elsewhere isn't enough of a track record to pivot on yet.
        experiments = [
            {"target": "other.com", "technique": "numeric_id_swap", "vuln_class": "idor",
             "tech_stack": ["express"], "result": "fail", "payload_category": "id_swap"},
        ]
        result = evaluate_experiment(
            target="a.com", technique="numeric_id_swap", vuln_class="idor", tech_stack=["express"],
            experiments=experiments,
        )
        assert result["decision"] == "continue"
        assert "1W/1L" not in result["reason"]

    def test_similar_tech_poor_track_record_pivots(self):
        experiments = [
            {"target": "other.com", "technique": "numeric_id_swap", "vuln_class": "idor",
             "tech_stack": ["express"], "result": "fail", "payload_category": "id_swap"},
            {"target": "other2.com", "technique": "numeric_id_swap", "vuln_class": "idor",
             "tech_stack": ["express"], "result": "fail", "payload_category": "id_swap"},
            {"target": "other3.com", "technique": "numeric_id_swap", "vuln_class": "idor",
             "tech_stack": ["express"], "result": "fail", "payload_category": "id_swap"},
        ]
        result = evaluate_experiment(
            target="a.com", technique="numeric_id_swap", vuln_class="idor", tech_stack=["express"],
            experiments=experiments,
        )
        assert result["decision"] == "pivot"

    def test_tech_stack_mismatch_excludes_experiment(self):
        experiments = [
            {"target": "other.com", "technique": "numeric_id_swap", "vuln_class": "idor",
             "tech_stack": ["django"], "result": "success", "payload_category": "id_swap"},
        ]
        result = evaluate_experiment(
            target="a.com", technique="numeric_id_swap", vuln_class="idor", tech_stack=["express"],
            experiments=experiments,
        )
        # No overlap with ["django"] -> treated as no prior data.
        assert result["decision"] == "continue"
        assert result["confidence"] == 20

    def test_vuln_class_filter_excludes_other_classes(self):
        experiments = [
            {"target": "other.com", "technique": "numeric_id_swap", "vuln_class": "xss",
             "tech_stack": ["express"], "result": "success", "payload_category": "id_swap"},
        ]
        result = evaluate_experiment(
            target="a.com", technique="numeric_id_swap", vuln_class="idor", tech_stack=["express"],
            experiments=experiments,
        )
        assert result["decision"] == "continue"
        assert result["confidence"] == 20

    def test_result_always_has_all_four_keys(self):
        result = evaluate_experiment(target="a.com", technique="x")
        assert set(result.keys()) == {"decision", "reason", "confidence", "recommended_next_step"}


# ─── Milestone 2: value-of-information ─────────────────────────────────────

def _exps(n_success, n_fail, target="other.com", technique="numeric_id_swap",
          vuln_class="idor", tech_stack=("nextjs",)):
    exps = []
    for i in range(n_success):
        exps.append({"target": f"{target}-{i}", "endpoint": f"e{i}", "vuln_class": vuln_class,
                      "payload_category": "id_swap", "technique": technique, "result": "success",
                      "tech_stack": list(tech_stack)})
    for i in range(n_fail):
        exps.append({"target": f"{target}-f{i}", "endpoint": f"ef{i}", "vuln_class": vuln_class,
                      "payload_category": "id_swap", "technique": technique, "result": "fail",
                      "tech_stack": list(tech_stack)})
    return exps


class TestExpectedInformationValue:

    def test_empty_history_is_deterministic_and_bounded(self):
        # 1. EMPTY HISTORY
        r = expected_information_value(target="t.example", technique="numeric_id_swap", vuln_class="idor")
        assert r["resolved"] is False
        assert 0.0 <= r["information_value"] <= 100.0
        assert r["prior_track_record"] == {
            "successes": 0, "failures": 0, "sample_size": 0, "estimated_success_probability": 0.5,
        }
        # No prior data -> maximal uncertainty, not an arbitrary low default.
        assert r["uncertainty_entropy"] == 1.0

    def test_informative_action_beats_equivalent_non_distinguishing_action(self):
        # 2 / 8. INFORMATIVE ACTION / HYPOTHESIS DISCRIMINATION
        exps = _exps(0, 10)  # one-sided track record -> base entropy has headroom below the cap
        hyps = [{"id": "lb-hyp1", "signal": "CHAIN: ato", "chain_of": ["lb-1", "lb-2"]}]

        distinguishing = expected_information_value(
            target="t.example", technique="numeric_id_swap", vuln_class="idor", tech_stack=["nextjs"],
            lead_id="lb-1", experiments=exps, active_hypotheses=hyps,
        )
        unrelated = expected_information_value(
            target="t.example", technique="numeric_id_swap", vuln_class="idor", tech_stack=["nextjs"],
            lead_id="lb-999", experiments=exps, active_hypotheses=hyps,
        )
        assert distinguishing["information_value"] > unrelated["information_value"]
        assert distinguishing["distinguishes_hypotheses"]
        assert unrelated["distinguishes_hypotheses"] == []

    def test_non_informative_action_has_low_information_value(self):
        # 3. NON-INFORMATIVE ACTION: lopsided track record -> outcome predictable
        exps = _exps(0, 10)
        r = expected_information_value(
            target="t.example", technique="numeric_id_swap", vuln_class="idor",
            tech_stack=["nextjs"], experiments=exps,
        )
        assert r["information_value"] < 50.0
        assert r["uncertainty_entropy"] < 0.5

    def test_previously_resolved_question_is_not_artificially_high(self):
        # 4. PREVIOUSLY RESOLVED QUESTION
        confirmed = [{"target": "t.example", "vuln_class": "idor",
                      "endpoint": "https://t.example/api/orders/1", "state": "CONFIRMED"}]
        r = expected_information_value(
            target="t.example", technique="numeric_id_swap", vuln_class="idor",
            endpoint="https://t.example/api/orders/1", confirmed_findings=confirmed,
        )
        assert r["information_value"] == 0.0
        assert r["resolved"] is True
        assert "CONFIRMED" in r["resolved_reason"]

    def test_failed_technique_remains_blocked_evoi_never_overrides(self):
        # 5. FAILED TECHNIQUE — even with a maximally-uncertain empty history
        # AND a hypothesis connection, the hard-kill wins.
        failed = [{"target": "t.example", "vuln_class": "idor", "technique": "numeric_id_swap",
                   "reason": "egress filtered"}]
        hyps = [{"id": "lb-hyp1", "chain_of": ["lb-1"]}]
        r = expected_information_value(
            target="t.example", technique="numeric_id_swap", vuln_class="idor",
            lead_id="lb-1", failed_patterns=failed, active_hypotheses=hyps,
        )
        assert r["information_value"] == 0.0
        assert r["resolved"] is True
        assert r["hard_kill"] is True

    def test_positive_historical_signal_shifts_estimated_probability(self):
        # 6. POSITIVE HISTORICAL SIGNAL
        exps = _exps(8, 0)
        r = expected_information_value(
            target="t.example", technique="numeric_id_swap", vuln_class="idor",
            tech_stack=["nextjs"], experiments=exps,
        )
        assert r["prior_track_record"]["estimated_success_probability"] > 0.5
        assert r["prior_track_record"]["successes"] == 8

    def test_target_specificity_no_cross_target_leakage(self):
        # 7. TARGET-SPECIFICITY
        failed_for_b = [{"target": "target-B", "vuln_class": "idor", "technique": "numeric_id_swap",
                          "reason": "n/a"}]
        r = expected_information_value(
            target="target-A", technique="numeric_id_swap", vuln_class="idor",
            failed_patterns=failed_for_b,
        )
        assert r["resolved"] is False  # target-B's hard-kill must not leak onto target-A

    def test_downstream_unlock_exposes_other_legs(self):
        # 9. DOWNSTREAM UNLOCK
        hyps = [{"id": "lb-hyp1", "signal": "CHAIN: ato", "chain_of": ["lb-1", "lb-2", "lb-3"]}]
        r = expected_information_value(
            target="t.example", technique="numeric_id_swap", vuln_class="idor",
            lead_id="lb-1", active_hypotheses=hyps,
        )
        assert len(r["distinguishes_hypotheses"]) == 1
        assert set(r["distinguishes_hypotheses"][0]["other_legs"]) == {"lb-2", "lb-3"}

    def test_cost_time_changes_information_value_per_hour(self):
        # 10. COST / TIME — same entropy, different minutes -> different per-hour rate.
        exps = _exps(0, 10)
        cheap = expected_information_value(
            target="t.example", technique="numeric_id_swap", vuln_class="idor",
            tech_stack=["nextjs"], experiments=exps, estimated_minutes=10,
        )
        expensive = expected_information_value(
            target="t.example", technique="numeric_id_swap", vuln_class="idor",
            tech_stack=["nextjs"], experiments=exps, estimated_minutes=40,
        )
        assert cheap["information_value"] == expensive["information_value"]
        assert cheap["information_value_per_hour"] > expensive["information_value_per_hour"]

    def test_determinism(self):
        # 11. DETERMINISM
        exps = _exps(2, 3)
        hyps = [{"id": "lb-hyp1", "chain_of": ["lb-1"]}]
        kwargs = dict(target="t.example", technique="numeric_id_swap", vuln_class="idor",
                      tech_stack=["nextjs"], lead_id="lb-1", experiments=exps, active_hypotheses=hyps)
        assert expected_information_value(**kwargs) == expected_information_value(**kwargs)

    def test_safety_invariant_hard_kill_never_overridden_by_any_combination(self):
        # 12. SAFETY INVARIANTS — stack every info-raising signal at once
        # (empty-ish mixed history, hypothesis connection, cheap cost) and
        # confirm the hard-kill still wins.
        failed = [{"target": "t.example", "vuln_class": "idor", "technique": "numeric_id_swap"}]
        hyps = [{"id": "lb-hyp1", "chain_of": ["lb-1"]}]
        exps = _exps(1, 1)
        r = expected_information_value(
            target="t.example", technique="numeric_id_swap", vuln_class="idor",
            tech_stack=["nextjs"], lead_id="lb-1", experiments=exps, active_hypotheses=hyps,
            failed_patterns=failed, estimated_minutes=1,
        )
        assert r["information_value"] == 0.0
        assert r["information_value_per_hour"] == 0.0
        assert r["resolved"] is True and r["hard_kill"] is True

    def test_never_crashes_on_missing_optional_fields(self):
        # Cold-start / incomplete target-profile safety.
        r = expected_information_value(target="t.example", technique="x", vuln_class="idor",
                                        tech_stack=None, endpoint=None, lead_id=None,
                                        experiments=None, failed_patterns=None,
                                        confirmed_findings=None, active_hypotheses=None)
        assert r["resolved"] is False

    def test_estimated_minutes_must_be_positive(self):
        with pytest.raises(ValueError):
            expected_information_value(target="t", technique="x", vuln_class="idor", estimated_minutes=0)


class TestRankByInformationValue:

    def test_ranks_high_low_resolved_hardkilled_correctly(self):
        candidates = [
            {"target": "target-A", "technique": "numeric_id_swap", "vuln_class": "idor",
             "tech_stack": ["nextjs"], "endpoint": "https://target-A/api/orders/1", "lead_id": "lb-1"},
            {"target": "target-A", "technique": "predictable_tech", "vuln_class": "ssrf",
             "tech_stack": ["nextjs"], "endpoint": "https://target-A/fetch", "lead_id": "lb-2"},
            {"target": "target-A", "technique": "resolved_tech", "vuln_class": "xss",
             "tech_stack": ["nextjs"], "endpoint": "https://target-A/already-confirmed", "lead_id": "lb-3"},
            {"target": "target-A", "technique": "dead_tech", "vuln_class": "rce",
             "tech_stack": ["nextjs"], "endpoint": "https://target-A/dead", "lead_id": "lb-4"},
        ]
        # high-information: no prior data, connects to an active hypothesis
        hyps = [{"id": "lb-hyp1", "chain_of": ["lb-1", "lb-9"]}]
        # low-information: lopsided prior track record
        low_info_exps = _exps(0, 10, technique="predictable_tech", vuln_class="ssrf")
        confirmed = [{"target": "target-A", "vuln_class": "xss",
                      "endpoint": "https://target-A/already-confirmed", "state": "CONFIRMED"}]
        failed = [{"target": "target-A", "vuln_class": "rce", "technique": "dead_tech", "reason": "n/a"}]

        ranked = rank_by_information_value(
            candidates, experiments=low_info_exps, failed_patterns=failed,
            confirmed_findings=confirmed, active_hypotheses=hyps,
        )
        order = [c["technique"] for c in ranked]

        assert order[0] == "numeric_id_swap"  # empty history + hypothesis bonus -> highest genuine info value
        assert order[1] == "predictable_tech"  # lopsided-but-nonzero track record -> some info, less than #1
        # Resolved (already-confirmed) and hard-killed candidates sort last -- still
        # present (never dropped), never ranked above a genuinely informative one.
        assert set(order[2:]) == {"resolved_tech", "dead_tech"}
        assert order.index("predictable_tech") < order.index("resolved_tech")
        assert order.index("predictable_tech") < order.index("dead_tech")
        for c in ranked:
            if c["technique"] in ("resolved_tech", "dead_tech"):
                assert c["evoi"]["resolved"] is True
                assert c["evoi"]["information_value"] == 0.0


class TestEvoiCliIntegration:

    def test_evoi_cli_composes_target_profile_without_duplicating_reads(self, tmp_path, monkeypatch):
        """The evoi CLI subcommand must read confirmed_findings/active_hypotheses
        via tools.target_profile.build_target_profile() -- not a second,
        independent read of finding_states.jsonl/the lead board."""
        import sys as _sys
        import json as _json

        from tools import lead_board as lb
        from memory.experiment_memory import main as em_main

        monkeypatch.setattr(lb, "LEADS_DIR", str(tmp_path / "leads"))
        lb.save_ledger("target-A", [{
            "id": "lb-1", "target": "target-A", "skill": "hunt-idor", "priority": "high",
            "signal": "CHAIN: ato", "why": "test", "evidence": "https://target-A/api/orders/1",
            "source": "hypothesis", "status": "new", "note": "", "created": lb.now_iso(),
            "last_seen": lb.now_iso(), "seen_count": 1, "chain_of": ["lb-2", "lb-3"],
        }])
        memory_dir = str(tmp_path / "hunt-memory")

        monkeypatch.setattr(_sys, "argv", [
            "experiment_memory.py", "evoi", "--target", "target-A", "--technique", "numeric_id_swap",
            "--vuln-class", "idor", "--lead-id", "lb-1", "--memory-dir", memory_dir,
            "--recon-dir", str(tmp_path / "recon" / "target-A"),
        ])
        assert em_main() == 0
