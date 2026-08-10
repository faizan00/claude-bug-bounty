"""Integration test for architecture Milestone 2 (value-of-information
planning): tools/target_profile.py feeding memory/experiment_memory.py's
expected_information_value()/rank_by_information_value(), against one
realistic multi-source "target-A" fixture.

Proves the planner can distinguish a high-information action from a
low-information one, an already-resolved question, and a hard-killed
technique — all from the SAME composed target profile, without bypassing
any existing gate (FailedPatternDB hard-kill, finding_state.py CONFIRMED
semantics, lead-board dedup/status).
"""

import os

from tools import director
from tools import lead_board as lb
from tools.target_profile import build_target_profile

from memory.experiment_memory import rank_by_information_value
from memory.finding_state import FindingStateDB
from memory.object_model import ObservationStore, make_observation
from memory.schemas import make_failed_pattern_entry, make_finding_state_entry
from memory.vuln_intelligence import FailedPatternDB


def _build_target_a_fixture(tmp_path, monkeypatch):
    monkeypatch.setattr(lb, "LEADS_DIR", str(tmp_path / "leads"))
    memory_dir = str(tmp_path / "hunt-memory")
    recon_dir = str(tmp_path / "recon" / "target-A")

    # Assets: several distinct endpoints/leads.
    lb.save_ledger("target-A", [
        {"id": "lb-1", "target": "target-A", "skill": "hunt-idor", "priority": "high",
         "signal": "test", "why": "test", "evidence": "https://target-A/api/orders/1",
         "source": "url", "status": "new", "note": "", "created": lb.now_iso(),
         "last_seen": lb.now_iso(), "seen_count": 1},
        {"id": "lb-2", "target": "target-A", "skill": "hunt-source-leak", "priority": "high",
         "signal": "test", "why": "test", "evidence": "https://target-A/static/app.js",
         "source": "url", "status": "new", "note": "", "created": lb.now_iso(),
         "last_seen": lb.now_iso(), "seen_count": 1},
        {"id": "lb-3", "target": "target-A", "skill": "hunt-auth-bypass", "priority": "med",
         "signal": "test", "why": "test", "evidence": "https://target-A/admin/export",
         "source": "url", "status": "new", "note": "", "created": lb.now_iso(),
         "last_seen": lb.now_iso(), "seen_count": 1},
        {"id": "lb-4", "target": "target-A", "skill": "hunt-ssrf", "priority": "med",
         "signal": "test", "why": "test", "evidence": "https://target-A/fetch",
         "source": "url", "status": "new", "note": "", "created": lb.now_iso(),
         "last_seen": lb.now_iso(), "seen_count": 1},
        # Two active hypotheses (dependent leads, "chain_of" -- lb-1/lb-2/lb-3
        # are legs of these composite claims).
        {"id": "lb-hyp-ato", "target": "target-A", "skill": "hunt-idor", "priority": "high",
         "signal": "CHAIN: account takeover via leaked secret", "why": "secret + api + weak authz",
         "evidence": "leaked secret + /api/orders/1 + /admin/export", "source": "hypothesis",
         "status": "new", "note": "", "created": lb.now_iso(), "last_seen": lb.now_iso(),
         "seen_count": 1, "chain_of": ["lb-2", "lb-1", "lb-3"]},
        {"id": "lb-hyp-ssrf-chain", "target": "target-A", "skill": "hunt-ssrf", "priority": "med",
         "signal": "CHAIN: ssrf to internal", "why": "fetch + admin export", "evidence": "x + y",
         "source": "hypothesis", "status": "new", "note": "", "created": lb.now_iso(),
         "last_seen": lb.now_iso(), "seen_count": 1, "chain_of": ["lb-4", "lb-3"]},
    ])

    # Prior failed technique on this target -- a hard-kill candidate.
    fp_db = FailedPatternDB(os.path.join(memory_dir, "failed_patterns.jsonl"))
    fp_db.save(make_failed_pattern_entry(
        target="target-A", vuln_class="ssrf", technique="dns_only_callback",
        tech_stack=["nextjs"], endpoint="https://target-A/fetch", reason="egress filtered, no internal reach",
    ))

    # A finding already CONFIRMED at a specific endpoint -- an
    # already-resolved-question candidate.
    fs_db = FindingStateDB(os.path.join(memory_dir, "finding_states.jsonl"))
    fs_db.save(make_finding_state_entry(target="target-A", vuln_class="auth-bypass",
                                         endpoint="https://target-A/admin/export", state="CONFIRMED"))

    # Realistic experiment history: numeric_id_swap has a genuinely mixed
    # track record on nextjs elsewhere (informative); source-leak-grep has
    # never been tried on this tech stack (also informative, cold).
    om_path = director.object_model_observations_path("target-A", memory_dir)
    ObservationStore(om_path).record(
        make_observation(subject_id="user:alice", object_ref="order:1", event="created",
                          evidence=[{"type": "Observed-HTTP-Response", "detail": "d", "artifact": "a"}])
    )

    return memory_dir, recon_dir


def test_evoi_over_a_realistic_target_a_fixture(tmp_path, monkeypatch):
    from memory.experiment_memory import ExperimentDB

    memory_dir, recon_dir = _build_target_a_fixture(tmp_path, monkeypatch)

    # Realistic experiment history, elsewhere on similar tech: BOTH
    # candidate techniques below have the SAME shape lopsided-but-real
    # track record (1 win, 4 losses) so their raw information value before
    # the hypothesis bonus is identical -- isolating the hypothesis-
    # discrimination bonus as the only thing that can separate them
    # (rather than one starting cold and hitting the entropy ceiling,
    # which no bonus could ever climb past).
    exp_db = ExperimentDB(os.path.join(memory_dir, "experiments.jsonl"))
    for technique, vuln_class in (("numeric_id_swap", "idor"), ("source_leak_grep", "info-disclosure")):
        exp_db.save({
            "ts": "2026-01-01T00:00:00Z", "target": "other-site.example", "endpoint": "/api/x",
            "vuln_class": vuln_class, "payload_category": "cat", "technique": technique,
            "result": "success", "tech_stack": ["nextjs"], "schema_version": 1,
        })
        for i in range(4):
            exp_db.save({
                "ts": f"2026-01-0{2 + i}T00:00:00Z", "target": f"other-site{i}.example", "endpoint": "/api/y",
                "vuln_class": vuln_class, "payload_category": "cat", "technique": technique,
                "result": "fail", "tech_stack": ["nextjs"], "schema_version": 1,
            })

    profile = build_target_profile("target-A", memory_dir=memory_dir, recon_dir=recon_dir)

    # Sanity: the composed profile itself is correct before EVOI runs on top of it.
    assert profile["leads_summary"]["new"] == 6  # 4 raw leads + 2 hypotheses, all status=="new"
    assert {h["id"] for h in profile["active_hypotheses"]} == {"lb-hyp-ato", "lb-hyp-ssrf-chain"}
    assert len(profile["confirmed_findings"]) == 1
    assert len(profile["failed_techniques"]) == 1

    candidates = [
        {  # HIGH-INFORMATION: same track record shape as the candidate below,
           # PLUS it sits on an active hypothesis's chain_of -- the only
           # thing that should separate the two.
            "target": "target-A", "technique": "numeric_id_swap", "vuln_class": "idor",
            "tech_stack": ["nextjs"], "endpoint": "https://target-A/api/orders/1", "lead_id": "lb-1",
            "estimated_minutes": 20,
        },
        {  # LOW-INFORMATION (relative to the one above): identical lopsided
           # track record shape, same cost, but not connected to any active
           # hypothesis.
            "target": "target-A", "technique": "source_leak_grep", "vuln_class": "info-disclosure",
            "tech_stack": ["nextjs"], "endpoint": "https://target-A/static/app.js", "lead_id": "lb-9-unconnected",
            "estimated_minutes": 20,
        },
        {  # ALREADY-RESOLVED: this exact target+vuln_class+endpoint is already CONFIRMED
            "target": "target-A", "technique": "role_check_bypass", "vuln_class": "auth-bypass",
            "tech_stack": ["nextjs"], "endpoint": "https://target-A/admin/export", "lead_id": "lb-3",
        },
        {  # HARD-KILLED: exact target+technique already in failed_patterns.jsonl
            "target": "target-A", "technique": "dns_only_callback", "vuln_class": "ssrf",
            "tech_stack": ["nextjs"], "endpoint": "https://target-A/fetch", "lead_id": "lb-4",
        },
    ]

    ranked = rank_by_information_value(
        candidates,
        experiments=exp_db.read_all(),
        failed_patterns=profile["failed_techniques"],
        confirmed_findings=profile["confirmed_findings"],
        active_hypotheses=profile["active_hypotheses"],
    )
    order = [c["technique"] for c in ranked]

    # The planner can tell all four apart, in the right order, without
    # bypassing any existing gate.
    assert order[0] == "numeric_id_swap"
    already_resolved_and_dead = {order[2], order[3]}
    assert already_resolved_and_dead == {"role_check_bypass", "dns_only_callback"}

    by_technique = {c["technique"]: c["evoi"] for c in ranked}
    assert by_technique["numeric_id_swap"]["distinguishes_hypotheses"]
    assert by_technique["numeric_id_swap"]["distinguishes_hypotheses"][0]["hypothesis_id"] == "lb-hyp-ato"
    assert by_technique["source_leak_grep"]["distinguishes_hypotheses"] == []

    assert by_technique["role_check_bypass"]["resolved"] is True
    assert "CONFIRMED" in by_technique["role_check_bypass"]["resolved_reason"]
    assert by_technique["role_check_bypass"]["information_value"] == 0.0

    assert by_technique["dns_only_callback"]["hard_kill"] is True
    assert by_technique["dns_only_callback"]["information_value"] == 0.0

    # Safety: EVOI never touched scope/rate-limit/mutation controls -- it's
    # pure computation over already-loaded lists, no Fetcher, no network.
    for c in ranked:
        assert set(c["evoi"].keys()) >= {
            "information_value", "information_value_per_hour", "resolved",
            "hard_kill", "reasoning", "prior_track_record", "uncertainty_entropy",
            "distinguishes_hypotheses", "estimated_minutes",
        }
