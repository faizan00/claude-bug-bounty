"""Tests for tools/target_profile.py — Milestone 1, the read-only target
digital twin.

Covers the contract that matters: build_target_profile() is pure
composition (never writes, never persists, safe to call repeatedly),
every field is backed by an existing, already-tested store's own real
API (never a second implementation), cold start returns defaults for
every field instead of raising, and each field is scoped to the exact
target requested (no cross-target leakage).
"""

import os

import pytest

from tools import director
from tools import lead_board as lb
from tools.target_profile import build_target_profile

from memory.finding_state import FindingStateDB
from memory.object_model import ObservationStore, make_observation, compute_relationships
from memory.schemas import make_failed_pattern_entry, make_finding_state_entry
from memory.vuln_intelligence import FailedPatternDB


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """Same isolation convention as tests/test_director.py: point the
    lead-board ledger at a tmp dir, and give every other store its own
    tmp memory_dir so nothing here touches real repo state."""
    monkeypatch.setattr(lb, "LEADS_DIR", str(tmp_path / "leads"))
    memory_dir = str(tmp_path / "hunt-memory")
    recon_dir = str(tmp_path / "recon" / "t.example")
    return tmp_path, memory_dir, recon_dir


def _lead(lead_id, skill="hunt-idor", evidence="https://t.example/api/orders/1",
          source="url", status="new", **overrides):
    base = {
        "id": lead_id, "target": "t.example", "skill": skill, "priority": "high",
        "signal": "test", "why": "test", "evidence": evidence, "source": source,
        "status": status, "note": "", "created": lb.now_iso(), "last_seen": lb.now_iso(),
        "seen_count": 1,
    }
    base.update(overrides)
    return base


def _tree_snapshot(root):
    """(path -> (mtime_ns, size)) for every file under root, for the
    zero-write test — must not just count files, must catch in-place
    mutation of an existing file too."""
    snap = {}
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            st = os.stat(p)
            snap[p] = (st.st_mtime_ns, st.st_size)
    return snap


class TestColdStart:
    def test_cold_start_returns_all_fields_with_defaults(self, isolated):
        tmp_path, memory_dir, recon_dir = isolated
        profile = build_target_profile("cold.example", memory_dir=memory_dir, recon_dir=recon_dir)

        assert profile["target"] == "cold.example"
        assert profile["tech_stack"] == []
        assert profile["leads_summary"] == {"new": 0, "investigating": 0, "killed": 0, "reported": 0}
        assert profile["confirmed_findings"] == []
        assert profile["failed_techniques"] == []
        assert profile["active_hypotheses"] == []
        assert profile["relationships"] == {}
        # build_capability_graph() always seeds a root Asset node for the
        # target itself, even with zero leads -- that's the underlying
        # graph's own semantics, not something invented here.
        assert [n["id"] for n in profile["assets"]["nodes"]] == [f"asset:cold.example"]

    def test_cold_start_creates_no_files_or_directories(self, isolated):
        tmp_path, memory_dir, recon_dir = isolated
        before = set(os.listdir(tmp_path))
        build_target_profile("cold.example", memory_dir=memory_dir, recon_dir=recon_dir)
        after = set(os.listdir(tmp_path))
        assert before == after, f"cold-start call created: {after - before}"


class TestTechStackOnly:
    def test_tech_stack_populated_other_fields_default(self, isolated, tmp_path, monkeypatch):
        _tmp_path, memory_dir, recon_dir = isolated
        monkeypatch.setattr(director, "load_tech_stack",
                             lambda target, mdir: ["nextjs", "postgres"] if target == "t.example" else [])
        profile = build_target_profile("t.example", memory_dir=memory_dir, recon_dir=recon_dir)
        assert profile["tech_stack"] == ["nextjs", "postgres"]
        assert profile["leads_summary"] == {"new": 0, "investigating": 0, "killed": 0, "reported": 0}
        assert profile["confirmed_findings"] == []
        assert profile["active_hypotheses"] == []


class TestLeadsOnly:
    def test_status_counts_and_active_hypotheses(self, isolated):
        _tmp_path, memory_dir, recon_dir = isolated
        lb.save_ledger("t.example", [
            _lead("lb-1", status="new"),
            _lead("lb-2", status="new"),
            _lead("lb-3", status="investigating"),
            _lead("lb-4", status="killed"),
            _lead("lb-5", status="killed"),
            _lead("lb-6", status="reported"),
            _lead("lb-7", source="hypothesis", status="new", signal="CHAIN: x", chain_of=["lb-1", "lb-2"]),
            _lead("lb-8", source="hypothesis", status="investigating", chain_of=["lb-1"]),  # not "new" -- excluded
            _lead("lb-9", source="chain", status="new", chain_of=["lb-1", "lb-3"]),  # chain, not hypothesis -- excluded
        ])
        profile = build_target_profile("t.example", memory_dir=memory_dir, recon_dir=recon_dir)
        assert profile["leads_summary"] == {"new": 4, "investigating": 2, "killed": 2, "reported": 1}
        assert [h["id"] for h in profile["active_hypotheses"]] == ["lb-7"]


class TestFindingsOnly:
    def test_only_confirmed_state_is_promoted(self, isolated):
        _tmp_path, memory_dir, recon_dir = isolated
        db = FindingStateDB(os.path.join(memory_dir, "finding_states.jsonl"))
        for state in ("SUSPECTED", "TESTING", "VALIDATED", "CONFIRMED"):
            db.save(make_finding_state_entry(target="t.example", vuln_class="idor",
                                              endpoint="https://t.example/api/orders/1", state=state))
        db.save(make_finding_state_entry(target="t.example", vuln_class="ssrf",
                                          endpoint="https://t.example/fetch", state="REJECTED"))
        db.save(make_finding_state_entry(target="t.example", vuln_class="xss",
                                          endpoint="https://t.example/search", state="SUSPECTED"))

        profile = build_target_profile("t.example", memory_dir=memory_dir, recon_dir=recon_dir)
        classes = {f["vuln_class"] for f in profile["confirmed_findings"]}
        assert classes == {"idor"}
        assert all(f["state"] == "CONFIRMED" for f in profile["confirmed_findings"])

    def test_confirmed_then_advanced_past_confirmed_is_excluded(self, isolated):
        """A finding whose CURRENT state has moved on to SELF_CRITIQUED is
        no longer literally "CONFIRMED" -- confirmed_findings reflects the
        current state, not "ever reached CONFIRMED"."""
        _tmp_path, memory_dir, recon_dir = isolated
        db = FindingStateDB(os.path.join(memory_dir, "finding_states.jsonl"))
        db.save(make_finding_state_entry(target="t.example", vuln_class="idor",
                                          endpoint="https://t.example/api/orders/1", state="CONFIRMED"))
        db.save(make_finding_state_entry(target="t.example", vuln_class="idor",
                                          endpoint="https://t.example/api/orders/1", state="SELF_CRITIQUED"))
        profile = build_target_profile("t.example", memory_dir=memory_dir, recon_dir=recon_dir)
        assert profile["confirmed_findings"] == []


class TestFailedTechniques:
    def test_only_this_target_leaks_through(self, isolated):
        _tmp_path, memory_dir, recon_dir = isolated
        fp_db = FailedPatternDB(os.path.join(memory_dir, "failed_patterns.jsonl"))
        fp_db.save(make_failed_pattern_entry(target="t.example", vuln_class="ssrf",
                                              technique="dns-only", tech_stack=[], endpoint="x", reason="egress filtered"))
        fp_db.save(make_failed_pattern_entry(target="t.example", vuln_class="idor",
                                              technique="numeric-swap", tech_stack=[], endpoint="y", reason="not owned"))
        fp_db.save(make_failed_pattern_entry(target="other.example", vuln_class="ssrf",
                                              technique="dns-only", tech_stack=[], endpoint="z", reason="n/a"))

        profile = build_target_profile("t.example", memory_dir=memory_dir, recon_dir=recon_dir)
        assert {f["technique"] for f in profile["failed_techniques"]} == {"dns-only", "numeric-swap"}
        assert all(f["target"] == "t.example" for f in profile["failed_techniques"])


class TestObjectModel:
    def test_relationships_exactly_match_compute_relationships(self, isolated):
        _tmp_path, memory_dir, recon_dir = isolated
        om_path = director.object_model_observations_path("t.example", memory_dir)
        store = ObservationStore(om_path)
        obs1 = make_observation(subject_id="user:alice", object_ref="order:42", event="created",
                                 evidence=[{"type": "Observed-HTTP-Response", "detail": "d", "artifact": "a"}])
        obs2 = make_observation(subject_id="org:acme", object_ref="user:alice", event="membership_granted",
                                 evidence=[{"type": "Human-Input", "detail": "d", "artifact": ""}])
        store.record(obs1)
        store.record(obs2)

        profile = build_target_profile("t.example", memory_dir=memory_dir, recon_dir=recon_dir)
        expected = compute_relationships(store.all())
        assert profile["relationships"] == expected
        assert ("user:alice", "OWNS", "order:42") in profile["relationships"]

    def test_no_heuristic_relationship_without_evidence(self, isolated):
        """A lead whose evidence string LOOKS like it implies ownership
        (e.g. a URL with a user id in it) must never produce a relationship
        -- only a real object_model.py Observation can."""
        _tmp_path, memory_dir, recon_dir = isolated
        lb.save_ledger("t.example", [_lead("lb-1", evidence="https://t.example/api/user/42/orders")])
        profile = build_target_profile("t.example", memory_dir=memory_dir, recon_dir=recon_dir)
        assert profile["relationships"] == {}


class TestAssetInformation:
    def test_assets_come_from_the_attack_graph_not_a_second_representation(self, isolated):
        _tmp_path, memory_dir, recon_dir = isolated
        lb.save_ledger("t.example", [
            _lead("lb-1", skill="hunt-idor", evidence="https://t.example/api/orders/1"),
            _lead("lb-2", skill="hunt-ssrf", evidence="https://t.example/fetch"),
        ])
        profile = build_target_profile("t.example", memory_dir=memory_dir, recon_dir=recon_dir)
        node_ids = {n["id"] for n in profile["assets"]["nodes"]}
        assert node_ids == {"asset:t.example", "lead:lb-1", "lead:lb-2"}
        types = {n["id"]: n["type"] for n in profile["assets"]["nodes"]}
        assert types["lead:lb-1"] == "Endpoint"
        assert types["lead:lb-2"] == "Endpoint"
        # Every node here must carry real provenance -- not a stripped view.
        for n in profile["assets"]["nodes"]:
            assert n["origin_source"]

    def test_credential_nodes_are_not_assets(self, isolated):
        """hunt-source-leak produces a Credential-type node in the underlying
        graph (a leaked secret, not target inventory) -- deliberately
        excluded from "assets", same scoping the graph itself already
        distinguishes (Node.type in {Asset, Endpoint} vs Credential/
        Capability/Boundary). Not an oversight: this is the one place this
        milestone narrows the existing graph's node types on purpose."""
        _tmp_path, memory_dir, recon_dir = isolated
        lb.save_ledger("t.example", [
            _lead("lb-1", skill="hunt-source-leak", evidence="https://t.example/static/app.js"),
        ])
        profile = build_target_profile("t.example", memory_dir=memory_dir, recon_dir=recon_dir)
        node_ids = {n["id"] for n in profile["assets"]["nodes"]}
        assert "lead:lb-1" not in node_ids
        assert node_ids == {"asset:t.example"}


class TestFullProfile:
    def test_multi_source_fixture_every_field_populated(self, isolated):
        _tmp_path, memory_dir, recon_dir = isolated

        director_stub_stack = ["django", "postgres"]
        target_json = os.path.join(memory_dir, "targets")
        os.makedirs(target_json, exist_ok=True)
        import json
        with open(os.path.join(target_json, "t.example.json"), "w") as fh:
            json.dump({"tech_stack": director_stub_stack}, fh)

        lb.save_ledger("t.example", [
            _lead("lb-1", skill="hunt-idor", evidence="https://t.example/api/orders/1", status="new"),
            _lead("lb-2", skill="hunt-ssrf", evidence="https://t.example/fetch", status="killed"),
            _lead("lb-3", source="hypothesis", status="new", signal="CHAIN: ato", chain_of=["lb-1", "lb-2"]),
        ])

        om_path = director.object_model_observations_path("t.example", memory_dir)
        obs = make_observation(subject_id="user:alice", object_ref="order:1", event="created",
                                evidence=[{"type": "Observed-HTTP-Response", "detail": "d", "artifact": "a"}])
        ObservationStore(om_path).record(obs)

        fs_db = FindingStateDB(os.path.join(memory_dir, "finding_states.jsonl"))
        fs_db.save(make_finding_state_entry(target="t.example", vuln_class="idor",
                                             endpoint="https://t.example/api/orders/1", state="CONFIRMED"))

        fp_db = FailedPatternDB(os.path.join(memory_dir, "failed_patterns.jsonl"))
        fp_db.save(make_failed_pattern_entry(target="t.example", vuln_class="ssrf", technique="dns-only",
                                              tech_stack=[], endpoint="https://t.example/fetch", reason="egress filtered"))

        profile = build_target_profile("t.example", memory_dir=memory_dir, recon_dir=recon_dir)

        assert profile["tech_stack"] == director_stub_stack
        assert profile["leads_summary"] == {"new": 2, "investigating": 0, "killed": 1, "reported": 0}
        assert [h["id"] for h in profile["active_hypotheses"]] == ["lb-3"]
        assert len(profile["confirmed_findings"]) == 1
        assert profile["confirmed_findings"][0]["vuln_class"] == "idor"
        assert len(profile["failed_techniques"]) == 1
        assert profile["failed_techniques"][0]["technique"] == "dns-only"
        assert ("user:alice", "OWNS", "order:1") in profile["relationships"]
        node_ids = {n["id"] for n in profile["assets"]["nodes"]}
        assert {"asset:t.example", "lead:lb-1", "lead:lb-2"}.issubset(node_ids)


class TestZeroWriteGuarantee:
    def test_no_files_created_or_mutated_across_a_populated_fixture(self, isolated):
        _tmp_path, memory_dir, recon_dir = isolated

        lb.save_ledger("t.example", [_lead("lb-1")])
        om_path = director.object_model_observations_path("t.example", memory_dir)
        ObservationStore(om_path).record(
            make_observation(subject_id="user:alice", object_ref="order:1", event="created",
                              evidence=[{"type": "Observed-HTTP-Response", "detail": "d", "artifact": "a"}])
        )
        fs_db = FindingStateDB(os.path.join(memory_dir, "finding_states.jsonl"))
        fs_db.save(make_finding_state_entry(target="t.example", vuln_class="idor",
                                             endpoint="https://t.example/api/orders/1", state="CONFIRMED"))
        fp_db = FailedPatternDB(os.path.join(memory_dir, "failed_patterns.jsonl"))
        fp_db.save(make_failed_pattern_entry(target="t.example", vuln_class="ssrf", technique="dns-only",
                                              tech_stack=[], endpoint="x", reason="egress filtered"))

        before = _tree_snapshot(_tmp_path)
        build_target_profile("t.example", memory_dir=memory_dir, recon_dir=recon_dir)
        after = _tree_snapshot(_tmp_path)

        assert before == after, (
            f"build_target_profile() mutated the filesystem. "
            f"new/changed files: {set(after) - set(before) | {p for p in before if before[p] != after.get(p)}}"
        )

    def test_no_files_created_on_repeated_calls_cold_start(self, isolated):
        _tmp_path, memory_dir, recon_dir = isolated
        before = _tree_snapshot(_tmp_path)
        build_target_profile("t.example", memory_dir=memory_dir, recon_dir=recon_dir)
        build_target_profile("t.example", memory_dir=memory_dir, recon_dir=recon_dir)
        after = _tree_snapshot(_tmp_path)
        assert before == after


class TestRepeatedRead:
    def test_two_calls_with_no_state_change_are_equivalent(self, isolated):
        _tmp_path, memory_dir, recon_dir = isolated
        lb.save_ledger("t.example", [_lead("lb-1"), _lead("lb-2", status="killed")])

        profile1 = build_target_profile("t.example", memory_dir=memory_dir, recon_dir=recon_dir)
        profile2 = build_target_profile("t.example", memory_dir=memory_dir, recon_dir=recon_dir)
        assert profile1 == profile2


class TestIntegrationInternalConsistency:
    def test_composed_profile_is_internally_consistent_with_underlying_stores(self, isolated):
        """Cross-checks the composed view against directly querying each
        underlying store a second, independent way -- not against the
        profile's own fields."""
        _tmp_path, memory_dir, recon_dir = isolated

        lb.save_ledger("t.example", [
            _lead("lb-1", status="new"),
            _lead("lb-2", status="investigating"),
            _lead("lb-3", source="hypothesis", status="new", chain_of=["lb-1", "lb-2"]),
        ])
        fs_db = FindingStateDB(os.path.join(memory_dir, "finding_states.jsonl"))
        fs_db.save(make_finding_state_entry(target="t.example", vuln_class="idor",
                                             endpoint="https://t.example/api/orders/1", state="CONFIRMED"))
        om_path = director.object_model_observations_path("t.example", memory_dir)
        ObservationStore(om_path).record(
            make_observation(subject_id="user:alice", object_ref="order:1", event="created",
                              evidence=[{"type": "Observed-HTTP-Response", "detail": "d", "artifact": "a"}])
        )

        profile = build_target_profile("t.example", memory_dir=memory_dir, recon_dir=recon_dir)

        # 1. active_hypothesis lead ids must resolve to real leads on the board.
        real_lead_ids = {l["id"] for l in lb.load_ledger("t.example")}
        for hyp in profile["active_hypotheses"]:
            assert hyp["id"] in real_lead_ids
            for leg_id in hyp.get("chain_of", []):
                assert leg_id in real_lead_ids

        # 2. lead_summary counts must match a direct recount of the ledger.
        direct_leads = lb.load_ledger("t.example")
        direct_counts = {"new": 0, "investigating": 0, "killed": 0, "reported": 0}
        for l in direct_leads:
            if l["status"] in direct_counts:
                direct_counts[l["status"]] += 1
        assert profile["leads_summary"] == direct_counts

        # 3. confirmed_findings must match FindingStateDB.current_state() queried directly.
        for f in profile["confirmed_findings"]:
            assert fs_db.current_state("t.example", f["vuln_class"], f["endpoint"]) == "CONFIRMED"

        # 4. relationships must come from object_model.py, not be invented --
        # cross-check against a fresh, independent compute_relationships() call.
        assert profile["relationships"] == compute_relationships(ObservationStore(om_path).all())
