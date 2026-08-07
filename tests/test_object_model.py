"""Tests for memory/object_model.py — Phase 6 Part 1 (Application Object Model).

Covers the acceptance list from the phase brief: no relationship without
Evidence Typing, a violation requires BOTH relationship data AND a
contradicting observation, legitimate ownership transfer never produces a
violation, append-only observations are preserved, and (via
tests/test_director.py's own cold-start suite pattern) cold-start never
crashes anything downstream.
"""

import json

import pytest

from memory import object_model as om
from memory.identity import entity_id, object_id


def _ev(evidence_type="Observed-HTTP-Response", detail="d", artifact="a"):
    return [{"type": evidence_type, "detail": detail, "artifact": artifact}]


ALICE = entity_id("User", "alice")
BOB = entity_id("User", "bob")
DOC1 = object_id("Document", "1")
ORG_A = entity_id("Organization", "acme")
ORG_B = entity_id("Organization", "globex")


class TestObservationRequiresEvidenceTyping:
    def test_no_evidence_raises(self):
        with pytest.raises(ValueError, match="Evidence Typing"):
            om.make_observation(ALICE, DOC1, "created", evidence=[])

    def test_evidence_type_outside_vocabulary_raises(self):
        with pytest.raises(ValueError):
            om.make_observation(ALICE, DOC1, "created", evidence=[{"type": "Vibes", "detail": "d"}])

    def test_unknown_event_raises(self):
        with pytest.raises(ValueError, match="unknown observation event"):
            om.make_observation(ALICE, DOC1, "teleported", evidence=_ev())

    def test_event_relationship_type_mismatch_raises(self):
        with pytest.raises(ValueError, match="establishes/ends"):
            om.make_observation(ALICE, DOC1, "created", evidence=_ev(), relationship_type="HAS_MEMBER")

    def test_created_establishes_owns_relationship_type_automatically(self):
        obs = om.make_observation(ALICE, DOC1, "created", evidence=_ev())
        assert obs["relationship_type"] == "OWNS"

    def test_valid_observation_carries_its_evidence(self):
        obs = om.make_observation(ALICE, DOC1, "created", evidence=_ev(detail="POST /documents -> 201"))
        assert obs["evidence"][0]["detail"] == "POST /documents -> 201"


class TestComputeRelationships:
    def test_created_establishes_active_owns_edge(self):
        obs = [om.make_observation(ALICE, DOC1, "created", evidence=_ev())]
        state = om.compute_relationships(obs)
        assert state[(ALICE, "OWNS", DOC1)]["status"] == "active"

    def test_created_with_org_establishes_belongs_to_and_contains(self):
        obs = [om.make_observation(ALICE, DOC1, "created", evidence=_ev(),
                                    metadata={"organization_id": ORG_A})]
        state = om.compute_relationships(obs)
        assert state[(DOC1, "BELONGS_TO", ORG_A)]["status"] == "active"
        assert state[(ORG_A, "CONTAINS", DOC1)]["status"] == "active"


class TestOwnershipTransferNeverFalsePositives:
    """Part 1, non-negotiable: 'Legitimate ownership transfer MUST NEVER
    produce a violation' and 'Historical ownership MUST NOT trigger false
    positives.'"""

    def test_transfer_supersedes_old_owner_not_deletes(self):
        obs = [
            om.make_observation(ALICE, DOC1, "created", evidence=_ev(), ts="2026-01-01T00:00:00Z"),
            om.make_observation(BOB, DOC1, "ownership_transferred", evidence=_ev(),
                                 ts="2026-01-02T00:00:00Z", metadata={"transferred_from": ALICE}),
        ]
        state = om.compute_relationships(obs)
        assert state[(ALICE, "OWNS", DOC1)]["status"] == "superseded"
        assert state[(BOB, "OWNS", DOC1)]["status"] == "active"

    def test_new_owner_accessing_after_transfer_is_not_a_violation(self):
        obs = [
            om.make_observation(ALICE, DOC1, "created", evidence=_ev(), ts="2026-01-01T00:00:00Z"),
            om.make_observation(BOB, DOC1, "ownership_transferred", evidence=_ev(),
                                 ts="2026-01-02T00:00:00Z", metadata={"transferred_from": ALICE}),
            om.make_observation(BOB, DOC1, "accessed", evidence=_ev(), outcome_status=200,
                                 ts="2026-01-03T00:00:00Z"),
        ]
        violations = om.detect_relationship_violations(obs)
        assert violations == []

    def test_old_owner_accessing_after_transfer_IS_a_violation(self):
        """The old owner no longer has an active OWNS edge -- their access
        now contradicts the CURRENT graph, which is exactly the point."""
        obs = [
            om.make_observation(ALICE, DOC1, "created", evidence=_ev(), ts="2026-01-01T00:00:00Z"),
            om.make_observation(BOB, DOC1, "ownership_transferred", evidence=_ev(),
                                 ts="2026-01-02T00:00:00Z", metadata={"transferred_from": ALICE}),
            om.make_observation(ALICE, DOC1, "accessed", evidence=_ev(), outcome_status=200,
                                 ts="2026-01-03T00:00:00Z"),
        ]
        violations = om.detect_relationship_violations(obs)
        assert len(violations) == 1
        assert violations[0]["type"] == "ownership_violation"


class TestViolationRequiresBothRelationshipDataAndContradiction:
    def test_no_relationship_at_all_no_violation(self):
        """An access with nothing ever established about the object -- no
        evidence means no relationship, so nothing to contradict."""
        obs = [om.make_observation(BOB, DOC1, "accessed", evidence=_ev(), outcome_status=200)]
        assert om.detect_relationship_violations(obs) == []

    def test_relationship_established_but_no_access_observation_no_violation(self):
        obs = [om.make_observation(ALICE, DOC1, "created", evidence=_ev())]
        assert om.detect_relationship_violations(obs) == []

    def test_owner_accessing_own_object_no_violation(self):
        obs = [
            om.make_observation(ALICE, DOC1, "created", evidence=_ev(), ts="2026-01-01T00:00:00Z"),
            om.make_observation(ALICE, DOC1, "accessed", evidence=_ev(), outcome_status=200,
                                 ts="2026-01-02T00:00:00Z"),
        ]
        assert om.detect_relationship_violations(obs) == []

    def test_non_2xx_access_is_not_a_violation(self):
        """A 403 is the boundary holding -- confirmation, not a violation."""
        obs = [
            om.make_observation(ALICE, DOC1, "created", evidence=_ev(), ts="2026-01-01T00:00:00Z"),
            om.make_observation(BOB, DOC1, "accessed", evidence=_ev(), outcome_status=403,
                                 ts="2026-01-02T00:00:00Z"),
        ]
        assert om.detect_relationship_violations(obs) == []

    def test_cross_actor_2xx_access_with_established_ownership_IS_a_violation(self):
        obs = [
            om.make_observation(ALICE, DOC1, "created", evidence=_ev(), ts="2026-01-01T00:00:00Z"),
            om.make_observation(BOB, DOC1, "accessed", evidence=_ev(), outcome_status=200,
                                 ts="2026-01-02T00:00:00Z"),
        ]
        violations = om.detect_relationship_violations(obs)
        assert len(violations) == 1
        c = violations[0]
        assert c["type"] == "ownership_violation"
        assert c["validation_plan"]["expected"] == "403 / 401"
        assert "inconsistent with the currently observed relationship graph" in c["rationale"]
        assert "vulnerability" not in c["rationale"].lower()

    def test_org_member_accessing_org_object_no_violation(self):
        """Tenant isolation: a fellow org member touching an org-owned
        object is a legitimate shared-access path, not a violation."""
        obs = [
            om.make_observation(ALICE, DOC1, "created", evidence=_ev(), ts="2026-01-01T00:00:00Z",
                                 metadata={"organization_id": ORG_A}),
            om.make_observation(ORG_A, BOB, "membership_granted", evidence=_ev(), ts="2026-01-02T00:00:00Z"),
            om.make_observation(BOB, DOC1, "accessed", evidence=_ev(), outcome_status=200,
                                 ts="2026-01-03T00:00:00Z"),
        ]
        assert om.detect_relationship_violations(obs) == []

    def test_other_org_member_accessing_object_IS_tenant_isolation_violation(self):
        obs = [
            om.make_observation(ALICE, DOC1, "created", evidence=_ev(), ts="2026-01-01T00:00:00Z",
                                 metadata={"organization_id": ORG_A}),
            om.make_observation(ORG_B, BOB, "membership_granted", evidence=_ev(), ts="2026-01-02T00:00:00Z"),
            om.make_observation(BOB, DOC1, "accessed", evidence=_ev(), outcome_status=200,
                                 ts="2026-01-03T00:00:00Z"),
        ]
        violations = om.detect_relationship_violations(obs)
        assert len(violations) == 1
        assert violations[0]["type"] == "tenant_isolation_violation"

    def test_revoked_membership_reintroduces_the_violation(self):
        obs = [
            om.make_observation(ALICE, DOC1, "created", evidence=_ev(), ts="2026-01-01T00:00:00Z",
                                 metadata={"organization_id": ORG_A}),
            om.make_observation(ORG_A, BOB, "membership_granted", evidence=_ev(), ts="2026-01-02T00:00:00Z"),
            om.make_observation(ORG_A, BOB, "membership_revoked", evidence=_ev(), ts="2026-01-03T00:00:00Z"),
            om.make_observation(BOB, DOC1, "accessed", evidence=_ev(), outcome_status=200,
                                 ts="2026-01-04T00:00:00Z"),
        ]
        violations = om.detect_relationship_violations(obs)
        assert len(violations) == 1


class TestAppendOnlyObservationStore:
    def test_record_appends_and_all_reads_back_in_order(self, tmp_path):
        store = om.ObservationStore(tmp_path / "observations.jsonl")
        o1 = om.make_observation(ALICE, DOC1, "created", evidence=_ev(), ts="2026-01-01T00:00:00Z")
        o2 = om.make_observation(BOB, DOC1, "accessed", evidence=_ev(), outcome_status=200,
                                  ts="2026-01-02T00:00:00Z")
        store.record(o1)
        store.record(o2)
        all_obs = store.all()
        assert [o["id"] for o in all_obs] == [o1["id"], o2["id"]]

    def test_file_is_append_only_never_rewritten(self, tmp_path):
        store = om.ObservationStore(tmp_path / "observations.jsonl")
        store.record(om.make_observation(ALICE, DOC1, "created", evidence=_ev()))
        first_line = store.path.read_text().splitlines()
        store.record(om.make_observation(BOB, DOC1, "accessed", evidence=_ev(), outcome_status=200))
        lines = store.path.read_text().splitlines()
        assert lines[0] == first_line[0]
        assert len(lines) == 2

    def test_corrupted_line_skipped_not_raised(self, tmp_path):
        path = tmp_path / "observations.jsonl"
        path.write_text('{not json\n' + json.dumps(
            om.make_observation(ALICE, DOC1, "created", evidence=_ev())
        ) + "\n")
        store = om.ObservationStore(path)
        assert len(store.all()) == 1
