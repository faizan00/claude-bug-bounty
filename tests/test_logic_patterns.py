"""Tests for memory/object_model.py's Part 2 (business logic taxonomy) —
rules/logic_patterns.yaml loading + detect_logic_pattern_violations()'s
generic executor.
"""

import pytest
import yaml

from memory import object_model as om
from memory.identity import entity_id, object_id


def _ev(detail="d"):
    return [{"type": "Observed-HTTP-Response", "detail": detail, "artifact": "a"}]


ORG_A = entity_id("Organization", "acme")
ORG_B = entity_id("Organization", "globex")
ALICE = entity_id("User", "alice")
BOB = entity_id("User", "bob")


class TestLoadLogicPatterns:
    def test_default_file_loads_all_seven_patterns(self):
        patterns = om.load_logic_patterns()
        ids = {p.id for p in patterns}
        assert ids == {
            "invite_flow", "ownership_transfer", "tenant_isolation",
            "billing", "refund", "coupon", "role_escalation",
        }

    def test_every_pattern_declares_a_known_hunt_skill_and_relationship(self):
        for p in om.load_logic_patterns():
            assert p.skill.startswith("hunt-")
            assert set(p.required_relationships).issubset(om.RELATIONSHIP_TYPES)
            assert p.requires_active_relationship in om.RELATIONSHIP_TYPES
            assert p.action_event in om.OBSERVATION_EVENTS

    def test_malformed_yaml_raises_loudly(self, tmp_path):
        path = tmp_path / "bad.yaml"
        path.write_text("not: a: list")
        with pytest.raises((om.LogicPatternLoadError, yaml.YAMLError)):
            om.load_logic_patterns(str(path))

    def test_missing_required_field_raises(self, tmp_path):
        path = tmp_path / "bad.yaml"
        path.write_text(yaml.safe_dump([{"id": "x", "description": "d"}]))
        with pytest.raises(om.LogicPatternLoadError):
            om.load_logic_patterns(str(path))

    def test_unknown_relationship_type_raises(self, tmp_path):
        bad = {
            "id": "x", "description": "d", "required_relationships": ["NOT_A_TYPE"],
            "action_event": "modified", "performed_by": "subject_id",
            "requires_active_relationship": "OWNS", "governing_object": "object_id",
            "skill": "hunt-idor", "vuln_type": "x_violation", "violation": "v",
            "validation_plan": {"steps": [], "expected": "e", "stop_condition": "s"},
        }
        path = tmp_path / "bad.yaml"
        path.write_text(yaml.safe_dump([bad]))
        with pytest.raises(om.LogicPatternLoadError):
            om.load_logic_patterns(str(path))


class TestMissingRelationshipEvidenceMeansPatternDoesNotExecute:
    def test_no_can_invite_evidence_at_all_invite_flow_never_fires(self):
        """No CAN_INVITE observation anywhere -> invite_flow pattern must
        not execute, even though a membership_granted with no valid
        grantor evidence would otherwise look like a violation."""
        obs = [om.make_observation(ORG_A, ALICE, "membership_granted", evidence=_ev(),
                                    metadata={"performed_by": BOB})]
        violations = om.detect_logic_pattern_violations(obs)
        assert not any(v["type"] == "invite_flow_violation" for v in violations)

    def test_has_member_evidence_present_gates_billing_pattern_open(self):
        obs = [
            om.make_observation(ORG_A, ALICE, "membership_granted", evidence=_ev(),
                                 ts="2026-01-01T00:00:00Z"),
            om.make_observation(BOB, object_id("Invoice", "1"), "modified", evidence=_ev(),
                                 outcome_status=200, ts="2026-01-02T00:00:00Z",
                                 metadata={"context": "billing", "organization_id": ORG_A}),
        ]
        violations = om.detect_logic_pattern_violations(obs)
        assert any(v["type"] == "billing_violation" for v in violations)


class TestInviteFlowPattern:
    def test_invite_without_can_invite_grant_is_a_violation(self):
        obs = [
            om.make_observation(ALICE, ORG_A, "invite_capability_granted", evidence=_ev(),
                                 ts="2026-01-01T00:00:00Z"),
            om.make_observation(ORG_A, BOB, "membership_granted", evidence=_ev(),
                                 ts="2026-01-02T00:00:00Z", metadata={"performed_by": BOB}),
        ]
        violations = om.detect_logic_pattern_violations(obs)
        matches = [v for v in violations if v["type"] == "invite_flow_violation"]
        assert len(matches) == 1

    def test_invite_with_active_can_invite_grant_is_not_a_violation(self):
        obs = [
            om.make_observation(ALICE, ORG_A, "invite_capability_granted", evidence=_ev(),
                                 ts="2026-01-01T00:00:00Z"),
            om.make_observation(ORG_A, BOB, "membership_granted", evidence=_ev(),
                                 ts="2026-01-02T00:00:00Z", metadata={"performed_by": ALICE}),
        ]
        violations = om.detect_logic_pattern_violations(obs)
        assert not any(v["type"] == "invite_flow_violation" for v in violations)

    def test_revoked_can_invite_grant_before_invite_IS_a_violation(self):
        obs = [
            om.make_observation(ALICE, ORG_A, "invite_capability_granted", evidence=_ev(),
                                 ts="2026-01-01T00:00:00Z"),
            om.make_observation(ALICE, ORG_A, "invite_capability_revoked", evidence=_ev(),
                                 ts="2026-01-02T00:00:00Z"),
            om.make_observation(ORG_A, BOB, "membership_granted", evidence=_ev(),
                                 ts="2026-01-03T00:00:00Z", metadata={"performed_by": ALICE}),
        ]
        violations = om.detect_logic_pattern_violations(obs)
        assert any(v["type"] == "invite_flow_violation" for v in violations)


class TestOwnershipTransferPattern:
    def test_transfer_by_actual_owner_is_not_a_violation(self):
        doc = object_id("Document", "1")
        obs = [
            om.make_observation(ALICE, doc, "created", evidence=_ev(), ts="2026-01-01T00:00:00Z"),
            om.make_observation(BOB, doc, "ownership_transferred", evidence=_ev(),
                                 ts="2026-01-02T00:00:00Z",
                                 metadata={"transferred_from": ALICE, "performed_by": ALICE}),
        ]
        violations = om.detect_logic_pattern_violations(obs)
        assert not any(v["type"] == "ownership_transfer_violation" for v in violations)

    def test_transfer_by_a_non_owner_IS_a_violation(self):
        """Point-in-time evaluation: performed_by (bob) never owned the
        object at any point before the transfer -- this must fire even
        though bob ends up as the new owner (a self-serving transfer)."""
        doc = object_id("Document", "1")
        obs = [
            om.make_observation(ALICE, doc, "created", evidence=_ev(), ts="2026-01-01T00:00:00Z"),
            om.make_observation(BOB, doc, "ownership_transferred", evidence=_ev(),
                                 ts="2026-01-02T00:00:00Z",
                                 metadata={"transferred_from": ALICE, "performed_by": BOB}),
        ]
        violations = om.detect_logic_pattern_violations(obs)
        assert any(v["type"] == "ownership_transfer_violation" for v in violations)


class TestTenantIsolationPattern:
    def test_member_accessing_own_org_tagged_object_no_violation(self):
        doc = object_id("Document", "1")
        obs = [
            om.make_observation(ORG_A, ALICE, "membership_granted", evidence=_ev(),
                                 ts="2026-01-01T00:00:00Z"),
            om.make_observation(ALICE, doc, "accessed", evidence=_ev(), outcome_status=200,
                                 ts="2026-01-02T00:00:00Z", metadata={"organization_id": ORG_A}),
        ]
        violations = om.detect_logic_pattern_violations(obs)
        assert not any(v["type"] == "tenant_isolation_pattern_violation" for v in violations)

    def test_non_member_accessing_org_tagged_object_IS_a_violation(self):
        doc = object_id("Document", "1")
        obs = [
            om.make_observation(ORG_A, ALICE, "membership_granted", evidence=_ev(),
                                 ts="2026-01-01T00:00:00Z"),
            om.make_observation(BOB, doc, "accessed", evidence=_ev(), outcome_status=200,
                                 ts="2026-01-02T00:00:00Z", metadata={"organization_id": ORG_A}),
        ]
        violations = om.detect_logic_pattern_violations(obs)
        assert any(v["type"] == "tenant_isolation_pattern_violation" for v in violations)

    def test_missing_organization_tag_is_skipped_not_guessed(self):
        doc = object_id("Document", "1")
        obs = [
            om.make_observation(ORG_A, ALICE, "membership_granted", evidence=_ev(),
                                 ts="2026-01-01T00:00:00Z"),
            om.make_observation(BOB, doc, "accessed", evidence=_ev(), outcome_status=200,
                                 ts="2026-01-02T00:00:00Z"),  # no organization_id tag
        ]
        violations = om.detect_logic_pattern_violations(obs)
        assert not any(v["type"] == "tenant_isolation_pattern_violation" for v in violations)


class TestActionContextDisambiguatesSharedEvent:
    """billing/refund/coupon all watch 'modified' -- action_context must
    keep them from cross-firing on each other's observations."""

    def test_billing_context_does_not_trigger_refund_or_coupon(self):
        obs = [
            om.make_observation(ORG_A, ALICE, "membership_granted", evidence=_ev(),
                                 ts="2026-01-01T00:00:00Z"),
            om.make_observation(BOB, object_id("Invoice", "1"), "modified", evidence=_ev(),
                                 outcome_status=200, ts="2026-01-02T00:00:00Z",
                                 metadata={"context": "billing", "organization_id": ORG_A}),
        ]
        violations = om.detect_logic_pattern_violations(obs)
        types = {v["type"] for v in violations}
        assert "billing_violation" in types
        assert "refund_violation" not in types
        assert "coupon_violation" not in types

    def test_non_2xx_action_is_not_a_violation(self):
        obs = [
            om.make_observation(ORG_A, ALICE, "membership_granted", evidence=_ev(),
                                 ts="2026-01-01T00:00:00Z"),
            om.make_observation(BOB, object_id("Invoice", "1"), "modified", evidence=_ev(),
                                 outcome_status=403, ts="2026-01-02T00:00:00Z",
                                 metadata={"context": "billing", "organization_id": ORG_A}),
        ]
        violations = om.detect_logic_pattern_violations(obs)
        assert not any(v["type"] == "billing_violation" for v in violations)


class TestRoleEscalationPattern:
    def test_role_assignment_without_can_invite_grant_is_a_violation(self):
        obs = [
            om.make_observation(ALICE, ORG_A, "invite_capability_granted", evidence=_ev(),
                                 ts="2026-01-01T00:00:00Z"),
            om.make_observation(ORG_A, BOB, "membership_granted", evidence=_ev(),
                                 ts="2026-01-02T00:00:00Z",
                                 metadata={"performed_by": BOB, "context": "role_assignment"}),
        ]
        violations = om.detect_logic_pattern_violations(obs)
        assert any(v["type"] == "role_escalation_violation" for v in violations)


class TestCandidateShapeFromPatterns:
    def test_violation_candidate_never_claims_to_be_a_vulnerability(self):
        doc = object_id("Document", "1")
        obs = [
            om.make_observation(ALICE, doc, "created", evidence=_ev(), ts="2026-01-01T00:00:00Z"),
            om.make_observation(BOB, doc, "ownership_transferred", evidence=_ev(),
                                 ts="2026-01-02T00:00:00Z",
                                 metadata={"transferred_from": ALICE, "performed_by": BOB}),
        ]
        violations = om.detect_logic_pattern_violations(obs)
        c = next(v for v in violations if v["type"] == "ownership_transfer_violation")
        assert "vulnerability" not in c["rationale"].lower()
        assert c["validation_plan"]["expected"]
        assert c["state"] == "new"
