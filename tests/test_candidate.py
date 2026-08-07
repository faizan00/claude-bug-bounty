"""Tests for memory/identity.py + memory/candidate.py — Phase 6 Part 0.

Covers: identity helpers match attack_graph.py's pre-existing endpoint:/
capability: node id output exactly (the "align, don't rename" contract),
Candidate schema construction + evidence-typing enforcement, and both view
directions (lead -> Candidate, Candidate -> lead) being pure/read-only —
retrofitting existing lead-producing functions never changes what
tools/director.py actually scores.
"""

import pytest

from memory import attack_graph as ag
from memory import candidate as cand
from memory.identity import capability_id, endpoint_id, entity_id, object_id
from tools import director


class TestIdentityScheme:
    def test_entity_object_endpoint_capability_prefixes(self):
        assert entity_id("User", "u1") == "entity:User:u1"
        assert object_id("Document", "42") == "object:Document:42"
        assert endpoint_id("/api/v1/orders") == "endpoint:/api/v1/orders"
        assert capability_id("ROLE_ADMIN") == "capability:ROLE_ADMIN"

    def test_attack_graph_endpoint_and_capability_ids_match_identity_helpers(self, tmp_path):
        """attack_graph.py's own node-id construction (refactored, Part 0,
        to call endpoint_id()/capability_id() instead of an inline
        f-string) must produce byte-identical ids to calling the shared
        helper directly — this IS the "align attack_graph.py with this
        convention" requirement, proven rather than asserted."""
        recon_dir = tmp_path / "recon" / "t.example"
        browser_dir = recon_dir / "browser"
        browser_dir.mkdir(parents=True)
        (browser_dir / "auth-model.json").write_text(
            '{"target": "t.example", "role_permission_constants": ["ROLE_ADMIN"], '
            '"candidate_privileged_client_routes": [], '
            '"auth_lifecycle_endpoints": ["https://t.example/api/auth/refresh"]}'
        )
        graph = ag.build_capability_graph("t.example", recon_dir=str(recon_dir), leads=[])
        assert capability_id("ROLE_ADMIN") in graph.nodes
        assert endpoint_id("https://t.example/api/auth/refresh") in graph.nodes


class TestCandidateSchema:
    def test_make_candidate_shape(self):
        c = cand.make_candidate(
            source="object-model", type_="ownership_violation",
            evidence=[{"type": "Observed-HTTP-Response", "detail": "d", "artifact": "a"}],
            rationale="r",
        )
        assert c["id"].startswith("cand-")
        assert c["state"] == "new"
        assert c["evidence"][0]["type"] == "Observed-HTTP-Response"
        assert c["validation_plan"] == {"steps": [], "expected": "", "stop_condition": ""}
        assert c["provenance"] == {"origin_lead_id": None, "origin_source": "object-model"}
        assert c["metadata"] == {}

    def test_make_candidate_rejects_evidence_type_outside_vocabulary(self):
        with pytest.raises(ValueError):
            cand.make_candidate(
                source="object-model", type_="ownership_violation",
                evidence=[{"type": "Speculative-Guess", "detail": "d", "artifact": "a"}],
                rationale="r",
            )

    def test_evidence_types_vocabulary_is_the_documented_eight(self):
        assert cand.EVIDENCE_TYPES == frozenset({
            "Observed-Runtime", "Observed-HTTP-Response", "Browser-Artifact",
            "Static-JS", "Fingerprint", "Historical-Memory", "Human-Input",
            "Validation-Confirmed",
        })


class TestRetrofitDoesNotChangeScoring:
    """The whole point of Part 0's retrofit: wrapping existing lead-
    producing functions' output as a Candidate VIEW must not touch what
    tools/director.py._score_lead() computes."""

    def test_lead_to_candidate_view_does_not_mutate_input(self):
        lead = {
            "id": "bi-abc123", "target": "t.example", "skill": "hunt-idor",
            "priority": "high", "signal": "numeric object ref", "why": "sequential ID",
            "evidence": "/api/v1/orders/5", "source": "browser-intel", "status": "new",
        }
        original = dict(lead)
        view = cand.lead_to_candidate_view(lead)
        assert lead == original
        assert view["id"] == "cand-bi-abc123"
        assert view["type"] == "hunt-idor"
        assert view["provenance"]["origin_lead_id"] == "bi-abc123"

    def test_leads_to_candidates_view_does_not_change_score_lead_output(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        mem = director.load_memory(str(tmp_path / "hunt-memory"))
        lead = {
            "id": "bi-1", "target": "t.example", "skill": "hunt-idor",
            "priority": "high", "signal": "s", "why": "w", "evidence": "e",
            "source": "browser-intel", "status": "new",
        }
        before = d._score_lead(lead, "t.example", [], mem)
        cand.leads_to_candidates([lead])  # the retrofit view — side-effect-free
        after = d._score_lead(lead, "t.example", [], mem)
        assert before == after

    def test_secret_scan_evidence_type_read_back_from_why(self):
        lead = {
            "id": "tf-1", "target": "t.example", "skill": "hunt-source-leak",
            "priority": "high", "signal": "exposed_sourcemap",
            "why": "exposed_sourcemap finding (directory_evidence, evidence_type=Browser-Artifact)",
            "evidence": "e", "source": "secret-scan", "status": "new",
        }
        view = cand.lead_to_candidate_view(lead)
        assert view["evidence"][0]["type"] == "Browser-Artifact"

    def test_unrecognized_source_falls_back_to_historical_memory_not_fabricated(self):
        lead = {
            "id": "L1", "target": "t.example", "skill": "hunt-graphql",
            "priority": "med", "signal": "s", "why": "w", "evidence": "e",
            "source": "graphql", "status": "new",
        }
        view = cand.lead_to_candidate_view(lead)
        assert view["evidence"][0]["type"] == "Historical-Memory"


class TestCandidateToLeadView:
    def test_round_trip_shape_matches_lead_board_convention(self):
        c = cand.make_candidate(
            source="object-model", type_="ownership_violation",
            evidence=[{"type": "Observed-HTTP-Response", "detail": "actor B accessed actor A's object",
                       "artifact": "object:Document:42"}],
            rationale="observed access contradicts current OWNS relationship",
            validation_plan={"steps": ["retry modifying request as non-owner"],
                              "expected": "403 / 401", "stop_condition": "retry fails -> not reproducible"},
            metadata={"target": "t.example"},
        )
        lead = cand.candidate_to_lead_view(c, skill="hunt-idor", priority="high")
        assert lead["id"] == f"cand-{c['id']}"
        assert lead["target"] == "t.example"
        assert lead["skill"] == "hunt-idor"
        assert lead["priority"] == "high"
        assert lead["source"] == "object-model"
        assert lead["candidate_id"] == c["id"]
        assert lead["status"] == "new"
