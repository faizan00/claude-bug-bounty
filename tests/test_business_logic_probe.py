"""Tests for tools/business_logic_probe.py — mutation-gated producer for
memory/object_model.py Part 2 (rules/logic_patterns.yaml).

Real end-to-end tests against a real local HTTP server (no mocks, no live
network): establish() + probe() -> real Observations -> a real Candidate
out of the actual detect_logic_pattern_violations() / director.py
object_model_leads() pipeline, not a reimplementation. Every one of the 7
patterns in rules/logic_patterns.yaml has been gated shut since Phase 6
(zero required_relationships evidence ever recorded) -- these tests prove
this tool is the first thing that ever opens that gate.
"""

import http.server
import json
import threading

import pytest

import business_logic_probe as blp
from tools import lead_board as lb
from tools.auth_session import AuthSession
from tools.scope_checker import ScopeChecker
from tools import director
from memory.object_model import load_logic_patterns, LogicPatternLoadError


class _OrgHandler(http.server.BaseHTTPRequestHandler):
    """Two endpoints: a genuinely vulnerable invite (no CAN_INVITE check)
    and a genuinely fixed one (checks the actor)."""

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        auth = self.headers.get("Authorization", "")
        if self.path == "/api/orgs/42/invite":
            self.send_response(200)  # VULNERABLE: no authorization check at all
        elif self.path == "/api/orgs/42/invite-fixed":
            self.send_response(200 if "token-admin" in auth else 403)  # FIXED
        elif self.path == "/api/orgs/42/refund":
            self.send_response(200)  # VULNERABLE refund
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"ok": True}).encode())

    def do_GET(self):  # noqa: N802
        if self.path == "/api/orgs/42/dashboard":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"dashboard": True}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def demo_server():
    httpd = http.server.ThreadingHTTPServer(("localhost", 0), _OrgHandler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://localhost:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture
def isolated_leads(tmp_path, monkeypatch):
    monkeypatch.setattr(lb, "LEADS_DIR", str(tmp_path / "leads"))
    return tmp_path


@pytest.fixture
def sessions(tmp_path):
    admin = tmp_path / "admin.json"
    attacker = tmp_path / "attacker.json"
    admin.write_text(json.dumps({"bearer": "token-admin"}))
    attacker.write_text(json.dumps({"bearer": "token-attacker"}))
    return AuthSession.from_file(admin), AuthSession.from_file(attacker)


class TestPatternSpecsMatchYaml:
    """The single most important regression guard: this tool's hardcoded
    PATTERN_SPECS table must never silently drift from the actual YAML it
    claims to implement."""

    @pytest.mark.parametrize("pattern_id", sorted(blp.PATTERN_SPECS))
    def test_every_hardcoded_pattern_matches_the_real_yaml(self, pattern_id):
        blp._validate_spec_matches_yaml(pattern_id, blp.PATTERN_SPECS[pattern_id])  # must not raise

    def test_every_real_yaml_pattern_has_a_hardcoded_spec(self):
        yaml_ids = {p.id for p in load_logic_patterns()}
        assert yaml_ids == set(blp.PATTERN_SPECS)

    def test_detects_a_real_mismatch(self, tmp_path):
        bad_spec = blp.PatternSpec(
            establish_relationship="CAN_INVITE", establish_event="invite_capability_granted",
            action_event="modified",  # wrong -- real invite_flow uses membership_granted
            action_context=None, performed_by_field="metadata.performed_by",
            governing_object_field="subject_id", action_is_mutating=True, object_type="User",
        )
        with pytest.raises(ValueError, match="no longer matches"):
            blp._validate_spec_matches_yaml("invite_flow", bad_spec)


class TestInviteFlowEndToEnd:
    def test_vulnerable_endpoint_produces_a_real_violation(self, demo_server, sessions, isolated_leads, tmp_path):
        admin, attacker = sessions
        target = "demo.local"
        memory_dir = tmp_path / "hunt-memory"

        blp.establish(target, "invite_flow", admin, "42", str(memory_dir))

        checker = ScopeChecker(["localhost"])
        runner = blp.ProbeRunner(target, checker, attacker, memory_dir=str(memory_dir), allow_mutate=True)
        result = runner.probe("invite_flow", "POST", f"{demo_server}/api/orgs/42/invite",
                               "42", "newuser@x.com", data='{"email":"newuser@x.com"}')

        assert result["status"] == 200
        assert result["violations"], "detect_logic_pattern_violations() never fired"
        assert result["violations"][0]["type"] == "invite_flow_violation"

        # The actual consumer: director.py's real function, not a reimplementation.
        leads = director.object_model_leads(target, str(memory_dir))
        assert any(l["signal"] == "invite_flow_violation" for l in leads)

        # A real lead-board entry too.
        board_leads = lb.load_ledger(target)
        assert any(l["skill"] == "hunt-business-logic" for l in board_leads)

    def test_fixed_endpoint_produces_no_violation(self, demo_server, sessions, isolated_leads, tmp_path):
        admin, attacker = sessions
        target = "demo-fixed.local"
        memory_dir = tmp_path / "hunt-memory"

        blp.establish(target, "invite_flow", admin, "42", str(memory_dir))

        checker = ScopeChecker(["localhost"])
        runner = blp.ProbeRunner(target, checker, attacker, memory_dir=str(memory_dir), allow_mutate=True)
        result = runner.probe("invite_flow", "POST", f"{demo_server}/api/orgs/42/invite-fixed",
                               "42", "newuser@x.com", data='{"email":"newuser@x.com"}')

        assert result["status"] == 403
        assert not result["violations"]

    def test_without_establish_the_gate_stays_closed(self, demo_server, sessions, isolated_leads, tmp_path):
        """Part 2's own non-negotiable discipline: zero required_relationships
        evidence means the pattern does not execute at all -- even against
        the genuinely vulnerable endpoint."""
        _, attacker = sessions
        target = "never-established.local"
        memory_dir = tmp_path / "hunt-memory"

        checker = ScopeChecker(["localhost"])
        runner = blp.ProbeRunner(target, checker, attacker, memory_dir=str(memory_dir), allow_mutate=True)
        result = runner.probe("invite_flow", "POST", f"{demo_server}/api/orgs/42/invite",
                               "42", "newuser@x.com", data='{"email":"newuser@x.com"}')

        assert result["status"] == 200  # the vulnerable endpoint still returns success...
        assert not result["violations"]  # ...but the ungated pattern correctly refuses to fire


class TestReadOnlyTenantIsolation:
    def test_get_only_enforced(self, demo_server, sessions, isolated_leads, tmp_path):
        admin, attacker = sessions
        checker = ScopeChecker(["localhost"])
        runner = blp.ProbeRunner("demo.local", checker, attacker, memory_dir=str(tmp_path / "hunt-memory"),
                                  allow_mutate=False)
        with pytest.raises(ValueError, match="method must be GET"):
            runner.probe("tenant_isolation", "POST", f"{demo_server}/api/orgs/42/dashboard", "42", "dash")

    def test_mutating_pattern_rejects_get(self, demo_server, sessions, isolated_leads, tmp_path):
        admin, attacker = sessions
        checker = ScopeChecker(["localhost"])
        runner = blp.ProbeRunner("demo.local", checker, attacker, memory_dir=str(tmp_path / "hunt-memory"),
                                  allow_mutate=False)
        with pytest.raises(ValueError, match="needs a mutating method"):
            runner.probe("invite_flow", "GET", f"{demo_server}/api/orgs/42/invite", "42", "x")

    def test_real_tenant_isolation_violation(self, demo_server, sessions, isolated_leads, tmp_path):
        admin, attacker = sessions
        target = "tenant.local"
        memory_dir = tmp_path / "hunt-memory"
        # attacker is NOT a member of org 42 -- establish membership for a
        # DIFFERENT session (admin) so the HAS_MEMBER gate opens, then probe
        # as the non-member.
        blp.establish(target, "tenant_isolation", admin, "42", str(memory_dir))

        checker = ScopeChecker(["localhost"])
        runner = blp.ProbeRunner(target, checker, attacker, memory_dir=str(memory_dir), allow_mutate=False)
        result = runner.probe("tenant_isolation", "GET", f"{demo_server}/api/orgs/42/dashboard", "42", "dashboard")

        assert result["status"] == 200
        assert result["violations"]
        assert result["violations"][0]["type"] == "tenant_isolation_pattern_violation"


class TestRefundPattern:
    """Different field-mapping shape than invite_flow (HAS_MEMBER not
    CAN_INVITE, performed_by=subject_id not metadata.performed_by,
    governing_object=metadata.organization_id not subject_id) -- proves
    the tool is genuinely generic across pattern shapes, not just working
    by coincidence for one pattern."""

    def test_refund_violation_detected(self, demo_server, sessions, isolated_leads, tmp_path):
        admin, attacker = sessions
        target = "refund.local"
        memory_dir = tmp_path / "hunt-memory"
        blp.establish(target, "refund", admin, "42", str(memory_dir))

        checker = ScopeChecker(["localhost"])
        runner = blp.ProbeRunner(target, checker, attacker, memory_dir=str(memory_dir), allow_mutate=True)
        result = runner.probe("refund", "POST", f"{demo_server}/api/orgs/42/refund", "42", "refund-99")

        assert result["status"] == 200
        assert result["violations"]
        assert result["violations"][0]["type"] == "refund_violation"


class TestSessionCheckpoint:
    """Part 3 (memory/object_model.py's make_checkpoint()/save_session())
    has had zero producers since Phase 6 -- establish()/probe() must be
    the first thing that ever writes one, automatically (not opt-in),
    since an optional checkpoint nobody remembers to request is exactly
    how this mechanism stayed dormant in the first place."""

    def test_establish_writes_a_real_checkpoint(self, sessions, isolated_leads, tmp_path):
        admin, _ = sessions
        target = "cp.local"
        memory_dir = tmp_path / "hunt-memory"
        blp.establish(target, "invite_flow", admin, "42", str(memory_dir))

        path = blp.checkpoint_path(str(memory_dir), target, "invite_flow")
        assert path.exists()
        cp = json.loads(path.read_text())
        assert cp["version"] == 1
        assert cp["workflow_state"]["last_action"] == "establish"
        assert cp["workflow_state"]["pattern"] == "invite_flow"
        assert cp["fingerprinted_session_reference"] == admin.session_id()
        # entity:Organization:42 is what admin's own establish() call
        # touched (the org side of the CAN_INVITE grant).
        assert "entity:Organization:42" in cp["reachable_objects"]

    def test_probe_updates_the_checkpoint_with_the_real_outcome(
        self, demo_server, sessions, isolated_leads, tmp_path
    ):
        admin, attacker = sessions
        target = "cp2.local"
        memory_dir = tmp_path / "hunt-memory"
        blp.establish(target, "invite_flow", admin, "42", str(memory_dir))

        checker = ScopeChecker(["localhost"])
        runner = blp.ProbeRunner(target, checker, attacker, memory_dir=str(memory_dir), allow_mutate=True)
        runner.probe("invite_flow", "POST", f"{demo_server}/api/orgs/42/invite",
                      "42", "newuser@x.com", data='{"email":"newuser@x.com"}')

        cp = json.loads(blp.checkpoint_path(str(memory_dir), target, "invite_flow").read_text())
        assert cp["workflow_state"]["last_action"] == "probe"
        assert cp["workflow_state"]["last_status"] == 200
        assert cp["workflow_state"]["violation_detected"] is True
        assert cp["fingerprinted_session_reference"] == attacker.session_id()
        assert "object:User:newuser@x.com" in cp["reachable_objects"]

    def test_no_raw_credentials_ever_reach_the_checkpoint_file(self, sessions, isolated_leads, tmp_path):
        admin, _ = sessions
        memory_dir = tmp_path / "hunt-memory"
        blp.establish("cp3.local", "invite_flow", admin, "42", str(memory_dir))
        raw = blp.checkpoint_path(str(memory_dir), "cp3.local", "invite_flow").read_text()
        assert "token-admin" not in raw

    def test_reachable_refs_ignores_a_different_actor(self):
        actor = "entity:User:aaa"
        other = "entity:User:bbb"
        observations = [
            {"subject_id": other, "object_id": "object:Doc:1", "outcome_status": 200, "metadata": {}},
            {"subject_id": actor, "object_id": "object:Doc:2", "outcome_status": 200, "metadata": {}},
        ]
        objects, caps = blp._reachable_refs(observations, actor)
        assert objects == ["object:Doc:2"]
        assert caps == []

    def test_reachable_refs_excludes_failed_requests(self):
        actor = "entity:User:aaa"
        observations = [
            {"subject_id": actor, "object_id": "object:Doc:1", "outcome_status": 403, "metadata": {}},
            {"subject_id": actor, "object_id": "object:Doc:2", "outcome_status": 200, "metadata": {}},
        ]
        objects, _ = blp._reachable_refs(observations, actor)
        assert objects == ["object:Doc:2"]

    def test_reachable_refs_matches_metadata_performed_by_too(self):
        """membership_granted's subject_id is the ORG, not the actor -- the
        actor only appears in metadata.performed_by (see PATTERN_SPECS).
        _reachable_refs() must still find it there."""
        actor = "entity:User:aaa"
        observations = [
            {"subject_id": "entity:Organization:42", "object_id": "object:User:invited",
             "outcome_status": 200, "metadata": {"performed_by": actor}},
        ]
        objects, _ = blp._reachable_refs(observations, actor)
        assert objects == ["object:User:invited"]


class TestSafety:
    def test_establish_dry_run_records_nothing(self, sessions, tmp_path):
        admin, _ = sessions
        memory_dir = tmp_path / "hunt-memory"
        rc = blp.main([
            "demo.local", "--pattern", "invite_flow", "--establish",
            "--holder-session-file", str(_write_session(tmp_path, "admin2.json", "token-admin")),
            "--org-ref", "42", "--memory-dir", str(memory_dir),
        ])
        assert rc == 0
        assert not (memory_dir / "object_model").exists()

    def test_probe_dry_run_makes_no_request_and_records_nothing(self, demo_server, tmp_path):
        memory_dir = tmp_path / "hunt-memory"
        rc = blp.main([
            "demo.local", "--pattern", "invite_flow", "--probe",
            "--acting-session-file", str(_write_session(tmp_path, "attacker2.json", "token-attacker")),
            "--org-ref", "42", "--target-ref", "x@y.com",
            "--method", "POST", "--url", f"{demo_server}/api/orgs/42/invite",
            "--domain", "localhost", "--memory-dir", str(memory_dir),
        ])
        assert rc == 0
        assert not (memory_dir / "object_model").exists()

    def test_probe_requires_allow_mutate_for_mutating_pattern(self, demo_server, tmp_path, capsys):
        memory_dir = tmp_path / "hunt-memory"
        rc = blp.main([
            "demo.local", "--pattern", "invite_flow", "--probe",
            "--acting-session-file", str(_write_session(tmp_path, "attacker3.json", "token-attacker")),
            "--org-ref", "42", "--target-ref", "x@y.com",
            "--method", "POST", "--url", f"{demo_server}/api/orgs/42/invite",
            "--domain", "localhost", "--memory-dir", str(memory_dir), "--i-understand",
        ])
        assert rc == 1
        assert "--allow-mutate" in capsys.readouterr().err
        assert not (memory_dir / "object_model").exists()

    def test_unknown_pattern_rejected_by_argparse(self):
        with pytest.raises(SystemExit):
            blp.main(["demo.local", "--pattern", "not-a-real-pattern", "--establish",
                      "--holder-session-file", "x.json", "--org-ref", "42"])


def _write_session(tmp_path, name, bearer):
    p = tmp_path / name
    p.write_text(json.dumps({"bearer": bearer}))
    return p
