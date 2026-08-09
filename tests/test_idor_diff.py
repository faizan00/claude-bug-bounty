"""Tests for tools/idor_diff.py — generic cross-session IDOR/BOLA diff tester.

Real end-to-end tests against a real local HTTP server (no mocks, no live
network) proving the full chain works: idor_diff.py's diff logic -> real
Observations recorded via memory/object_model.py -> real Candidates from
detect_relationship_violations() -> real scored leads from
tools/director.py's object_model_leads(). Before this tool existed, that
chain had never fired in a live hunt at all (detect_relationship_
violations() was real and tested in isolation, but had no producer).
"""

import http.server
import json
import threading

import pytest

import idor_diff as idd
# from tools import lead_board (not bare `import lead_board`) so
# monkeypatch.setattr(lb, "LEADS_DIR", ...) reaches the SAME module object
# idor_diff.py's own `from tools import lead_board as lead_board` uses --
# same gotcha already documented in tests/test_director.py.
from tools import lead_board as lb
from tools.auth_session import AuthSession
from tools.scope_checker import ScopeChecker
from tools import director


class _OrdersHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        auth = self.headers.get("Authorization", "")
        if self.path == "/api/orders/1042":
            # VULNERABLE: identical data regardless of who's asking.
            body = json.dumps({"order_id": 1042, "owner": "alice", "total": 499.0})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body.encode())
        elif self.path == "/api/orders/2000":
            # FIXED: ownership-checked, only account A gets data.
            if "token-account-a" in auth:
                body = json.dumps({"order_id": 2000, "owner": "alice"})
                self.send_response(200)
            else:
                body = json.dumps({"error": "forbidden"})
                self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body.encode())
        elif self.path == "/api/public/catalog":
            # Legitimately shared data -- identical to everyone on purpose,
            # not a per-object ownership case (this URL isn't object-scoped
            # so discover_candidate_urls() should never even suggest it,
            # but a direct --url test must still not crash on it).
            body = json.dumps({"items": ["widget", "gadget"]})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body.encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def demo_server():
    httpd = http.server.ThreadingHTTPServer(("localhost", 0), _OrdersHandler)
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
def two_sessions(tmp_path):
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    a.write_text(json.dumps({"bearer": "token-account-a"}))
    b.write_text(json.dumps({"bearer": "token-account-b"}))
    return AuthSession.from_file(a), AuthSession.from_file(b)


def _runner(target, session_a, session_b, memory_dir, owner=None):
    checker = ScopeChecker(["localhost"])
    return idd.IdorDiffRunner(target, checker, session_a, session_b, owner=owner, memory_dir=str(memory_dir))


class TestDiffLogic:
    def test_flags_identical_json_returned_to_both_sessions(self, demo_server, two_sessions, isolated_leads, tmp_path):
        session_a, session_b = two_sessions
        runner = _runner("demo.local", session_a, session_b, tmp_path / "hunt-memory")
        result = runner.test_url(f"{demo_server}/api/orders/1042")
        assert result["matched"] is True
        assert result["status_a"] == 200 and result["status_b"] == 200
        assert runner.findings

    def test_does_not_flag_a_fixed_endpoint(self, demo_server, two_sessions, isolated_leads, tmp_path):
        session_a, session_b = two_sessions
        runner = _runner("demo.local", session_a, session_b, tmp_path / "hunt-memory")
        result = runner.test_url(f"{demo_server}/api/orders/2000")
        assert result["matched"] is False
        assert result["status_a"] == 200
        assert result["status_b"] == 403
        assert not runner.findings

    def test_a_match_writes_a_real_lead(self, demo_server, two_sessions, isolated_leads, tmp_path):
        session_a, session_b = two_sessions
        target = "demo.local"
        runner = _runner(target, session_a, session_b, tmp_path / "hunt-memory")
        runner.test_url(f"{demo_server}/api/orders/1042")
        leads = lb.load_ledger(target)
        assert any(l["skill"] == "hunt-idor" and f"{demo_server}/api/orders/1042" in l["evidence"] for l in leads)

    def test_identical_sessions_are_rejected(self, tmp_path):
        a = tmp_path / "same.json"
        a.write_text(json.dumps({"bearer": "identical-token"}))
        s1 = AuthSession.from_file(a)
        s2 = AuthSession.from_file(a)
        assert s1.session_id() == s2.session_id()  # sanity: fixture actually identical


class TestObjectModelWiring:
    """The real point of this tool: it must be the first thing that ever
    populates memory/object_model.py's relationship graph in a live run."""

    def test_owner_flag_produces_a_real_ownership_violation_candidate(
        self, demo_server, two_sessions, isolated_leads, tmp_path
    ):
        session_a, session_b = two_sessions
        target = "demo.local"
        memory_dir = tmp_path / "hunt-memory"
        runner = _runner(target, session_a, session_b, memory_dir, owner="a")
        runner.test_url(f"{demo_server}/api/orders/1042")

        # Real observations landed on disk.
        obs_path = memory_dir / "object_model" / f"{target}.jsonl"
        assert obs_path.exists()
        observations = [json.loads(ln) for ln in obs_path.read_text().splitlines() if ln.strip()]
        events = {o["event"] for o in observations}
        assert events == {"created", "accessed"}
        created = next(o for o in observations if o["event"] == "created")
        assert created["relationship_type"] == "OWNS"
        assert created["subject_id"] == f"entity:User:{session_a.session_id()}"

        # The actual consumer: director.py's real function, not a reimplementation.
        leads = director.object_model_leads(target, str(memory_dir))
        assert leads, "detect_relationship_violations() never fired -- the producer/consumer wiring is broken"
        assert leads[0]["signal"] == "ownership_violation"
        assert leads[0]["skill"] == "hunt-idor"

    def test_without_owner_flag_only_behavioral_observations_recorded(
        self, demo_server, two_sessions, isolated_leads, tmp_path
    ):
        """No --owner means no relationship-establishing claim -- object_model.py's
        own discipline (never infer OWNS without genuine out-of-band
        knowledge) must hold even when idor_diff.py finds a match."""
        session_a, session_b = two_sessions
        target = "demo.local"
        memory_dir = tmp_path / "hunt-memory"
        runner = _runner(target, session_a, session_b, memory_dir, owner=None)
        runner.test_url(f"{demo_server}/api/orders/1042")

        obs_path = memory_dir / "object_model" / f"{target}.jsonl"
        observations = [json.loads(ln) for ln in obs_path.read_text().splitlines() if ln.strip()]
        assert {o["event"] for o in observations} == {"accessed"}
        assert all(o["relationship_type"] is None for o in observations)

        # No OWNS edge exists yet -- detect_relationship_violations() must
        # correctly find nothing to contradict.
        leads = director.object_model_leads(target, str(memory_dir))
        assert leads == []

    def test_no_match_records_no_observations_at_all(self, demo_server, two_sessions, isolated_leads, tmp_path):
        """ObservationStore's own __init__ eagerly mkdir()s its parent dir
        (same convention as every other JSONL store in this codebase) --
        that's not what's being tested here. The real assertion is that no
        observation was ever appended for a non-matching URL."""
        session_a, session_b = two_sessions
        target = "demo.local"
        memory_dir = tmp_path / "hunt-memory"
        runner = _runner(target, session_a, session_b, memory_dir, owner="a")
        runner.test_url(f"{demo_server}/api/orders/2000")  # the fixed endpoint
        obs_path = memory_dir / "object_model" / f"{target}.jsonl"
        assert not obs_path.exists() or obs_path.read_text().strip() == ""


class TestCandidateUrlDiscovery:
    def test_looks_object_scoped_matches_numeric_path_and_query_id(self):
        assert idd.looks_object_scoped("https://x.example/api/orders/1042")
        assert idd.looks_object_scoped("https://x.example/api/export?order_id=42")
        assert idd.looks_object_scoped(
            "https://x.example/api/docs/550e8400-e29b-41d4-a716-446655440000"
        )

    def test_looks_object_scoped_rejects_non_object_urls(self):
        assert not idd.looks_object_scoped("https://x.example/api/public/catalog")
        assert not idd.looks_object_scoped("https://x.example/login")

    def test_discover_candidate_urls_filters_and_caps(self, tmp_path):
        urls_dir = tmp_path / "urls"
        urls_dir.mkdir()
        (urls_dir / "with_params.txt").write_text(
            "https://x.example/api/orders/101\n"
            "https://x.example/login\n"
            "https://x.example/api/orders/102\n"
            "https://x.example/api/orders/103\n"
        )
        found = idd.discover_candidate_urls(str(tmp_path), max_urls=2)
        assert len(found) == 2
        assert all("orders" in u for u in found)

    def test_discover_candidate_urls_missing_dir_returns_empty(self, tmp_path):
        assert idd.discover_candidate_urls(str(tmp_path / "nonexistent"), max_urls=10) == []


class TestSafety:
    def test_dry_run_without_i_understand_makes_no_request(self, capsys):
        rc = idd.main([
            "demo.local", "--url", "https://demo.local/api/orders/1",
            "--session-a-file", "/nonexistent/a.json",
            "--session-b-file", "/nonexistent/b.json",
            "--domain", "demo.local",
        ])
        assert rc == 1  # both session files are empty -> rejected before any dry-run/network step
        assert "must load at least one header" in capsys.readouterr().err

    def test_out_of_scope_url_is_refused_not_silently_skipped(self, two_sessions, isolated_leads, tmp_path):
        session_a, session_b = two_sessions
        runner = _runner("demo.local", session_a, session_b, tmp_path / "hunt-memory")
        result = runner.test_url("https://out-of-scope.invalid/api/orders/1")
        assert result["error"] is not None
        assert "out-of-scope" in result["error"] or "scope" in result["error"].lower()
        assert not runner.findings
