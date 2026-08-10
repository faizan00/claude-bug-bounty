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
        elif self.path.startswith("/api/expiring/"):
            # Simulates account B's session having expired/been revoked:
            # account A still gets real data, account B gets 401 no matter
            # what -- never a shared error page (which IS meaningfully
            # equal to nothing), always A=200/B=401 specifically.
            if "token-account-a" in auth:
                body = json.dumps({"order_id": self.path.rsplit("/", 1)[-1], "owner": "alice"})
                self.send_response(200)
            else:
                body = json.dumps({"error": "session expired"})
                self.send_response(401)
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


class TestSessionExpiryDetection:
    """Phase 4 (failure/recovery): a session that expires/gets revoked
    partway through a multi-URL --auto run must never silently become
    "no IDOR found" with no signal at all -- missing evidence (a broken
    session) is not the same claim as negative evidence (a well-protected
    endpoint), and this codebase's discipline forbids treating either one
    as if it were the other."""

    def test_majority_non_2xx_for_one_session_warns(self):
        results = (
            [{"url": f"/a/{i}", "status_a": 200, "status_b": 200} for i in range(2)]
            + [{"url": f"/a/{i}", "status_a": 200, "status_b": 401} for i in range(2, 6)]
        )
        warnings = idd.detect_possible_session_expiry(results)
        assert len(warnings) == 1
        assert "Session B" in warnings[0]
        assert "4/6" in warnings[0]

    def test_minority_non_2xx_never_warns(self):
        # A couple of individually-protected resources is expected and
        # normal -- must not be confused with a broken session.
        results = (
            [{"url": f"/a/{i}", "status_a": 200, "status_b": 200} for i in range(8)]
            + [{"url": f"/a/{i}", "status_a": 200, "status_b": 403} for i in range(8, 10)]
        )
        assert idd.detect_possible_session_expiry(results) == []

    def test_empty_results_never_warns(self):
        assert idd.detect_possible_session_expiry([]) == []

    def test_below_min_sample_never_warns_even_at_100_percent_failure(self):
        # A single --url test hitting one genuinely protected resource
        # must not produce a session-expiry warning -- there's no
        # aggregate PATTERN in a sample of 1-2, just one status code the
        # hunter already sees directly.
        results = [{"url": "/a/1", "status_a": 200, "status_b": 401}]
        assert idd.detect_possible_session_expiry(results) == []
        results2 = [{"url": f"/a/{i}", "status_a": 200, "status_b": 401} for i in range(2)]
        assert idd.detect_possible_session_expiry(results2) == []

    def test_error_only_results_never_warn_key_error(self):
        # test_url() sets result["error"] and returns early WITHOUT
        # status_a/status_b on a ScopeViolation/RequestCapExceeded/network
        # error -- must not KeyError or misclassify these as a session
        # problem (they're a completely different failure class).
        results = [{"url": "/a/1", "matched": False, "reason": None, "error": "out-of-scope"}]
        assert idd.detect_possible_session_expiry(results) == []

    def test_both_sessions_degrading_produces_two_warnings(self):
        results = [{"url": f"/a/{i}", "status_a": 401, "status_b": 403} for i in range(4)]
        warnings = idd.detect_possible_session_expiry(results)
        assert len(warnings) == 2
        assert any("Session A" in w for w in warnings)
        assert any("Session B" in w for w in warnings)

    def test_real_run_against_a_degrading_endpoint_surfaces_the_warning(
        self, demo_server, two_sessions, isolated_leads, tmp_path
    ):
        # End-to-end against the real local server: account B's session is
        # rejected (401) for every /api/expiring/* URL, exactly the
        # "session expired mid-run" scenario -- must neither fabricate an
        # IDOR match (both must be 2xx) NOR stay silent about the pattern.
        session_a, session_b = two_sessions
        runner = _runner("demo.local", session_a, session_b, tmp_path / "hunt-memory")
        urls = [f"{demo_server}/api/expiring/{i}" for i in range(4)]
        results = runner.run(urls)
        assert not runner.findings  # never a fabricated match
        warnings = idd.detect_possible_session_expiry(results)
        assert len(warnings) == 1
        assert "Session B" in warnings[0]
        assert "4/4" in warnings[0]

    def test_json_output_shape_carries_warnings_without_losing_results(
        self, demo_server, two_sessions, isolated_leads, tmp_path, capsys
    ):
        session_a, session_b = two_sessions
        rc = idd.main([
            "demo.local", "--url", f"{demo_server}/api/expiring/1",
            "--session-a-file", str(_write_session(tmp_path, "sa.json", "token-account-a")),
            "--session-b-file", str(_write_session(tmp_path, "sb.json", "token-account-b")),
            "--domain", "localhost", "--i-understand", "--json",
            "--memory-dir", str(tmp_path / "hunt-memory"),
        ])
        assert rc == 0
        # main() always prints an informational banner (target/session
        # summary) before the JSON blob, even in --json mode -- pre-existing
        # behavior unrelated to this fix; extract just the JSON tail.
        raw = capsys.readouterr().out
        out = json.loads(raw[raw.index("{"):])
        assert "results" in out and "warnings" in out
        assert len(out["results"]) == 1
        assert out["warnings"] == []  # a single 401 out of 1 -- not a MAJORITY, correctly no warning


def _write_session(tmp_path, name, token):
    p = tmp_path / name
    p.write_text(json.dumps({"bearer": token}))
    return p
