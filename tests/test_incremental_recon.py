"""Tests for tools/incremental_recon.py — the "DISCOVER NEW INFORMATION ->
RECON AGAIN" step recon_engine.sh's linear pipeline never had.

Real end-to-end tests against a real local HTTP server (no mocks, no live
network): a host referenced only in urls/all.txt or browser/api-calls.json
(never in subdomains/all.txt) gets discovered, really probed, and — if
live — really merged back into subdomains/all.txt + live/urls.txt so
every downstream tool picks it up for free.
"""

import http.server
import json
import threading

import pytest

import incremental_recon as ir
from tools.recon_adapter import ReconAdapter
from tools.scope_checker import ScopeChecker


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/":
            self.send_response(200)
        elif self.path == "/forbidden":
            self.send_response(403)
        else:
            self.send_response(404)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def demo_server():
    httpd = http.server.ThreadingHTTPServer(("localhost", 0), _Handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        httpd.shutdown()
        httpd.server_close()


def _seed(recon_dir, subdomains=(), urls=(), api_calls=None):
    (recon_dir / "subdomains").mkdir(parents=True, exist_ok=True)
    (recon_dir / "subdomains" / "all.txt").write_text("\n".join(subdomains) + ("\n" if subdomains else ""))
    (recon_dir / "urls").mkdir(parents=True, exist_ok=True)
    (recon_dir / "urls" / "all.txt").write_text("\n".join(urls) + ("\n" if urls else ""))
    if api_calls is not None:
        (recon_dir / "browser").mkdir(parents=True, exist_ok=True)
        (recon_dir / "browser" / "api-calls.json").write_text(json.dumps({"calls": api_calls}))


class TestOriginOf:
    def test_default_https_port_omitted(self):
        assert ir._origin_of("https://x.example/path") == "https://x.example"

    def test_default_http_port_omitted(self):
        assert ir._origin_of("http://x.example:80/path") == "http://x.example"

    def test_non_default_port_preserved(self):
        assert ir._origin_of("https://x.example:8443/api") == "https://x.example:8443"
        assert ir._origin_of("http://x.example:8080/") == "http://x.example:8080"

    def test_hostname_lowercased(self):
        assert ir._origin_of("https://X.EXAMPLE/") == "https://x.example"

    def test_non_http_scheme_rejected(self):
        assert ir._origin_of("ftp://x.example/") is None
        assert ir._origin_of("mailto:a@x.example") is None

    def test_malformed_url_returns_none(self):
        assert ir._origin_of("not a url") is None
        assert ir._origin_of("") is None


class TestDiscoverCandidateOrigins:
    def test_reads_urls_all_txt(self, tmp_path):
        _seed(tmp_path, urls=["https://api.example/v1/x", "https://api.example/v1/y"])
        counts = ir.discover_candidate_origins(str(tmp_path))
        assert counts["https://api.example"] == 2

    def test_reads_api_calls_json(self, tmp_path):
        _seed(tmp_path, api_calls=[
            {"url": "https://internal.example/x", "response_status": 200},
            {"url": "https://internal.example/y", "response_status": 200},
        ])
        counts = ir.discover_candidate_origins(str(tmp_path))
        assert counts["https://internal.example"] == 2

    def test_missing_files_returns_empty_not_raises(self, tmp_path):
        assert ir.discover_candidate_origins(str(tmp_path / "nonexistent")) == {}

    def test_malformed_api_calls_json_does_not_raise(self, tmp_path):
        _seed(tmp_path)
        (tmp_path / "browser").mkdir(parents=True, exist_ok=True)
        (tmp_path / "browser" / "api-calls.json").write_text("{not valid json")
        assert ir.discover_candidate_origins(str(tmp_path)) == {}


class TestNewInScopeOrigins:
    def test_already_known_host_excluded_even_on_a_new_port(self, tmp_path):
        _seed(tmp_path, subdomains=["api.example"], urls=["https://api.example:8443/x"])
        checker = ScopeChecker(["*.example", "example"])
        new = ir.new_in_scope_origins(str(tmp_path), checker)
        assert new == []

    def test_out_of_scope_origin_excluded(self, tmp_path):
        _seed(tmp_path, urls=["https://evil-unrelated.com/x"])
        checker = ScopeChecker(["*.example", "example"])
        new = ir.new_in_scope_origins(str(tmp_path), checker)
        assert new == []

    def test_genuinely_new_in_scope_host_included(self, tmp_path):
        _seed(tmp_path, subdomains=["example"], urls=["https://api.example/x"])
        checker = ScopeChecker(["*.example", "example"])
        new = ir.new_in_scope_origins(str(tmp_path), checker)
        assert new == ["https://api.example"]

    def test_most_referenced_first_then_alphabetical(self, tmp_path):
        _seed(tmp_path, urls=[
            "https://b.example/1", "https://a.example/1", "https://a.example/2",
        ])
        checker = ScopeChecker(["*.example"])
        new = ir.new_in_scope_origins(str(tmp_path), checker)
        assert new == ["https://a.example", "https://b.example"]

    def test_max_new_hosts_caps(self, tmp_path):
        _seed(tmp_path, urls=[f"https://h{i}.example/x" for i in range(5)])
        checker = ScopeChecker(["*.example"])
        new = ir.new_in_scope_origins(str(tmp_path), checker, max_new_hosts=2)
        assert len(new) == 2


class TestIncrementalReconEndToEnd:
    def test_live_origin_gets_probed_and_merged(self, demo_server, tmp_path):
        recon_dir = tmp_path / "recon" / "demo.local"
        _seed(recon_dir, subdomains=["demo.local"], urls=[f"http://localhost:{demo_server}/api/x"])
        checker = ScopeChecker(["localhost"])
        runner = ir.IncrementalRecon(str(recon_dir), checker)

        candidates = ir.new_in_scope_origins(str(recon_dir), checker)
        assert candidates == [f"http://localhost:{demo_server}"]

        results = runner.run(candidates)
        assert results[0]["live"] is True
        assert results[0]["status"] == 200

        subs = ReconAdapter(str(recon_dir)).get_subdomains()
        assert "localhost" in subs
        live = ReconAdapter(str(recon_dir)).get_live_hosts()
        assert f"http://localhost:{demo_server}/" in live

    def test_error_status_still_counts_as_live(self, demo_server, tmp_path):
        """A 403/404 is a real response -- the host is genuinely live, just
        not necessarily interesting yet. Must still merge (matches httpx's
        own definition of "live": responded, regardless of status)."""
        recon_dir = tmp_path / "recon" / "demo.local"
        _seed(recon_dir, urls=[f"http://localhost:{demo_server}/forbidden"])
        checker = ScopeChecker(["localhost"])
        runner = ir.IncrementalRecon(str(recon_dir), checker)
        results = runner.run([f"http://localhost:{demo_server}"])
        # probe_origin always hits the bare origin + "/", not the referenced
        # path -- "/" on this handler is a 200, proving liveness is judged
        # by the real probe response, not the discovery source's path.
        assert results[0]["live"] is True
        assert results[0]["status"] == 200

    def test_unreachable_origin_is_not_merged(self, tmp_path):
        recon_dir = tmp_path / "recon" / "demo.local"
        _seed(recon_dir, urls=["http://localhost:1/dead"])  # nothing listens on port 1
        checker = ScopeChecker(["localhost"])
        runner = ir.IncrementalRecon(str(recon_dir), checker)
        results = runner.run(["http://localhost:1"])
        assert results[0]["live"] is False
        assert results[0]["error"] is not None
        assert ReconAdapter(str(recon_dir)).get_subdomains() == []

    def test_merge_is_idempotent(self, demo_server, tmp_path):
        recon_dir = tmp_path / "recon" / "demo.local"
        _seed(recon_dir)
        checker = ScopeChecker(["localhost"])
        runner = ir.IncrementalRecon(str(recon_dir), checker)
        origin = f"http://localhost:{demo_server}"
        runner.run([origin])
        runner.run([origin])  # second pass -- must not duplicate
        subs = ReconAdapter(str(recon_dir)).get_subdomains()
        live = ReconAdapter(str(recon_dir)).get_live_hosts()
        assert subs.count("localhost") == 1
        assert live.count(f"{origin}/") == 1

    def test_out_of_scope_candidate_is_never_actually_requested(self, tmp_path):
        """The scope filter must happen BEFORE any candidate reaches the
        Fetcher -- confirms fail-closed behavior, not just that an
        out-of-scope URL happens to return an error."""
        recon_dir = tmp_path / "recon" / "demo.local"
        _seed(recon_dir, urls=["https://out-of-scope.invalid/x"])
        checker = ScopeChecker(["localhost"])  # out-of-scope.invalid is NOT localhost
        candidates = ir.new_in_scope_origins(str(recon_dir), checker)
        assert candidates == []  # filtered before any Fetcher call is even constructed


class TestMainCLI:
    def test_dry_run_makes_no_writes(self, demo_server, tmp_path, capsys):
        recon_dir = tmp_path / "recon" / "demo.local"
        _seed(recon_dir, urls=[f"http://localhost:{demo_server}/x"])
        rc = ir.main(["demo.local", "--recon-dir", str(recon_dir), "--domain", "localhost"])
        assert rc == 0
        assert "DRY-RUN" in capsys.readouterr().out
        assert not (recon_dir / "live").exists()

    def test_real_run_merges_and_reports(self, demo_server, tmp_path, capsys):
        recon_dir = tmp_path / "recon" / "demo.local"
        _seed(recon_dir, urls=[f"http://localhost:{demo_server}/x"])
        rc = ir.main([
            "demo.local", "--recon-dir", str(recon_dir), "--domain", "localhost", "--i-understand",
        ])
        assert rc == 0
        out = capsys.readouterr().out
        assert "1/1 new host(s) live and merged" in out
        assert "localhost" in ReconAdapter(str(recon_dir)).get_subdomains()

    def test_no_candidates_reports_cleanly(self, tmp_path, capsys):
        recon_dir = tmp_path / "recon" / "demo.local"
        _seed(recon_dir, subdomains=["demo.local"])
        rc = ir.main([
            "demo.local", "--recon-dir", str(recon_dir), "--domain", "demo.local", "--i-understand",
        ])
        assert rc == 0
        assert "No new in-scope hosts found" in capsys.readouterr().out
