"""
End-to-end wiring test for tools/recon_engine.sh -> tools/incremental_recon.py
(Phase 5.5: Incremental Re-Recon).

Before this change, recon_engine.sh's 10 phases were strictly linear and
ran once -- a hostname first referenced by Phase 4's URL collection
(gau/wayback/katana) never got probed by Phase 2, fingerprinted by
Phase 2.6, or fed to any downstream tool, because nothing in the pipeline
ever re-checked what got discovered along the way. This is the concrete
"DISCOVER NEW INFORMATION -> RECON AGAIN" gap the mission's own iterative-
recon model describes and `director.py`'s DEFAULT_CHECKPOINTS only ever
gestured at in prose nothing executed.

This test proves the loop actually closes, in one real pipeline
execution: seeds a URL referencing a real local demo server on a host not
yet in subdomains/all.txt (simulating what a real gau/katana crawl would
have found), runs the real recon_engine.sh subprocess (stubbed external
tools, no live network), and asserts the newly discovered host is (a)
actually probed, (b) merged into subdomains/all.txt + live/urls.txt, and
(c) a LATER phase in the SAME run (Phase 6.5's config-exposure check,
which is gated on live/urls.txt being non-empty) picks it up -- not a
future manual re-recon nobody reliably remembers to do.
"""

import http.server
import os
import stat
import subprocess
import threading
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
RECON_ENGINE = REPO_ROOT / "tools" / "recon_engine.sh"

_STUBBED_BINARIES = [
    "subfinder", "amass", "katana", "ffuf", "nuclei", "dig",
    "curl", "gau", "waybackurls", "dnsx", "sisakulint", "trufflehog",
    "gitleaks", "arjun",
    # nmap specifically: unlike test_recon_engine_scope_e2e.py/
    # test_recon_engine_fingerprint_wiring.py (whose scenarios leave
    # subdomains/all.txt empty, so Phase 3's `-s subdomains/all.txt` gate
    # never lets nmap run at all), this test deliberately seeds a real,
    # resolvable domain into subdomains/seed.txt -- an unstubbed nmap
    # installed on the test machine would otherwise really port-scan it
    # over the live network. Must always be stubbed here.
    "nmap",
]


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
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


@pytest.fixture()
def stub_bin_dir(tmp_path):
    d = tmp_path / "stub-bin"
    d.mkdir()
    for name in _STUBBED_BINARIES:
        stub = d / name
        stub.write_text("#!/bin/sh\nexit 1\n")
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    # httpx must answer -version as real ProjectDiscovery httpx or
    # _resolve_pd_httpx() falls back to the bare string "httpx" and Phase 2
    # skips entirely (see tests/test_tool_failure_masking.py's identical
    # stub) -- irrelevant to what THIS test checks, but required for the
    # rest of the pipeline to run its normal phases around Phase 5.5.
    httpx_stub = d / "httpx"
    httpx_stub.write_text('#!/bin/sh\n[ "$1" = "-version" ] && echo "projectdiscovery httpx" && exit 0\nexit 1\n')
    httpx_stub.chmod(httpx_stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return d


@pytest.fixture()
def base_env(stub_bin_dir, tmp_path):
    env = dict(os.environ)
    env["PATH"] = str(stub_bin_dir) + os.pathsep + env.get("PATH", "")
    env["HTTP_PROXY"] = "http://127.0.0.1:1"
    env["HTTPS_PROXY"] = "http://127.0.0.1:1"
    # localhost must actually be reachable for this test's real demo
    # server -- every OTHER recon_engine.sh test wants the opposite
    # (everything routed into a closed port), but this is the first one
    # that needs a real successful probe to prove the merge happened.
    env["NO_PROXY"] = "localhost"
    env["no_proxy"] = "localhost"
    env["HUNT_MEMORY_OUT_DIR"] = str(tmp_path / "hunt-memory")
    return env


def test_new_host_is_discovered_probed_and_merged_within_one_run(demo_server, base_env, tmp_path):
    recon_dir = tmp_path / "recon-out"
    (recon_dir / "urls").mkdir(parents=True)
    (recon_dir / "subdomains").mkdir(parents=True)
    # A uniquely-named seed file: any of the pipeline's own OWN output
    # filenames (gau.txt, katana.txt, all.txt, ...) get truncated by their
    # tool's own `-o`/`>` redirection even when the stubbed tool then
    # fails -- shell redirection truncates before the command runs. This
    # name collides with nothing recon_engine.sh ever writes to, so it
    # survives into Phase 4's `cat urls/*.txt > urls/all.txt` merge.
    (recon_dir / "urls" / "seed_from_a_real_crawl.txt").write_text(
        f"http://localhost:{demo_server}/api/x\n"
    )
    (recon_dir / "subdomains" / "seed.txt").write_text("example.com\n")

    env = dict(base_env)
    env["RECON_OUT_DIR"] = str(recon_dir)
    env["BB_SCOPE_DOMAINS"] = "localhost,example.com,*.example.com"

    proc = subprocess.run(
        ["bash", str(RECON_ENGINE), "example.com", "--quick"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=90, env=env,
    )
    assert proc.returncode == 0, f"stdout={proc.stdout[-3000:]}\nstderr={proc.stderr[-2000:]}"
    assert "Phase 5.5: Incremental Re-Recon" in proc.stdout
    assert f"localhost -> http://localhost:{demo_server}/ [200] (merged)" in proc.stdout, (
        f"stdout={proc.stdout[-3000:]}"
    )

    subs = (recon_dir / "subdomains" / "all.txt").read_text()
    assert "localhost" in subs.splitlines()

    live = (recon_dir / "live" / "urls.txt").read_text()
    assert f"http://localhost:{demo_server}/" in live.splitlines()

    # The real proof this is "recon again," not just a side file: a LATER
    # phase in the SAME run, gated on live/urls.txt being non-empty, must
    # have actually run against the newly merged host, not skipped.
    assert "No live hosts — skipping config check" not in proc.stdout


def test_no_scope_domains_skips_cleanly(base_env, tmp_path):
    recon_dir = tmp_path / "recon-out"
    env = dict(base_env)
    env["RECON_OUT_DIR"] = str(recon_dir)
    env.pop("BB_SCOPE_DOMAINS", None)
    env["BB_SCOPE_DOMAINS"] = "off"

    proc = subprocess.run(
        ["bash", str(RECON_ENGINE), "example.com", "--quick"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60, env=env,
    )
    assert proc.returncode == 0, f"stdout={proc.stdout[-3000:]}"
    assert "Phase 5.5: Incremental Re-Recon" in proc.stdout
    assert "requires --domain to send any request, skipping" in proc.stdout


def test_no_new_hosts_reports_cleanly_and_pipeline_continues(base_env, tmp_path):
    recon_dir = tmp_path / "recon-out"
    (recon_dir / "subdomains").mkdir(parents=True)
    (recon_dir / "subdomains" / "seed.txt").write_text("example.com\n")
    env = dict(base_env)
    env["RECON_OUT_DIR"] = str(recon_dir)
    env["BB_SCOPE_DOMAINS"] = "example.com,*.example.com"

    proc = subprocess.run(
        ["bash", str(RECON_ENGINE), "example.com", "--quick"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60, env=env,
    )
    assert proc.returncode == 0, f"stdout={proc.stdout[-3000:]}"
    assert "No new in-scope hosts found" in proc.stdout
    assert "Phase 6: Directory Fuzzing" in proc.stdout, "pipeline must continue past Phase 5.5 regardless"
