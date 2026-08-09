"""
End-to-end wiring test for tools/browser_recon.py -> tools/director.py.

Before this hardening pass, tools/browser_recon.py (1,445 lines: source-map
recovery, framework route extraction, client-side auth-model analysis,
hidden-endpoint discovery) was never invoked by anything in the pipeline
-- recon_engine.sh, every commands/*.md, and every agents/*.md all had zero
references to it. tools/director.py's browser_intel_leads() correctly reads
recon/<target>/browser/{routes,auth-model,api-calls,never-called}.json, but
those files never existed on a real hunt, so that consumer always silently
degraded to []. The fix: recon_engine.sh now has an opt-in Phase 2.5
(BB_BROWSER_RECON=1) that actually runs browser_recon.py.

This test proves the wiring is real, not just plausible: it runs the actual
browser_recon.py CLI (subprocess, not a reimplementation) against a real,
local, in-process demo/app.py instance -- per this project's own testing
rule, no test may touch the live network -- and then feeds the real output
files into director.py's real browser_intel_leads() function, asserting the
schema keys line up and nothing crashes. This is the exact "does the
consumer actually understand what the producer emits" question the
post-Phase-7 audit flagged as unverified.
"""

import http.server
import importlib.util
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BROWSER_RECON = os.path.join(REPO_ROOT, "tools", "browser_recon.py")

for _p in (REPO_ROOT,):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from tools import director  # noqa: E402

TARGET = "demo.local"


@pytest.fixture(scope="module")
def demo_app():
    """Same fixture pattern as tests/test_e2e_hunt_loop.py's demo_app:
    a real, in-process demo/app.py instance bound to "localhost" (not a
    raw IP literal, which tools/scope_checker.py deliberately refuses to
    treat as in-scope)."""
    os.environ["APP_HOST"] = "localhost"
    spec = importlib.util.spec_from_file_location(
        "browser_recon_wiring_demo_app", os.path.join(REPO_ROOT, "demo", "app.py")
    )
    demo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(demo)
    assert demo.HOST == "localhost"

    httpd = http.server.ThreadingHTTPServer((demo.HOST, 0), demo.DemoHandler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://{demo.HOST}:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_browser_recon_output_is_real_and_director_consumes_it_without_error(demo_app, tmp_path):
    recon_dir = tmp_path / "recon" / TARGET
    recon_dir.mkdir(parents=True)

    proc = subprocess.run(
        [
            sys.executable, BROWSER_RECON, TARGET,
            "--recon-dir", str(recon_dir),
            "--domain", "localhost",
            "--source-maps", "--hidden-endpoints", "--route-extraction",
            "--auth-model", "--api-capture",
            "--entry-url", demo_app,
            "--max-pages", "3",
            "--page-timeout", "10",
        ],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, f"stdout={proc.stdout}\nstderr={proc.stderr}"

    browser_dir = recon_dir / "browser"
    expected_files = {"routes.json", "auth-model.json", "api-calls.json", "never-called.json"}
    actual_files = {p.name for p in browser_dir.glob("*.json")}
    assert expected_files <= actual_files, (
        f"browser_recon.py did not write all files director.py expects: "
        f"missing {expected_files - actual_files}"
    )

    # Schema check: the exact keys director.py's browser_intel_leads() reads.
    never_called = json.loads((browser_dir / "never-called.json").read_text())
    assert "never_called" in never_called

    routes = json.loads((browser_dir / "routes.json").read_text())
    assert "routes" in routes

    auth_model = json.loads((browser_dir / "auth-model.json").read_text())
    assert "candidate_privileged_client_routes" in auth_model

    # The actual consumer: director.py's real function, not a reimplementation.
    leads = director.browser_intel_leads(TARGET, str(recon_dir))
    assert isinstance(leads, list)
    for lead in leads:
        assert "skill" in lead
        assert "id" in lead


def test_browser_intel_leads_is_empty_not_crashing_when_phase_never_ran():
    # Cold-start / phase-skipped case: director.py must degrade to [] rather
    # than raise, exactly as before this wiring existed.
    leads = director.browser_intel_leads(TARGET, "/nonexistent/recon/dir")
    assert leads == []
