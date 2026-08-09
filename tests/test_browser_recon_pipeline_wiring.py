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


def test_api_capture_feeds_object_model_across_two_accounts(demo_app, tmp_path):
    """memory/api_call_observer.py's observe_from_api_calls() was built and
    tested in isolation (tests/test_api_call_observer.py) but, before this
    hardening pass, nothing in the live pipeline ever called it -- so
    memory/object_model/<target>.jsonl (which tools/director.py's
    object_model_leads() reads) always stayed empty on a real hunt.

    This proves the full, real, two-account wiring end to end: run the
    actual browser_recon.py CLI --api-capture twice against the SAME
    recon-dir under two different --bearer tokens (the real workflow a
    hunter follows with two test accounts for IDOR testing), and confirm
    (1) api-calls.json accumulates both runs' calls rather than the second
    overwriting the first, and (2) a real cross-actor Observation lands in
    memory/object_model/<target>.jsonl as a direct result -- no
    reimplementation, the actual CLI subprocess and the actual on-disk
    files both runs.
    """
    target = "demo-two-account.local"
    recon_dir = tmp_path / "recon" / target
    recon_dir.mkdir(parents=True)
    memory_dir = tmp_path / "hunt-memory"

    def run_capture(bearer_token):
        return subprocess.run(
            [
                sys.executable, BROWSER_RECON, target,
                "--recon-dir", str(recon_dir),
                "--memory-dir", str(memory_dir),
                "--domain", "localhost",
                "--api-capture",
                "--entry-url", demo_app + "/",
                "--max-pages", "1",
                "--page-timeout", "10",
                "--bearer", bearer_token,
            ],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=60,
        )

    proc_a = run_capture("account-a-token")
    assert proc_a.returncode == 0, f"stdout={proc_a.stdout}\nstderr={proc_a.stderr}"
    proc_b = run_capture("account-b-token")
    assert proc_b.returncode == 0, f"stdout={proc_b.stdout}\nstderr={proc_b.stderr}"

    api_calls = json.loads((recon_dir / "browser" / "api-calls.json").read_text())
    root_hits = [c for c in api_calls["calls"] if c["url"].rstrip("/") == demo_app]
    fingerprints = {
        tuple(sorted(c["request_headers_auth_fingerprint"].items()))
        for c in root_hits if c.get("request_headers_auth_fingerprint")
    }
    assert len(fingerprints) == 2, (
        "expected both accounts' captures to survive in api-calls.json -- "
        f"got {len(root_hits)} hit(s) with {len(fingerprints)} distinct auth fingerprint(s), "
        "account B's run may have overwritten account A's"
    )

    observations_path = memory_dir / "object_model" / f"{target}.jsonl"
    assert observations_path.exists(), "browser_recon.py --api-capture did not call observe_from_api_calls()"
    observations = [json.loads(ln) for ln in observations_path.read_text().splitlines() if ln.strip()]
    assert len(observations) >= 2, (
        f"expected an 'accessed' observation per actor for the shared URL, got {len(observations)}"
    )
    assert {o["event"] for o in observations} == {"accessed"}

    # And the consumer side still doesn't crash reading it (no relationship-
    # establishing event exists yet in this test, so leads == [] is the
    # correct, conservative-by-design outcome -- this asserts "doesn't
    # crash", not "produces a lead here").
    leads = director.object_model_leads(target, str(memory_dir))
    assert leads == []
