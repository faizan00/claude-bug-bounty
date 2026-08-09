"""
End-to-end wiring test for tools/recon_engine.sh -> tools/fingerprint.py.

Before this change, tools/fingerprint.py (700+ lines: framework/infra/
API-style/SPA detection, CVE matching against tech_attack_matrix.json) had
zero callers anywhere -- not in recon_engine.sh, not in any agents/*.md or
commands/*.md. tools/director.py's build_plan() only picks up any of its
signal if recon/<target>/fingerprint.json already exists
(load_fingerprint_tech_attack_matrix()'s own docstring says as much), and
sync_tech_stack() is the only path that ever populates hunt-memory's
tech_stack profile from real recon signal -- so every real hunt silently
got zero tech-stack-aware scoring unless the hunter remembered to manually
run `python3 tools/fingerprint.py` themselves, which nothing ever told
them to do. Same "IMPLEMENTED != REACHABLE" shape as the browser_recon.py
wiring gap fixed earlier (tests/test_browser_recon_pipeline_wiring.py).

This test proves the wiring is real: runs the actual recon_engine.sh CLI
(subprocess, not a reimplementation) with stubbed external tools (no live
network), pre-seeds a realistic live/httpx_full.txt the way a real Phase 2
run would produce one, and asserts (a) fingerprint.json is written with a
real (non-"unknown") framework detected from it, (b) hunt-memory's
tech_stack profile gets synced, and (c) none of this touches the real
repo's hunt-memory/ directory -- HUNT_MEMORY_OUT_DIR (mirroring
RECON_OUT_DIR's existing override convention) must isolate it.
"""

import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
RECON_ENGINE = REPO_ROOT / "tools" / "recon_engine.sh"

_STUBBED_BINARIES = [
    "subfinder", "amass", "httpx", "katana", "ffuf", "nuclei", "dig",
    "curl", "gau", "waybackurls", "dnsx", "sisakulint", "trufflehog",
    "gitleaks", "arjun",
]


@pytest.fixture()
def stub_bin_dir(tmp_path):
    d = tmp_path / "stub-bin"
    d.mkdir()
    for name in _STUBBED_BINARIES:
        stub = d / name
        stub.write_text("#!/bin/sh\nexit 1\n")
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return d


@pytest.fixture()
def base_env(stub_bin_dir, tmp_path):
    env = dict(os.environ)
    env["PATH"] = str(stub_bin_dir) + os.pathsep + env.get("PATH", "")
    env["HTTP_PROXY"] = "http://127.0.0.1:1"
    env["HTTPS_PROXY"] = "http://127.0.0.1:1"
    # Isolate hunt-memory writes from the real repo -- mirrors RECON_OUT_DIR's
    # existing override, without which fingerprint.py's sync_tech_stack()
    # would write into this repo's own hunt-memory/targets/ on every test run.
    env["HUNT_MEMORY_OUT_DIR"] = str(tmp_path / "hunt-memory")
    return env


def test_fingerprint_phase_runs_and_writes_output(base_env, tmp_path):
    recon_dir = tmp_path / "recon-out"
    env = dict(base_env)
    env["RECON_OUT_DIR"] = str(recon_dir)

    proc = subprocess.run(
        ["bash", str(RECON_ENGINE), "example.com", "--quick"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60, env=env,
    )
    assert proc.returncode == 0, f"stdout={proc.stdout[-3000:]}\nstderr={proc.stderr[-2000:]}"
    assert "Phase 2.6: Technology Fingerprinting" in proc.stdout
    assert (recon_dir / "fingerprint.json").exists()


def test_real_framework_signal_is_detected_from_httpx_output(base_env, tmp_path):
    """Pre-seed live/httpx_full.txt the way a real Phase 2 httpx run would
    have produced one (httpx is stubbed to fail here, so this proves Phase
    2.6 reads whatever Phase 2 already wrote, not that httpx itself ran)."""
    recon_dir = tmp_path / "recon-out"
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "live" / "httpx_full.txt").write_text(
        "https://example.com [200] [WordPress] [nginx]\n"
    )
    env = dict(base_env)
    env["RECON_OUT_DIR"] = str(recon_dir)

    proc = subprocess.run(
        ["bash", str(RECON_ENGINE), "example.com", "--quick"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60, env=env,
    )
    assert proc.returncode == 0, f"stdout={proc.stdout[-3000:]}\nstderr={proc.stderr[-2000:]}"
    assert "framework=wordpress" in proc.stdout, f"stdout={proc.stdout[-3000:]}"

    fingerprint = json.loads((recon_dir / "fingerprint.json").read_text())
    assert fingerprint["framework"] == "wordpress"


def test_hunt_memory_tech_stack_is_synced_and_isolated_from_real_repo(base_env, tmp_path):
    recon_dir = tmp_path / "recon-out"
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "live" / "httpx_full.txt").write_text(
        "https://example.com [200] [Django]\n"
    )
    memory_dir = tmp_path / "hunt-memory"
    env = dict(base_env)
    env["RECON_OUT_DIR"] = str(recon_dir)
    env["HUNT_MEMORY_OUT_DIR"] = str(memory_dir)

    real_repo_hunt_memory = REPO_ROOT / "hunt-memory" / "targets" / "example.com.json"
    existed_before = real_repo_hunt_memory.exists()

    proc = subprocess.run(
        ["bash", str(RECON_ENGINE), "example.com", "--quick"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60, env=env,
    )
    assert proc.returncode == 0, f"stdout={proc.stdout[-3000:]}"

    profile_path = memory_dir / "targets" / "example.com.json"
    assert profile_path.exists()
    profile = json.loads(profile_path.read_text())
    assert "django" in profile["tech_stack"]

    # The real repo's own hunt-memory must be completely untouched.
    assert real_repo_hunt_memory.exists() == existed_before


def test_pipeline_continues_past_phase_2_6_regardless(base_env, tmp_path):
    """Phase 2.6 must never gate Phase 3+ -- content check that it follows
    the exact same `if python3 ...; then ... else log_warn (non-fatal) ...
    fi` shape every other optional phase in this script already uses
    (Phase 2.5's browser_recon.py call is the precedent), plus a real run
    proving Phase 3 actually executes afterward."""
    src = RECON_ENGINE.read_text()
    phase_26 = src[src.index("Phase 2.6: Technology Fingerprinting"):src.index("Phase 3: Port Scanning")]
    assert "log_warn" in phase_26 and "non-fatal" in phase_26

    recon_dir = tmp_path / "recon-out"
    env = dict(base_env)
    env["RECON_OUT_DIR"] = str(recon_dir)
    proc = subprocess.run(
        ["bash", str(RECON_ENGINE), "example.com", "--quick"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60, env=env,
    )
    assert proc.returncode == 0
    assert "Phase 3: Port Scanning" in proc.stdout
