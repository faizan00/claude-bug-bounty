"""
End-to-end regression tests for tools/recon_engine.sh's Phase 1.5 scope gate.

Before this hardening pass, no test executed recon_engine.sh itself with a
mix of in-scope/out-of-scope hosts and asserted the filter actually gated
later phases -- every existing scope test only unit-tested scope_checker.py
in isolation. Two real bugs lived in that untested integration seam:

1. Fail-open: a scope_checker.py crash (e.g. a non-UTF-8 byte in a
   crt.sh/wayback-derived hostname -- realistic, not contrived) logged an
   error and fell through to Phase 2+ with the UNFILTERED host list.
2. Phase 3's nmap call scanned the raw $TARGET string directly, completely
   bypassing the Phase 1.5 filter -- an out-of-scope host (or a program
   scoping only *.target.com, apex excluded) still got port-scanned.

Both tests below actually execute the real script as a subprocess (not a
source-text grep) against a stub PATH so there are zero live network calls
or dependencies on which security tools happen to be installed (mirrors
the pattern already established in tests/test_tool_contracts.py).
"""

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
    # Belt-and-suspenders: route any escaped HTTP call into a closed local
    # port rather than the real network.
    env["HTTP_PROXY"] = "http://127.0.0.1:1"
    env["HTTPS_PROXY"] = "http://127.0.0.1:1"
    # Isolate hunt-memory writes from the real repo. Phase 2.6
    # (fingerprint.py, wired in after this fixture was first written) now
    # runs unconditionally on every recon_engine.sh invocation and syncs
    # tech_stack into hunt-memory/targets/ -- without this override every
    # test in this file was silently writing recon/hunt-memory/targets/
    # example.com.json and testscopeguard.invalid.json into THIS repo's
    # own hunt-memory/ on every test run (found and fixed alongside
    # tools/incremental_recon.py's own Phase 5.5 wiring tests).
    env["HUNT_MEMORY_OUT_DIR"] = str(tmp_path / "hunt-memory")
    return env


def test_scope_checker_failure_aborts_instead_of_scanning_unfiltered(base_env, tmp_path):
    recon_dir = tmp_path / "recon-out"
    (recon_dir / "subdomains").mkdir(parents=True)
    # A non-UTF-8 byte is a realistic crt.sh/wayback artifact, not a
    # contrived edge case -- this is what actually crashed scope_checker.py.
    (recon_dir / "subdomains" / "seed.txt").write_bytes(
        b"good.example.com\n\xff\xfeinvalidbyte.example.com\n"
    )
    env = dict(base_env)
    env["RECON_OUT_DIR"] = str(recon_dir)

    proc = subprocess.run(
        ["bash", str(RECON_ENGINE), "example.com", "--quick"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60, env=env,
    )

    assert proc.returncode != 0, (
        "recon_engine.sh must abort when scope_checker.py fails, not fall "
        f"through to Phase 2 with an unfiltered host list.\nstdout={proc.stdout[-2000:]}"
    )
    assert "aborting rather than probing an unfiltered host list" in proc.stdout
    # The strongest proof it actually stopped: Phase 2 (httpx) never ran, so
    # live/urls.txt was never created.
    assert not (recon_dir / "live" / "urls.txt").exists()


def test_nmap_scans_the_scope_filtered_list_not_the_raw_target(base_env, tmp_path):
    recon_dir = tmp_path / "recon-out"
    (recon_dir / "subdomains").mkdir(parents=True)
    (recon_dir / "subdomains" / "seed.txt").write_text(
        "good.testscopeguard.invalid\nevil-unrelated.com\n"
    )

    nmap_argv_log = tmp_path / "nmap_argv.log"
    nmap_stub = tmp_path / "stub-bin" / "nmap"
    nmap_stub.write_text(
        "#!/bin/sh\n"
        f'echo "$@" >> "{nmap_argv_log}"\n'
        "exit 0\n"
    )
    nmap_stub.chmod(nmap_stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    env = dict(base_env)
    env["RECON_OUT_DIR"] = str(recon_dir)

    proc = subprocess.run(
        ["bash", str(RECON_ENGINE), "testscopeguard.invalid", "--quick"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60, env=env,
    )
    assert proc.returncode == 0, f"stdout={proc.stdout[-2000:]}\nstderr={proc.stderr[-2000:]}"

    all_txt = (recon_dir / "subdomains" / "all.txt").read_text()
    assert "good.testscopeguard.invalid" in all_txt
    assert "evil-unrelated.com" not in all_txt, "Phase 1.5 should have filtered this out"

    assert nmap_argv_log.exists(), "nmap was never invoked"
    nmap_invocation = nmap_argv_log.read_text()
    assert "-iL" in nmap_invocation, (
        "nmap must scan the scope-filtered host LIST (-iL), not the raw target string"
    )
    assert str(recon_dir / "subdomains" / "all.txt") in nmap_invocation
    assert "evil-unrelated.com" not in nmap_invocation
    assert "testscopeguard.invalid " not in nmap_invocation and not nmap_invocation.strip().endswith(
        "testscopeguard.invalid"
    ), "nmap must not be invoked against the raw $TARGET string directly"


def test_browser_recon_phase_is_opt_in_and_off_by_default(base_env, tmp_path):
    recon_dir = tmp_path / "recon-out"
    env = dict(base_env)
    env["RECON_OUT_DIR"] = str(recon_dir)
    env.pop("BB_BROWSER_RECON", None)

    proc = subprocess.run(
        ["bash", str(RECON_ENGINE), "example.com", "--quick"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60, env=env,
    )
    assert proc.returncode == 0, f"stdout={proc.stdout[-2000:]}"
    assert "Phase 2.5" not in proc.stdout
    assert not (recon_dir / "browser").exists()


def test_browser_recon_phase_skips_gracefully_with_no_live_hosts(base_env, tmp_path):
    # httpx is stubbed to fail in base_env, so Phase 2 never produces
    # live/urls.txt -- Phase 2.5 must skip cleanly (fast, no browser launch)
    # rather than crash or hang.
    recon_dir = tmp_path / "recon-out"
    env = dict(base_env)
    env["RECON_OUT_DIR"] = str(recon_dir)
    env["BB_BROWSER_RECON"] = "1"

    proc = subprocess.run(
        ["bash", str(RECON_ENGINE), "example.com", "--quick"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60, env=env,
    )
    assert proc.returncode == 0, f"stdout={proc.stdout[-2000:]}"
    assert "Phase 2.5: Browser Intelligence" in proc.stdout
    assert "No live hosts from Phase 2 — skipping browser intelligence" in proc.stdout
    assert not (recon_dir / "browser").exists()
