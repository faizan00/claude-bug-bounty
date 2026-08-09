"""Real end-to-end tests for the crash-vs-genuinely-empty distinction added
to tools/recon_engine.sh and tools/vuln_scanner.sh (hardening audit finding:
nearly every tool invocation discarded its exit code via `|| true`, so a
crashed/rate-limited/misconfigured tool and a tool that ran fine and found
nothing both logged identically as "0 findings"/"0 subdomains" -- a hunt
could silently conclude a target has no attack surface when a tool actually
never ran).

Same real-subprocess-against-a-stub-PATH pattern already established in
tests/test_recon_engine_scope_e2e.py -- no live network calls, no
dependency on which security tools happen to be installed on the host
running the test.
"""

import os
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
RECON_ENGINE = REPO_ROOT / "tools" / "recon_engine.sh"
VULN_SCANNER = REPO_ROOT / "tools" / "vuln_scanner.sh"

_CRASHING_BINARIES = [
    "subfinder", "amass", "httpx", "katana", "nuclei", "curl", "gau",
    "dig", "sisakulint",
]


def _make_stub(d: Path, name: str, script: str):
    stub = d / name
    stub.write_text(script)
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return stub


@pytest.fixture()
def crashing_stub_bin_dir(tmp_path):
    """Every stubbed tool exits 1 with no output -- simulates every real
    tool invocation crashing/timing out/being misconfigured, the exact
    scenario that used to be silently indistinguishable from "target has no
    attack surface."""
    d = tmp_path / "stub-bin"
    d.mkdir()
    for name in _CRASHING_BINARIES:
        _make_stub(d, name, "#!/bin/sh\nexit 1\n")
    # recon_engine.sh's _resolve_pd_httpx() only trusts a binary that
    # answers `-version` with "projectdiscovery" -- otherwise it falls back
    # to the bare string "httpx" (not a resolvable path), and Phase 2's own
    # `[ -x "$HTTPX_BIN" ]` gate skips the whole phase before ever invoking
    # it. Answer -version so the REAL probing call still reaches (and
    # crashes on) the stub.
    _make_stub(d, "httpx", '#!/bin/sh\n[ "$1" = "-version" ] && echo "projectdiscovery httpx" && exit 0\nexit 1\n')
    return d


@pytest.fixture()
def crash_env(crashing_stub_bin_dir):
    env = dict(os.environ)
    env["PATH"] = str(crashing_stub_bin_dir) + os.pathsep + env.get("PATH", "")
    # Belt-and-suspenders: route any escaped HTTP call into a closed local
    # port rather than the real network.
    env["HTTP_PROXY"] = "http://127.0.0.1:1"
    env["HTTPS_PROXY"] = "http://127.0.0.1:1"
    return env


class TestReconEngineDistinguishesCrashFromEmpty:

    def test_every_instrumented_tool_warns_distinctly_on_crash(self, crash_env, tmp_path):
        """With every tool stubbed to exit 1 with zero output, the script
        must (a) never abort (no `set -e` in this script; a crash must not
        take down the whole recon run) and (b) print a distinct FAILED-run
        warning per tool, not just silently report "0 subdomains/URLs"."""
        recon_dir = tmp_path / "recon-out"
        env = dict(crash_env)
        env["RECON_OUT_DIR"] = str(recon_dir)

        proc = subprocess.run(
            ["bash", str(RECON_ENGINE), "example.com"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=90, env=env,
        )
        assert proc.returncode == 0, (
            "a crashing tool must not abort the recon run\n"
            f"stdout={proc.stdout[-3000:]}\nstderr={proc.stderr[-2000:]}"
        )
        for label in ("subfinder", "amass", "crt.sh", "wayback (subdomains)", "gau"):
            assert f"{label} exited 1 with no output -- treating as a FAILED run" in proc.stdout, (
                f"missing FAILED-run warning for {label}\nstdout={proc.stdout[-3000:]}"
            )

    def test_genuinely_empty_result_does_not_warn(self, crash_env, tmp_path):
        """The other side of the same distinction: a tool that exits 0
        with no output ran fine and genuinely found nothing -- must NOT be
        flagged as a failure."""
        stub_dir = Path(crash_env["PATH"].split(os.pathsep)[0])
        _make_stub(stub_dir, "subfinder", "#!/bin/sh\nexit 0\n")

        recon_dir = tmp_path / "recon-out"
        env = dict(crash_env)
        env["RECON_OUT_DIR"] = str(recon_dir)

        proc = subprocess.run(
            ["bash", str(RECON_ENGINE), "example.com"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=90, env=env,
        )
        assert proc.returncode == 0, f"stdout={proc.stdout[-3000:]}"
        assert "subfinder exited" not in proc.stdout
        assert "subfinder: 0 subdomains" in proc.stdout  # still reports the count normally
        # A different, still-crashing tool must still warn -- confirms the
        # fixture isn't accidentally suppressing every warning.
        assert "amass exited 1 with no output -- treating as a FAILED run" in proc.stdout

    def test_httpx_crash_warns_when_a_host_list_exists(self, crash_env, tmp_path):
        """httpx feeding 'Live hosts: 0' is the single most consequential
        case (Phase 2 gates most of the rest of the pipeline) -- needs a
        pre-seeded host list so httpx's own `-s subdomains/all.txt` gate
        actually lets it run, same seeding technique as
        test_recon_engine_scope_e2e.py's nmap test."""
        recon_dir = tmp_path / "recon-out"
        (recon_dir / "subdomains").mkdir(parents=True)
        (recon_dir / "subdomains" / "seed.txt").write_text("good.example.com\n")
        env = dict(crash_env)
        env["RECON_OUT_DIR"] = str(recon_dir)

        proc = subprocess.run(
            ["bash", str(RECON_ENGINE), "example.com", "--quick"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=90, env=env,
        )
        assert proc.returncode == 0, f"stdout={proc.stdout[-3000:]}"
        assert "httpx exited 1 with no output -- treating as a FAILED run" in proc.stdout, (
            f"stdout={proc.stdout[-3000:]}"
        )

    def test_crtsh_and_wayback_use_bounded_curl(self):
        """The 3 unbounded curl calls (crt.sh, wayback-subs, wayback-urls-
        fallback) relied entirely on the script's own 3600s outer watchdog
        to ever recover -- content check that --max-time is actually set,
        not just claimed."""
        src = RECON_ENGINE.read_text()
        assert 'curl -s --max-time 30 "https://crt.sh' in src
        assert src.count('curl -s --max-time 30 "https://web.archive.org/cdx/search/cdx') == 2


class TestVulnScannerDistinguishesCrashFromEmpty:

    def test_nuclei_sqli_and_dalfox_use_log_tool_result(self):
        """Content check for the two batch-scanner call sites the audit
        specifically named (vuln_scanner.sh:260, 328-334) -- both must
        route through log_tool_result now, not a bare `|| true`."""
        src = VULN_SCANNER.read_text()
        assert 'log_tool_result $? "$FINDINGS_DIR/sqli/nuclei_sqli.txt" "nuclei (sqli)"' in src
        assert 'log_tool_result "${PIPESTATUS[1]}" "$FINDINGS_DIR/xss/dalfox_results.txt" "dalfox"' in src

    def test_dalfox_crash_warns_distinctly(self, tmp_path):
        stub_dir = tmp_path / "stub-bin"
        stub_dir.mkdir()
        _make_stub(stub_dir, "dalfox", "#!/bin/sh\nexit 1\n")

        # TARGET is basename(recon_dir) -- name it a real-looking domain so
        # both the scope gate and this fixture's BB_SCOPE_DOMAINS line up.
        recon_dir = tmp_path / "recon" / "example.com"
        findings_dir = tmp_path / "findings"
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "urls" / "with_params.txt").write_text("https://example.com/x?id=1\n")
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "live" / "urls.txt").write_text("https://example.com/x?id=1\n")

        env = dict(os.environ)
        env["PATH"] = str(stub_dir) + os.pathsep + env.get("PATH", "")
        env["BB_SCOPE_DOMAINS"] = "example.com"
        env["FINDINGS_OUT_DIR"] = str(findings_dir)
        # --skip everything except xss so only dalfox's own call site is
        # exercised -- keeps the run fast and the assertion unambiguous.
        skip_all_but_xss = ("lfi,ssti,ssrf,cors,takeover,misconfig,jwt,graphql,smuggling,redirects,"
                            "idor,auth_bypass,host_header,exposure,cloud,race,sqli,upload,cms,mfa,saml")

        proc = subprocess.run(
            ["bash", str(VULN_SCANNER), str(recon_dir), "--full", "--skip", skip_all_but_xss],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=60, env=env,
        )
        assert "dalfox exited 1 with no output -- treating as a FAILED run" in proc.stdout, (
            f"stdout={proc.stdout[-3000:]}\nstderr={proc.stderr[-2000:]}"
        )
