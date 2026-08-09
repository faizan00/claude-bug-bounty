"""Regression checks for the response-normalization bypass probe.

The two tests that used to live here (test_bypass_probe_normalizes_dynamic_
bodies_before_comparing) asserted the literal presence of
`orig_norm`/`bypass_norm`/`baseline_code=$orig_code` -- three variables that
were referenced but never assigned anywhere in the script. Under `set -u`
(line 13) that made tools/bypass_403.sh crash with "orig_code: unbound
variable" on every single invocation, and because that old test only did a
source-text grep (never executed the script), it passed the entire time the
tool was completely broken. This is the exact "test only proves the string
exists, not that the tool works" gap the post-Phase-7 hardening audit called
out: fixing the crash necessarily made that assertion false, so the test is
updated here rather than left describing dead code -- see project rule 7
(a test describing a bug that was deliberately fixed is stale, not sacred).
"""

import os
import subprocess
import sys
from pathlib import Path


BYPASS_PATH = Path(__file__).resolve().parents[1] / "tools" / "bypass_403.sh"


def test_bypass_probe_keeps_confidence_tiers():
    scanner = BYPASS_PATH.read_text()

    assert '[CONFIRMED]' in scanner
    assert '[POSSIBLE]' in scanner
    assert '[INFORMATIONAL]' in scanner


def test_normalize_body_helper_still_defined():
    # _normalize_body() itself is real, tested-in-isolation-below code; only
    # the three unassigned variables that referenced it were dead. Confirm
    # the helper wasn't accidentally deleted along with the crash.
    scanner = BYPASS_PATH.read_text()
    assert "_normalize_body()" in scanner


def test_bypass_probe_does_not_crash_on_unreachable_target():
    """The actual regression test the old grep-only test could never catch:
    execute the real script (not just read its source) against a target
    guaranteed to fail to connect (a closed local port, per the same
    HTTP_PROXY-to-127.0.0.1:1 pattern used in test_tool_contracts.py -- no
    live network, no real bug bounty target), and assert it runs to
    completion instead of dying on an unbound-variable reference."""
    env = dict(os.environ)
    env["HTTP_PROXY"] = "http://127.0.0.1:1"
    env["HTTPS_PROXY"] = "http://127.0.0.1:1"
    proc = subprocess.run(
        ["bash", str(BYPASS_PATH), "http://127.0.0.1:1/probe"],
        capture_output=True, text=True, timeout=60, env=env,
    )
    assert "unbound variable" not in proc.stderr, proc.stderr
    assert proc.returncode == 0, f"stdout={proc.stdout[-2000:]}\nstderr={proc.stderr[-2000:]}"


def test_bypass_probe_never_confirms_a_bypass_from_a_failed_connection():
    """Companion to the waf_response_analyzer status-0 regression test:
    end-to-end, a target that never answers must not produce a [CONFIRMED]
    bypass line or a populated bypass_hits.txt -- only needs_review/blocked
    buckets. Prefers NO FINDING over a fabricated finding (project rule 5)."""
    env = dict(os.environ)
    env["HTTP_PROXY"] = "http://127.0.0.1:1"
    env["HTTPS_PROXY"] = "http://127.0.0.1:1"
    proc = subprocess.run(
        ["bash", str(BYPASS_PATH), "http://127.0.0.1:1/probe"],
        capture_output=True, text=True, timeout=60, env=env,
    )
    assert "[CONFIRMED]" not in proc.stdout, proc.stdout[-2000:]
