"""Real end-to-end tests for tools/hunt.py's run_watched() -- no mocks, real
bash subprocesses and real signals, since the whole point of this helper is
its interaction with a *real* process group and a *real* trap.

Background (hardening audit, 2026-08-09): the old pattern in run_recon()/
run_vuln_scan()/run_zero_day_fuzzer() was `proc.wait(timeout=T)` then
`proc.kill()` on timeout. That's SIGKILL, which:

  1. cannot be trapped, so recon_engine.sh's `trap _emergency_merge_subs
     EXIT` (which exists specifically to save partial subdomain results on
     a watchdog kill) never fires on the one path it was written for; and
  2. only signals the direct child PID, not any process group -- tools the
     bash script already forked (nmap/curl/subfinder) are not killed and
     can keep sending traffic to the target after the watchdog "stopped"
     the hunt.

run_watched() fixes both: launch in a new session (own process group), and
on timeout send SIGTERM to the whole group first (giving `grace` seconds for
a trap to run and children to exit cleanly) before escalating to SIGKILL.
"""

import os
import signal
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import hunt  # noqa: E402


def test_run_watched_returns_promptly_on_normal_exit():
    rc, timed_out = hunt.run_watched(["true"], timeout=5)
    assert rc == 0
    assert timed_out is False


def test_run_watched_reports_nonzero_exit():
    rc, timed_out = hunt.run_watched(["false"], timeout=5)
    assert rc == 1
    assert timed_out is False


def test_sigterm_lets_exit_trap_run_before_escalating(tmp_path):
    """The core regression: a script whose only cleanup path is an EXIT
    trap must get the chance to run it. proc.kill() (SIGKILL) would never
    let this marker file get written; run_watched()'s SIGTERM-first stage
    must."""
    marker = tmp_path / "cleanup_ran"
    script = tmp_path / "trapper.sh"
    script.write_text(
        f"#!/bin/bash\n"
        f"trap 'touch {marker}' EXIT\n"
        f"sleep 30\n"
    )
    script.chmod(0o755)

    start = time.monotonic()
    rc, timed_out = hunt.run_watched(["bash", str(script)], timeout=1, grace=5)
    elapsed = time.monotonic() - start

    assert timed_out is True
    assert marker.exists(), "EXIT trap did not run -- watchdog used an untrappable kill"
    # Should resolve within the grace window, nowhere near the script's own
    # 30s sleep -- proves SIGTERM actually interrupted it rather than the
    # test just waiting out the full sleep.
    assert elapsed < 10, f"took {elapsed:.1f}s -- SIGTERM did not reach the process promptly"


def test_forked_child_is_reaped_via_process_group(tmp_path):
    """A child forked by the watched script (simulating nmap/subfinder
    already running when the watchdog fires) must not survive -- proves the
    kill targets the whole process group, not just the direct PID."""
    child_pid_file = tmp_path / "child.pid"
    script = tmp_path / "forker.sh"
    # The child traps SIGTERM away so only the SIGKILL escalation stage can
    # actually remove it -- proves both stages of run_watched are reachable
    # and effective, not just SIGTERM.
    script.write_text(
        f"#!/bin/bash\n"
        f"(trap '' TERM; echo $$ > {child_pid_file}; sleep 60) &\n"
        f"wait\n"
    )
    script.chmod(0o755)

    rc, timed_out = hunt.run_watched(["bash", str(script)], timeout=1, grace=2)
    assert timed_out is True

    # Give the reaper a brief moment, then confirm the forked child is gone.
    deadline = time.monotonic() + 5
    child_pid = None
    while time.monotonic() < deadline:
        if child_pid_file.exists():
            child_pid = int(child_pid_file.read_text().strip())
            break
        time.sleep(0.1)
    assert child_pid is not None, "forked child never started"

    alive = True
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            alive = False
            break
        time.sleep(0.1)
    assert not alive, f"forked child pid {child_pid} survived run_watched()'s kill"


def test_run_watched_uses_new_session_not_caller_group():
    """Guards against a regression back to plain subprocess.Popen(argv) with
    no start_new_session -- without it, a SIGTERM sent to the child's group
    would also hit the test runner's own group."""
    # A child that reports whether its pgid differs from its ppid's pgid.
    rc, timed_out = hunt.run_watched(
        ["bash", "-c", "[ $(ps -o pgid= -p $$) != $(ps -o pgid= -p $PPID) ]"],
        timeout=5,
    )
    assert timed_out is False
    assert rc == 0, "child was not placed in its own process group"
