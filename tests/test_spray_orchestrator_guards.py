"""
Regression tests for tools/spray_orchestrator.sh's safety guards.

Guards three findings, two from the post-Phase-7 hardening audit and one
from the follow-up hardening pass that made scope enforcement fail CLOSED:

1. The "human-in-the-loop" hostname/lockout confirmations were plain
   `read -r -p` with no TTY check. Since an automated caller (an agent's
   Bash tool, a CI step) runs commands with fully agent-controlled stdin,
   `printf 'target.com\\nyes\\n' | spray_orchestrator.sh ...` silently
   satisfied both guards -- no human ever confirmed anything. Fixed by
   refusing to proceed when stdin isn't a TTY unless --i-understand is
   passed explicitly.

2. A comment claimed tools/scope_checker.py "has no enforcement CLI" (it
   does -- a real argparse CLI, exit code 2 on out-of-scope) as the reason
   this, the highest-risk tool in the repo, performed zero automated scope
   check. Fixed by wiring the same _scope_gate_asset helper cve_scan.sh/
   takeover_scanner.sh/cloud_recon.sh now use.

3. _scope_gate_asset itself used to warn-and-allow when BB_SCOPE_DOMAINS was
   unset, so #2's fix was opt-in in practice -- spray_orchestrator.sh (and
   every other tool sharing the helper) ran unenforced out of the box unless
   an operator remembered to export BB_SCOPE_DOMAINS first. Fixed by making
   the helper fail CLOSED (deny) when BB_SCOPE_DOMAINS is unset.

No live network calls: TARGET_URL points at a hostname under the RFC 2606
reserved .invalid TLD (never resolvable to a real system) and HTTP_PROXY/
HTTPS_PROXY route to a closed local port as a second layer, but neither
matters in practice -- the script exits at the scope/confirmation gate
stage before ever reaching the actual HTTP dispatch code (project rule 8/9).

scope_checker.py has a documented, separate limitation that IP addresses are
never considered in-scope (see tools/scope_checker.py's module docstring) --
using an IP literal as the test target would make every scope-gated test
here fail regardless of BB_SCOPE_DOMAINS, for a reason unrelated to what
each test actually verifies. A domain literal avoids that entirely.
"""

import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SPRAY = REPO_ROOT / "tools" / "spray_orchestrator.sh"

TARGET_HOST = "spray-test.invalid"
TARGET_URL = f"https://{TARGET_HOST}:1"
IN_SCOPE_DOMAINS = TARGET_HOST


def _write_lists(tmp_path):
    users = tmp_path / "users.txt"
    passes = tmp_path / "passes.txt"
    users.write_text("user1\nuser2\n")
    passes.write_text("pass1\n")
    return users, passes


def _run(args, tmp_path, stdin_text=None, env_extra=None, include_scope_domains=True):
    users, passes = _write_lists(tmp_path)
    env = dict(os.environ)
    env["HTTP_PROXY"] = "http://127.0.0.1:1"
    env["HTTPS_PROXY"] = "http://127.0.0.1:1"
    if include_scope_domains:
        env["BB_SCOPE_DOMAINS"] = IN_SCOPE_DOMAINS
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["bash", str(SPRAY), TARGET_URL, "--mode", "http-form",
         "--users", str(users), "--passes", str(passes)] + args,
        # cwd=tmp_path, not REPO_ROOT: the script writes its audit log to a
        # cwd-relative recon/<host>/spray/ dir, and --i-understand runs here
        # deliberately clear both confirmation guards -- must not leak a
        # real recon/ directory into the actual repo checkout.
        cwd=tmp_path, capture_output=True, text=True, timeout=20, env=env,
        input=stdin_text,
    )


class TestPipedStdinCannotSatisfyHumanConfirmation:
    def test_piped_hostname_and_yes_are_rejected_not_accepted(self, tmp_path):
        # This is exactly the bypass the audit found: an agent (or any
        # non-interactive caller) piping the "correct" answers in used to
        # sail straight through both guards with no human ever involved.
        proc = _run([], tmp_path, stdin_text=f"{TARGET_HOST}\nyes\n")
        assert proc.returncode == 2, f"stdout={proc.stdout}\nstderr={proc.stderr}"
        assert "not a TTY" in proc.stdout or "not a TTY" in proc.stderr

    def test_dry_run_still_works_non_interactively(self, tmp_path):
        # --dry-run must not be broken by the new TTY gate -- it never
        # dispatches a real request, so it's always safe non-interactively.
        # BB_SCOPE_DOMAINS must still be declared -- the scope gate now fires
        # fail-closed before --dry-run is even checked (declaring scope is
        # required regardless of whether the run is real or a dry run).
        proc = _run(["--dry-run"], tmp_path, stdin_text="")
        assert proc.returncode == 0, f"stdout={proc.stdout}\nstderr={proc.stderr}"
        assert "would dispatch" in proc.stdout

    def test_i_understand_bypasses_the_tty_gate_explicitly(self, tmp_path):
        # A deliberate, explicit --i-understand (not a piped answer) is a
        # legitimate way to run non-interactively after a human has already
        # confirmed scope/lockout risk out of band.
        proc = _run(["--i-understand"], tmp_path, stdin_text="")
        assert "not a TTY" not in proc.stdout


class TestScopeGateIsReal:
    def test_out_of_scope_host_aborts_even_with_i_understand(self, tmp_path):
        # The scope gate is independent of the human-confirmation guards --
        # --i-understand bypasses the confirmation prompts, not scope
        # enforcement. BB_SCOPE_DOMAINS is set here, but to a domain that
        # genuinely doesn't match TARGET_HOST -- a real mismatch, not a
        # vacuous pass/fail from the IP-address limitation.
        proc = _run(
            ["--i-understand"], tmp_path, stdin_text="",
            env_extra={"BB_SCOPE_DOMAINS": "*.example.com,example.com"},
        )
        assert proc.returncode == 1, f"stdout={proc.stdout}\nstderr={proc.stderr}"
        assert "OUT OF SCOPE" in proc.stderr
        # Proof it stopped before ever reaching dispatch: no audit log dir.
        assert not (tmp_path / "recon" / TARGET_HOST / "spray").exists()

    def test_unset_scope_domains_fails_closed_by_default(self, tmp_path):
        # Locks in the fail-closed fix: BB_SCOPE_DOMAINS entirely unset must
        # refuse to run (deny), not warn-and-proceed like the prior default.
        proc = _run(
            ["--i-understand"], tmp_path, stdin_text="",
            include_scope_domains=False,
        )
        assert proc.returncode == 1, f"stdout={proc.stdout}\nstderr={proc.stderr}"
        assert "BB_SCOPE_DOMAINS not set" in proc.stderr
        assert not (tmp_path / "recon" / TARGET_HOST / "spray").exists()

    def test_scope_checker_is_actually_invoked_not_just_commented_about(self):
        content = SPRAY.read_text()
        assert "_scope_gate_asset" in content
        assert "no enforcement CLI" not in content, (
            "the false claim that scope_checker.py has no enforcement CLI "
            "should have been removed along with the fix"
        )
