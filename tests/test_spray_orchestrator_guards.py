"""
Regression tests for tools/spray_orchestrator.sh's safety guards.

Guards two findings from the post-Phase-7 hardening audit:

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

No live network calls: TARGET_URL points at a closed local port, and the
script exits at the confirmation/scope gate stage before ever reaching the
actual HTTP dispatch code (project rule 8/9).
"""

import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SPRAY = REPO_ROOT / "tools" / "spray_orchestrator.sh"


def _write_lists(tmp_path):
    users = tmp_path / "users.txt"
    passes = tmp_path / "passes.txt"
    users.write_text("user1\nuser2\n")
    passes.write_text("pass1\n")
    return users, passes


def _run(args, tmp_path, stdin_text=None, env_extra=None):
    users, passes = _write_lists(tmp_path)
    env = dict(os.environ)
    env["HTTP_PROXY"] = "http://127.0.0.1:1"
    env["HTTPS_PROXY"] = "http://127.0.0.1:1"
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["bash", str(SPRAY), "https://127.0.0.1:1", "--mode", "http-form",
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
        proc = _run([], tmp_path, stdin_text="127.0.0.1:1\nyes\n")
        assert proc.returncode == 2, f"stdout={proc.stdout}\nstderr={proc.stderr}"
        assert "not a TTY" in proc.stdout or "not a TTY" in proc.stderr

    def test_dry_run_still_works_non_interactively(self, tmp_path):
        # --dry-run must not be broken by the new TTY gate -- it never
        # dispatches a real request, so it's always safe non-interactively.
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
        # enforcement.
        proc = _run(
            ["--i-understand"], tmp_path, stdin_text="",
            env_extra={"BB_SCOPE_DOMAINS": "*.example.com,example.com"},
        )
        assert proc.returncode == 1, f"stdout={proc.stdout}\nstderr={proc.stderr}"
        assert "OUT OF SCOPE" in proc.stderr
        # Proof it stopped before ever reaching dispatch: no audit log dir.
        assert not (tmp_path / "recon" / "127.0.0.1" / "spray").exists()

    def test_scope_checker_is_actually_invoked_not_just_commented_about(self):
        content = SPRAY.read_text()
        assert "_scope_gate_asset" in content
        assert "no enforcement CLI" not in content, (
            "the false claim that scope_checker.py has no enforcement CLI "
            "should have been removed along with the fix"
        )
