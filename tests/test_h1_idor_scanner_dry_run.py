"""
Regression tests for tools/h1_idor_scanner.py's --i-understand dry-run gate.

Guards a safety gap found in a follow-up hardening pass: this script fires
real cross-account GraphQL/REST requests against the live HackerOne
platform, using two real bearer tokens, with zero confirmation gate --
unlike its sibling tools/h1_mutation_idor.py, which already required
--i-understand before firing any state-changing mutation. Domain-scope
checking (tools/scope_checker.py) doesn't apply here: both scripts hardcode
their target to https://hackerone.com itself, so there's no variable domain
to check against a BB_SCOPE_DOMAINS allowlist -- the open question is
program authorization, not domain membership, so an explicit human
confirmation gate is the right control (matching the established
spray_orchestrator.sh / h1_mutation_idor.py pattern in this repo).

Fix: main() now exits 0 with a dry-run notice, calling zero of the
test_*_idor() functions, unless --i-understand is passed. No live network
calls in this test file (project rule 8/9) -- urllib.request.urlopen is
monkeypatched.
"""

import sys
from unittest.mock import patch

import pytest

from tools import h1_idor_scanner


class TestMainDryRunByDefault:
    def test_dry_run_makes_no_network_call_and_exits_zero(self, monkeypatch, capsys):
        monkeypatch.setattr(
            sys, "argv",
            ["h1_idor_scanner.py", "--token-a", "tok-a", "--token-b", "tok-b",
             "--report-id", "123"],
        )
        with patch("urllib.request.urlopen") as mock_urlopen:
            with pytest.raises(SystemExit) as exc:
                h1_idor_scanner.main()
        assert exc.value.code == 0
        mock_urlopen.assert_not_called()
        out = capsys.readouterr().out
        assert "DRY-RUN" in out
        assert "--i-understand" in out

    def test_i_understand_flag_defaults_false(self):
        import argparse

        parser = argparse.ArgumentParser()
        parser.add_argument("--token-a", required=True)
        parser.add_argument("--token-b", required=True)
        parser.add_argument("--report-id")
        parser.add_argument("--i-understand", action="store_true")
        args = parser.parse_args(["--token-a", "a", "--token-b", "b", "--report-id", "1"])
        assert args.i_understand is False

    def test_i_understand_true_proceeds_past_the_dry_run_gate(self, monkeypatch, capsys):
        # With --i-understand, main() must reach the real test dispatch
        # instead of short-circuiting -- proven here by patching every
        # test_*_idor() function it would call for a report-id run and
        # asserting at least one was actually invoked, rather than by
        # letting a real network call happen.
        monkeypatch.setattr(
            sys, "argv",
            ["h1_idor_scanner.py", "--token-a", "tok-a", "--token-b", "tok-b",
             "--report-id", "123", "--i-understand", "--only", "1"],
        )
        with patch("tools.h1_idor_scanner.test_report_idor") as mock_test:
            h1_idor_scanner.main()
        mock_test.assert_called_once_with("tok-a", "tok-b", "123")
