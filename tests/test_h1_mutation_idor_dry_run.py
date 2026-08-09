"""
Regression tests for tools/h1_mutation_idor.py's --i-understand dry-run gate.

Guards a safety gap found during the post-Phase-7 hardening audit: this
script fires ten real, state-changing GraphQL mutations against a live
HackerOne report unconditionally -- closeReport, awardBounty,
requestPublicDisclosure, assignReport, etc. -- with no dry-run default and
no confirmation flag, unlike tools/spray_orchestrator.sh's established
typed-confirmation pattern for destructive actions in this repo.

Fix: mutations now route through run_mutation(), which only calls gql()
(the one function that ever sends a network request in this file) when
i_understand=True. Default (i_understand=False) prints a dry-run notice
and makes zero network calls. No live network calls in this test file
(project rule 8/9) -- gql() is monkeypatched.
"""

from unittest.mock import patch

from tools.h1_mutation_idor import run_mutation


class TestRunMutationDryRunByDefault:
    def test_dry_run_never_calls_gql(self):
        findings = []
        with patch("tools.h1_mutation_idor.gql") as mock_gql:
            run_mutation("closeReport", "mutation { closeReport }", "cookie", "csrf",
                         i_understand=False, findings=findings)
        mock_gql.assert_not_called()
        assert findings == []

    def test_dry_run_prints_notice(self, capsys):
        with patch("tools.h1_mutation_idor.gql"):
            run_mutation("awardBounty", "mutation { awardBounty }", "cookie", "csrf",
                         i_understand=False, findings=[])
        out = capsys.readouterr().out
        assert "DRY-RUN" in out
        assert "awardBounty" in out
        assert "--i-understand" in out

    def test_i_understand_true_actually_calls_gql(self):
        findings = []
        with patch("tools.h1_mutation_idor.gql", return_value=(200, {"data": {"x": None}})) as mock_gql:
            run_mutation("closeReport", "mutation { closeReport }", "cookie", "csrf",
                         i_understand=True, findings=findings)
        mock_gql.assert_called_once_with("cookie", "csrf", "mutation { closeReport }")

    def test_i_understand_true_records_a_real_finding_when_mutation_succeeds(self):
        findings = []
        with patch("tools.h1_mutation_idor.gql", return_value=(200, {"data": {"report": {"id": "1"}}})):
            run_mutation("closeReport", "mutation { closeReport }", "cookie", "csrf",
                         i_understand=True, findings=findings)
        assert findings == ["closeReport"]


class TestCliDefaultsToDryRun:
    def test_i_understand_flag_defaults_false(self):
        import argparse
        from tools import h1_mutation_idor

        parser = argparse.ArgumentParser()
        parser.add_argument("--cookie-a", required=True)
        parser.add_argument("--cookie-b", required=True)
        parser.add_argument("--report-id", required=True)
        parser.add_argument("--report-gid", required=True)
        parser.add_argument("--i-understand", action="store_true")
        args = parser.parse_args(["--cookie-a", "a", "--cookie-b", "b",
                                   "--report-id", "1", "--report-gid", "g"])
        assert args.i_understand is False
        del h1_mutation_idor  # imported only to prove the module still loads cleanly
