"""
Regression tests for tools/h1_idor_scanner.py's check() / is_same_data().

Guards a false-positive found during the post-Phase-7 hardening audit:
check() computed `same = is_same_data(resp_a, resp_b)` and then never read
`same` again -- the actual gate was "does B's response have any non-null
field", which flags cross-account access even when B's response doesn't
match A's data at all (e.g. B legitimately seeing their own, different,
non-null data for the same field name). That means every test_*_idor()
call in this file could fabricate an IDOR finding from ordinary, correct
authorization behavior.

Fix: check() now only flags when B's response is provably identical to
A's (same == True). A non-null-but-different response is reported as
"inconclusive", never auto-flagged. Prefer NO FINDING over a fabricated
finding (project rule 5).
"""

import io
import contextlib

from tools.h1_idor_scanner import check, is_same_data, FINDINGS


def _run_check(test_name, resp_a, resp_b, severity="HIGH"):
    FINDINGS.clear()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        check(test_name, resp_a, resp_b, severity)
    return FINDINGS.copy(), buf.getvalue()


class TestIsSameData:
    def test_identical_data_is_same(self):
        a = {"data": {"report": {"title": "secret"}}}
        b = {"data": {"report": {"title": "secret"}}}
        assert is_same_data(a, b) is True

    def test_different_data_is_not_same(self):
        a = {"data": {"report": {"title": "secret-A"}}}
        b = {"data": {"report": {"title": "my-own-report"}}}
        assert is_same_data(a, b) is False

    def test_null_data_is_not_same(self):
        a = {"data": {"report": {"title": "secret"}}}
        b = {"data": {"report": None}}
        assert is_same_data(a, b) is False


class TestCheckDoesNotFabricateFindings:
    def test_bs_own_different_data_is_never_flagged(self):
        # B has a non-null field, but it's B's OWN data, not A's -- this
        # used to be flagged as IDOR purely because b_data was non-null.
        resp_a = {"data": {"report": {"title": "A's private report"}}}
        resp_b = {"data": {"report": {"title": "B's own unrelated report"}}}
        findings, output = _run_check("report.title", resp_a, resp_b)
        assert findings == []
        assert "inconclusive" in output.lower()

    def test_public_shared_field_returning_same_value_is_still_flagged(self):
        # Documented, accepted limitation: check() cannot distinguish
        # "B illegitimately saw A's private data" from "the field is
        # genuinely public/identical for everyone" -- both look like an
        # exact match. A human must still judge sensitivity before
        # reporting. This test locks in that this is a deliberate,
        # disclosed limitation, not a silent regression.
        resp_a = {"data": {"program": {"policy": "public policy text"}}}
        resp_b = {"data": {"program": {"policy": "public policy text"}}}
        findings, _ = _run_check("program.policy", resp_a, resp_b, severity="MEDIUM")
        assert len(findings) == 1

    def test_exact_match_of_private_data_is_flagged(self):
        resp_a = {"data": {"report": {"title": "A's private report", "email": "a@x.com"}}}
        resp_b = {"data": {"report": {"title": "A's private report", "email": "a@x.com"}}}
        findings, output = _run_check("report.full", resp_a, resp_b, severity="CRITICAL")
        assert len(findings) == 1
        assert findings[0]["severity"] == "CRITICAL"
        assert "IDOR FOUND" in output

    def test_error_response_is_blocked_not_flagged(self):
        resp_a = {"data": {"report": {"title": "secret"}}}
        resp_b = {"errors": [{"message": "not authorized"}]}
        findings, output = _run_check("report.title", resp_a, resp_b)
        assert findings == []
        assert "BLOCKED" in output

    def test_null_response_is_ok_not_flagged(self):
        resp_a = {"data": {"report": {"title": "secret"}}}
        resp_b = {"data": {"report": None}}
        findings, output = _run_check("report.title", resp_a, resp_b)
        assert findings == []
        assert "NULL (ok)" in output
