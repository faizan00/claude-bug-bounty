"""
Regression tests for tools/waf_response_analyzer.py's ResponseClassifier.classify().

Guards a false-positive found during the post-Phase-7 hardening audit:
running tools/bypass_403.sh with no network reachable (a closed proxy, a
dead target, or simply no connectivity) caused curl to report HTTP status
000 for every probe. classify() had no gate requiring an actual HTTP
response before scoring -- an all-signals-absent score of 0 fell through
to the "bypassed" verdict purely because a failed connection has no WAF
block body to match against, so bypass_403.sh reported dozens of
[CONFIRMED] bypasses that were really just "curl never connected."

The project rule this enforces: prefer NO FINDING / INSUFFICIENT EVIDENCE
over a fabricated finding. status_code 0 must never classify as "bypassed"
(nor "blocked" -- nothing was actually blocked either), only "needs_review".
"""

from tools.waf_response_analyzer import ResponseClassifier, ResponseFingerprint


def _fp(**overrides) -> ResponseFingerprint:
    defaults = dict(
        status_code=200,
        body_length=0,
        body_preview="",
        vendor_hits=[],
        log_ids={},
        has_business_signal=False,
        has_business_cookies=False,
        has_block_title=False,
        has_challenge_signal=False,
        response_time_ms=50.0,
        body_sha256="",
    )
    defaults.update(overrides)
    return ResponseFingerprint(**defaults)


class TestNoResponseIsNeverABypass:
    def test_status_zero_is_needs_review_not_bypassed(self):
        fp = _fp(status_code=0, body_length=0)
        result = ResponseClassifier().classify(fp, baseline=None)
        assert result["verdict"] == "needs_review"
        assert result["score"] == 0

    def test_status_zero_is_never_blocked_either(self):
        # A connection failure is not proof the WAF blocked anything -- it's
        # proof nothing was observed at all. Must not silently become
        # "blocked" (which would look like the WAF did its job) any more
        # than it should become "bypassed".
        fp = _fp(status_code=0, body_length=0)
        result = ResponseClassifier().classify(fp, baseline=None)
        assert result["verdict"] != "blocked"

    def test_status_zero_wins_even_with_a_stale_block_baseline(self):
        # Even if a baseline was sampled earlier in the run (e.g. the
        # baseline probe succeeded but this specific probe's connection
        # then failed), status 0 must still short-circuit to needs_review
        # rather than being scored against that baseline.
        fp = _fp(status_code=0, body_length=0)
        baseline = {"block_baseline": {"median_length": 512, "vendor": "cloudflare"}}
        result = ResponseClassifier().classify(fp, baseline=baseline)
        assert result["verdict"] == "needs_review"


class TestRealResponsesStillClassifyNormally:
    """Sanity check: the status-0 gate must not swallow real verdicts."""

    def test_clean_200_with_no_signals_is_still_bypassed(self):
        fp = _fp(status_code=200, body_length=1500)
        result = ResponseClassifier().classify(fp, baseline=None)
        assert result["verdict"] == "bypassed"

    def test_vendor_signature_match_is_still_blocked(self):
        fp = _fp(status_code=403, vendor_hits=["cloudflare"], has_block_title=True)
        result = ResponseClassifier().classify(fp, baseline=None)
        assert result["verdict"] == "blocked"

    def test_backend_error_status_leans_toward_bypassed(self):
        fp = _fp(status_code=502, body_length=200)
        result = ResponseClassifier().classify(fp, baseline=None)
        assert result["verdict"] in ("bypassed", "needs_review")
