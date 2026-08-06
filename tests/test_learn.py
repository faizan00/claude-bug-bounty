"""Tests for tools/learn.py's Phase 5, Part D live-CVE-cache wiring.

fetch_and_cache_cve() is the one function in this file whose CALLERS must
opt in (see tools/fingerprint.py's --live-cve-lookup flag) before it makes
a network call at all. These tests never touch the real network: every
call to fetch_github_advisories()/fetch_nvd_cves() is monkeypatched.
"""

import json

import pytest

from tools import fingerprint as fp
from tools import learn


def _cve(id_, source="NVD", severity="HIGH", summary="A real vulnerability", score=None):
    return {"id": id_, "source": source, "tech": "x", "severity": severity,
            "summary": summary, "published": "2026-01-01", "score": score, "grep": []}


class TestWeightForCveResult:

    def test_nvd_score_rescaled_to_0_100(self):
        assert learn._weight_for_cve_result({"score": 7.5}) == 75

    def test_nvd_score_clamped_to_100(self):
        assert learn._weight_for_cve_result({"score": 10.0}) == 100

    def test_nvd_score_zero_is_zero(self):
        assert learn._weight_for_cve_result({"score": 0.0}) == 0

    def test_missing_score_falls_back_to_severity_tier(self):
        assert learn._weight_for_cve_result({"severity": "CRITICAL"}) == fp.severity_weight_tier("CRITICAL")

    def test_non_numeric_score_falls_back_to_severity_tier(self):
        assert learn._weight_for_cve_result({"score": None, "severity": "LOW"}) == fp.severity_weight_tier("LOW")


class TestFetchAndCacheCve:

    def test_no_network_call_when_already_cached(self, tmp_path, monkeypatch):
        cache_path = tmp_path / "cache.json"
        fp.save_tech_attack_matrix_cache(
            {"nextjs": {"version_ranges": [{"range": "*", "vulns": [
                {"class": "misconfig", "weight": 90, "cve": "CVE-2024-0001", "citation": "already cached"},
            ]}]}},
            str(cache_path),
        )

        def _boom(*a, **kw):
            raise AssertionError("must not fetch — already cached")

        monkeypatch.setattr(learn, "fetch_github_advisories", _boom)
        monkeypatch.setattr(learn, "fetch_nvd_cves", _boom)

        result = learn.fetch_and_cache_cve("nextjs", version=None, cache_path=str(cache_path))
        assert result["version_ranges"][0]["vulns"][0]["cve"] == "CVE-2024-0001"

    def test_real_cve_found_gets_cached(self, tmp_path, monkeypatch):
        cache_path = tmp_path / "cache.json"
        monkeypatch.setattr(learn, "fetch_github_advisories", lambda tech: [_cve("GHSA-xxxx-yyyy-zzzz", source="GitHub Advisory")])
        monkeypatch.setattr(learn, "fetch_nvd_cves", lambda tech: [_cve("CVE-2024-9999", score=8.1)])

        result = learn.fetch_and_cache_cve("sometech", version="2.0.0", cache_path=str(cache_path))
        assert result is not None
        vuln = result["version_ranges"][0]["vulns"][0]
        assert vuln["cve"] == "CVE-2024-9999"
        assert vuln["class"] == "misconfig"
        assert vuln["weight"] == 81
        assert result["version_ranges"][0]["range"] == "==2.0.0"

        # And it was actually written to disk.
        on_disk = fp.load_tech_attack_matrix(str(cache_path))
        assert on_disk["sometech"]["version_ranges"][0]["vulns"][0]["cve"] == "CVE-2024-9999"

    def test_no_real_cve_found_returns_none_and_does_not_cache(self, tmp_path, monkeypatch):
        cache_path = tmp_path / "cache.json"
        # Only a GHSA id, no real "CVE-" id anywhere -- must not be treated
        # as a CVE, per "never fabricate a CVE ID".
        monkeypatch.setattr(learn, "fetch_github_advisories", lambda tech: [_cve("GHSA-xxxx-yyyy-zzzz", source="GitHub Advisory")])
        monkeypatch.setattr(learn, "fetch_nvd_cves", lambda tech: [])

        result = learn.fetch_and_cache_cve("obscure-tech", cache_path=str(cache_path))
        assert result is None
        assert fp.load_tech_attack_matrix(str(cache_path)) == {}

    def test_empty_results_returns_none(self, tmp_path, monkeypatch):
        cache_path = tmp_path / "cache.json"
        monkeypatch.setattr(learn, "fetch_github_advisories", lambda tech: [])
        monkeypatch.setattr(learn, "fetch_nvd_cves", lambda tech: [])

        assert learn.fetch_and_cache_cve("nothing-tech", cache_path=str(cache_path)) is None

    def test_highest_severity_real_cve_wins_when_multiple_found(self, tmp_path, monkeypatch):
        cache_path = tmp_path / "cache.json"
        monkeypatch.setattr(learn, "fetch_github_advisories", lambda tech: [_cve("CVE-2024-1111", severity="LOW")])
        monkeypatch.setattr(learn, "fetch_nvd_cves", lambda tech: [_cve("CVE-2024-2222", severity="CRITICAL")])

        result = learn.fetch_and_cache_cve("multi-tech", cache_path=str(cache_path))
        assert result["version_ranges"][0]["vulns"][0]["cve"] == "CVE-2024-2222"

    def test_no_version_uses_wildcard_range(self, tmp_path, monkeypatch):
        cache_path = tmp_path / "cache.json"
        monkeypatch.setattr(learn, "fetch_github_advisories", lambda tech: [])
        monkeypatch.setattr(learn, "fetch_nvd_cves", lambda tech: [_cve("CVE-2024-3333")])

        result = learn.fetch_and_cache_cve("no-version-tech", version=None, cache_path=str(cache_path))
        assert result["version_ranges"][0]["range"] == "*"

    def test_citation_includes_real_summary_and_source(self, tmp_path, monkeypatch):
        cache_path = tmp_path / "cache.json"
        monkeypatch.setattr(learn, "fetch_github_advisories", lambda tech: [])
        monkeypatch.setattr(learn, "fetch_nvd_cves",
                             lambda tech: [_cve("CVE-2024-4444", summary="Remote code execution via template injection")])

        result = learn.fetch_and_cache_cve("citation-tech", cache_path=str(cache_path))
        citation = result["version_ranges"][0]["vulns"][0]["citation"]
        assert "Remote code execution via template injection" in citation
        assert "NVD" in citation

    def test_default_cache_path_used_when_omitted(self, monkeypatch, tmp_path):
        # Redirect the DEFAULT_LIVE_CVE_CACHE_PATH itself so this test never
        # touches the real tools/ directory on disk.
        fake_default = tmp_path / "default_cache.json"
        monkeypatch.setattr(fp, "DEFAULT_LIVE_CVE_CACHE_PATH", str(fake_default))
        monkeypatch.setattr(learn, "fetch_github_advisories", lambda tech: [])
        monkeypatch.setattr(learn, "fetch_nvd_cves", lambda tech: [_cve("CVE-2024-5555")])

        result = learn.fetch_and_cache_cve("default-path-tech")
        assert result is not None
        assert fake_default.exists()

    def test_existing_matrix_with_real_cve_short_circuits_fetch(self, tmp_path, monkeypatch):
        cache_path = tmp_path / "cache.json"  # empty cache on disk

        def _boom(*a, **kw):
            raise AssertionError("must not fetch — existing_matrix already has a real cve")

        monkeypatch.setattr(learn, "fetch_github_advisories", _boom)
        monkeypatch.setattr(learn, "fetch_nvd_cves", _boom)

        existing = {"nextjs": {"version_ranges": [{"range": ">=11.1.4,<13.5.9",
                                                     "vulns": [{"class": "auth-bypass", "weight": 90,
                                                                "cve": "CVE-2025-29927", "citation": "x"}]}]}}
        result = learn.fetch_and_cache_cve("nextjs", version="12.0.0", existing_matrix=existing, cache_path=str(cache_path))
        assert result is None  # nothing NEW cached (already known via existing_matrix), no crash
