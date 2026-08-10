"""Tests for tools/fingerprint.py — Phase 3 Target Intelligence.

Covers: golden-file fingerprints for 6 fixture stacks, graceful degradation
on an unrecognized stack, version-range CVE matching (including boundary
conditions), Phase 1 data taking priority over re-derivation, the
tech_stack -> memory_dir/targets/<target>.json -> director.load_tech_stack()
wiring, and tech_attack_matrix.json weights actually reaching
priority_score()'s technology_match component. No network access anywhere.
"""

import json

import pytest

from tools import fingerprint as fp
from tools import director
from memory.vuln_intelligence import priority_score


# ─── fixture helpers ────────────────────────────────────────────────────────


def _write_routes(recon_dir, framework, build_id=None, routes=None):
    d = recon_dir / "browser"
    d.mkdir(parents=True, exist_ok=True)
    (d / "routes.json").write_text(json.dumps({
        "target": "t.example",
        "framework_detected": framework,
        "build_id": build_id,
        "routes": routes or [],
        "lazy_chunk_imports": [],
        "heuristic_path_literal_count": 0,
    }))


def _write_auth_model(recon_dir, cookies=None):
    d = recon_dir / "browser"
    d.mkdir(parents=True, exist_ok=True)
    (d / "auth-model.json").write_text(json.dumps({
        "target": "t.example",
        "local_storage": [],
        "session_storage": [],
        "cookies": cookies or [],
        "role_permission_constants": [],
        "auth_lifecycle_endpoints": [],
        "candidate_privileged_client_routes": [],
    }))


def _write_api_calls(recon_dir, calls=None):
    d = recon_dir / "browser"
    d.mkdir(parents=True, exist_ok=True)
    (d / "api-calls.json").write_text(json.dumps({
        "target": "t.example",
        "pages_visited": 1,
        "requests_captured": len(calls or []),
        "calls": calls or [],
    }))


def _write_httpx(recon_dir, lines):
    d = recon_dir / "live"
    d.mkdir(parents=True, exist_ok=True)
    (d / "httpx_full.txt").write_text("\n".join(lines) + "\n")


def _cookie(name):
    return {"name": name, "domain": "t.example", "path": "/", "http_only": True,
            "secure": True, "same_site": "Lax", "looks_auth_related": True}


# ─── golden-file fixtures: 6 stacks ────────────────────────────────────────


class TestGoldenFixtures:
    def test_nextjs(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        _write_routes(rd, "nextjs", build_id="abc123")
        result = fp.build_fingerprint("t.example", str(rd))
        assert result["framework"] == "nextjs"
        assert result["confidence"] == 0.85
        assert result["spa_framework"] == "nextjs"
        assert result["router_type"] == "pages-router"
        assert "browser/routes.json" in result["sources"]

    def test_rails(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        _write_httpx(rd, ["https://t.example [200] [Home] [Ruby on Rails,nginx]"])
        result = fp.build_fingerprint("t.example", str(rd))
        assert result["framework"] == "rails"
        assert result["confidence"] == 0.6
        assert result["spa_framework"] is None

    def test_django(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        _write_httpx(rd, ["https://t.example [200] [Home] [Django,gunicorn]"])
        result = fp.build_fingerprint("t.example", str(rd))
        assert result["framework"] == "django"
        assert result["confidence"] == 0.6

    def test_laravel(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        _write_httpx(rd, ["https://t.example [200] [Home] [Laravel,PHP]"])
        result = fp.build_fingerprint("t.example", str(rd))
        assert result["framework"] == "laravel"
        assert result["confidence"] == 0.6

    def test_express(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        _write_httpx(rd, ["https://t.example [200] [API] [Express,Node.js]"])
        result = fp.build_fingerprint("t.example", str(rd))
        assert result["framework"] == "express"
        assert result["confidence"] == 0.6

    def test_wordpress(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        _write_httpx(rd, ["https://t.example [200] [Blog] [WordPress,PHP]"])
        result = fp.build_fingerprint("t.example", str(rd))
        assert result["framework"] == "wordpress"
        assert result["confidence"] == 0.6


# ─── unknown stack degrades gracefully ─────────────────────────────────────


class TestUnknownStack:
    def test_no_recon_data_at_all(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        rd.mkdir(parents=True)
        result = fp.build_fingerprint("t.example", str(rd))
        assert result["framework"] == "unknown"
        assert result["version"] is None
        assert result["confidence"] == 0.0
        assert result["sources"] == []
        assert result["cves"] == []
        # no crash, well-formed dict either way
        assert result["target"] == "t.example"

    def test_unrecognized_stack_still_populates_independent_signals(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        _write_auth_model(rd, cookies=[_cookie("some_random_cookie_name")])
        _write_api_calls(rd, calls=[{
            "method": "GET", "url": "https://t.example/api/widgets",
            "response_shape": {"id": "number", "name": "string"},
        }])
        result = fp.build_fingerprint("t.example", str(rd))
        assert result["framework"] == "unknown"
        assert result["confidence"] == 0.0
        # framework detection failing does NOT blank out unrelated signals
        assert result["auth_model"] is not None
        assert result["auth_model"]["cookies"][0]["name"] == "some_random_cookie_name"
        assert "json" in result["api_style"]


# ─── version-range CVE matching, including boundary conditions ────────────


class TestVersionInRange:
    def test_wildcard_matches_anything_including_unknown_version(self):
        assert fp.version_in_range(None, "*") is True
        assert fp.version_in_range("9.9.9", "*") is True

    def test_unknown_version_fails_closed_on_concrete_range(self):
        assert fp.version_in_range(None, ">=1.0.0,<2.0.0") is False

    def test_lower_bound_inclusive_boundary(self):
        assert fp.version_in_range("11.1.4", ">=11.1.4,<13.5.9") is True

    def test_upper_bound_exclusive_boundary(self):
        assert fp.version_in_range("13.5.9", ">=11.1.4,<13.5.9") is False
        assert fp.version_in_range("13.5.8", ">=11.1.4,<13.5.9") is True

    def test_below_lower_bound(self):
        assert fp.version_in_range("11.1.3", ">=11.1.4,<13.5.9") is False

    def test_malformed_range_fails_closed(self):
        assert fp.version_in_range("1.0.0", "not-a-range") is False

    def test_match_cves_only_surfaces_entries_with_real_cve_id(self):
        matrix = {
            "nextjs": {"version_ranges": [
                {"range": "*", "vulns": [{"class": "ssrf", "weight": 50, "cve": None, "citation": "x"}]},
                {"range": ">=11.1.4,<13.5.9", "vulns": [
                    {"class": "auth-bypass", "weight": 90, "cve": "CVE-2025-29927", "citation": "y"}
                ]},
            ]}
        }
        hits = fp._match_cves("nextjs", "12.0.0", matrix)
        assert hits == [{
            "id": "CVE-2025-29927", "severity": "critical",
            "affected_versions": [">=11.1.4,<13.5.9"],
            "vuln_class": "auth-bypass", "citation": "y",
        }]

        # Version outside the CVE's range -> no hit, even though the "*" entry matches (but has no cve).
        assert fp._match_cves("nextjs", "14.0.0", matrix) == []

    def test_match_cves_degrades_class_and_citation_to_none_when_absent(self):
        # A caller-supplied/malformed matrix omitting class/citation must
        # degrade to None, never raise -- vuln_class=None is how
        # director.py's fingerprint_cve_leads() knows to skip this hit
        # rather than guess a skill.
        matrix = {"custom": {"version_ranges": [
            {"range": "*", "vulns": [{"cve": "CVE-2024-0001", "weight": 60}]},
        ]}}
        hits = fp._match_cves("custom", "1.0.0", matrix)
        assert hits == [{
            "id": "CVE-2024-0001", "severity": "medium",
            "affected_versions": ["*"],
            "vuln_class": None, "citation": None,
        }]


# ─── Phase 1 data wins over re-derivation ──────────────────────────────────


class TestPhase1Priority:
    def test_routes_json_wins_over_contradicting_httpx_signal(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        _write_routes(rd, "nextjs", build_id="abc123")
        # httpx signal disagrees (points at Django) -- routes.json must still win.
        _write_httpx(rd, ["https://t.example [200] [Django Admin Login] [gunicorn]"])
        result = fp.build_fingerprint("t.example", str(rd))
        assert result["framework"] == "nextjs"
        # both tiers fired and agree on nothing, but tier 2 always wins regardless
        assert "browser/routes.json" in result["sources"]
        assert "live/httpx_full.txt" in result["sources"]
        # HIGH-severity fix: the WINNER doesn't change (tier 2 still wins on
        # WHICH framework), but the active contradiction must now be
        # recorded and discounted -- this was previously silent, confidence
        # stayed a flat 0.85 as if httpx had said nothing at all.
        assert result["tier_disagreement"] == [{"tier": 3, "said": "django"}]
        assert result["confidence"] < 0.85
        assert result["confidence"] == round(0.85 * fp.TIER_DISAGREEMENT_PENALTY, 2)

    def test_corroboration_boosts_confidence(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        _write_httpx(rd, ["https://t.example [200] [Home] [Laravel,PHP]"])
        _write_auth_model(rd, cookies=[_cookie("laravel_session")])
        result = fp.build_fingerprint("t.example", str(rd))
        assert result["framework"] == "laravel"
        # tier 3 base (0.6) + 0.1 corroboration from tier 4 cookie match
        assert result["confidence"] == 0.7
        # No disagreement in this scenario -- must not be silently penalized.
        assert result["tier_disagreement"] == []


# ─── HIGH-severity fix: tier disagreement is discounted, not silent ───────
#
# Direct unit tests on _detect_framework() (faster/more precise than going
# through build_fingerprint()'s file-writing helpers for every case) mirror
# memory/attack_graph.py's _apply_contradiction() approach: an active
# contradiction from a non-winning tier must lower confidence and be
# recorded, never just silently outvoted.


class TestTierDisagreement:
    def test_no_signal_from_other_tiers_is_not_a_disagreement(self):
        """Tier 2 wins alone, nothing else fired -- staying silent is not
        the same as contradicting."""
        result = fp._detect_framework({"framework_detected": "nextjs"}, "", None)
        assert result["tier_disagreement"] == []
        assert result["confidence"] == 0.85

    def test_agreement_across_all_tiers_no_disagreement(self):
        result = fp._detect_framework(
            {"framework_detected": "nextjs"}, "[nextjs webpack chunk]",
            {"cookies": [{"name": "next-auth.session-token"}]},
        )
        # tier3's httpx text matches the next.?js marker and corroborates
        # (+0.1); tier4 has no _COOKIE_FRAMEWORK_MARKERS rule for nextjs at
        # all, so it stays silent rather than agreeing OR disagreeing.
        # Silence from one tier + real corroboration from another must
        # never register as a disagreement.
        assert result["tier_disagreement"] == []
        assert result["confidence"] == 0.95  # 0.85 base + 0.10 corroboration, no discount

    def test_single_disagreeing_tier_penalizes_and_records_it(self):
        result = fp._detect_framework(
            {"framework_detected": "nextjs"}, "[Django Admin Login] [gunicorn]", None,
        )
        assert result["framework"] == "nextjs"  # winner unchanged
        assert result["tier_disagreement"] == [{"tier": 3, "said": "django"}]
        assert result["confidence"] == round(0.85 * fp.TIER_DISAGREEMENT_PENALTY, 2)

    def test_disagreement_from_lowest_tier_still_penalizes_the_winner(self):
        """Even the WEAKEST tier (4, cookie names) actively contradicting
        the winner must be recorded/discounted -- not dismissed just
        because it's the lowest-confidence tier in isolation."""
        result = fp._detect_framework(
            {"framework_detected": "react"}, "", {"cookies": [{"name": "laravel_session"}]},
        )
        assert result["framework"] == "react"
        assert result["tier_disagreement"] == [{"tier": 4, "said": "laravel"}]
        assert result["confidence"] == round(0.85 * fp.TIER_DISAGREEMENT_PENALTY, 2)

    def test_mixed_corroboration_and_disagreement_applies_both(self):
        """tier3 corroborates the tier2 winner while tier4 disagrees --
        both real signals must be reflected: the corroboration bonus is
        still earned, then the disagreement penalty is applied on top
        (composition of two already-justified adjustments, not a new
        formula)."""
        result = fp._detect_framework(
            {"framework_detected": "nextjs"}, "[nextjs webpack chunk]",
            {"cookies": [{"name": "laravel_session"}]},
        )
        assert result["framework"] == "nextjs"
        assert result["tier_disagreement"] == [{"tier": 4, "said": "laravel"}]
        # tier3's httpx text ("nextjs webpack chunk") matches the next.?js
        # marker and corroborates the tier2 winner (+0.1), WHILE tier4's
        # cookie name disagrees -- both real signals land on the same
        # result: (0.85 base + 0.10 corroboration) * 0.3 disagreement
        # discount. Exact value asserted, not a vague inequality, so this
        # stays a precise regression on the composition, not just "lower".
        assert result["confidence"] == round((0.85 + 0.10) * fp.TIER_DISAGREEMENT_PENALTY, 2)

    def test_cold_start_no_tier_fires_empty_disagreement_list(self):
        result = fp._detect_framework(None, "", None)
        assert result == {"framework": "unknown", "version": None, "confidence": 0.0, "tier_disagreement": []}

    def test_disagreement_field_reaches_build_fingerprint_output(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        _write_routes(rd, "react")
        _write_httpx(rd, ["https://t.example [200] [Home] [django]"])
        result = fp.build_fingerprint("t.example", str(rd))
        assert result["tier_disagreement"] == [{"tier": 3, "said": "django"}]

    def test_confidence_never_goes_negative_or_above_one(self):
        # winner_tier=2 (0.85) + corroboration would exceed 1.0 without the
        # cap; disagreement discount must still land inside [0, 1].
        result = fp._detect_framework(
            {"framework_detected": "nextjs"}, "[Django Admin Login]", None,
        )
        assert 0.0 <= result["confidence"] <= 1.0


# ─── infra / api_style / spa_framework — reuse, not reimplementation ──────


class TestInfraAndApiStyle:
    def test_cdn_waf_detected_from_httpx_tech_tags(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        _write_httpx(rd, ["https://t.example [200] [Home] [cloudflare,nginx]"])
        result = fp.build_fingerprint("t.example", str(rd))
        assert result["infra"]["cdn"] == "cloudflare"
        assert result["infra"]["waf"] == "cloudflare"

    def test_graphql_api_style_from_api_calls(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        _write_api_calls(rd, calls=[{
            "method": "POST", "url": "https://t.example/graphql",
            "response_shape": {"data": {"user": "string"}},
        }])
        result = fp.build_fingerprint("t.example", str(rd))
        assert "graphql" in result["api_style"]
        assert "json" in result["api_style"]


# ─── tech_stack -> memory_dir/targets/<target>.json -> director wiring ────


class TestSyncTechStack:
    def test_sync_then_director_load_tech_stack_reads_it(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        _write_routes(rd, "nextjs", build_id="abc123")
        _write_api_calls(rd, calls=[{
            "method": "POST", "url": "https://t.example/graphql",
            "response_shape": {"data": {}},
        }])
        result = fp.build_fingerprint("t.example", str(rd))

        mem_dir = tmp_path / "hunt-memory"
        fp.sync_tech_stack("t.example", str(mem_dir), result)

        stack = director.load_tech_stack("t.example", str(mem_dir))
        assert "nextjs" in stack
        assert "graphql" in stack

    def test_sync_preserves_existing_profile_fields(self, tmp_path):
        mem_dir = tmp_path / "hunt-memory"
        (mem_dir / "targets").mkdir(parents=True)
        (mem_dir / "targets" / "t.example.json").write_text(json.dumps({
            "target": "t.example", "first_hunted": "2026-01-01T00:00:00Z",
            "last_hunted": "2026-01-01T00:00:00Z", "schema_version": 1,
            "tech_stack": ["manual-tag"], "hunt_sessions": 3,
        }))
        result = {"framework": "nextjs", "spa_framework": "nextjs", "api_style": []}
        profile = fp.sync_tech_stack("t.example", str(mem_dir), result)
        assert profile["hunt_sessions"] == 3
        assert "manual-tag" in profile["tech_stack"]
        assert "nextjs" in profile["tech_stack"]

    def test_crash_mid_write_never_corrupts_the_prior_profile(self, tmp_path, monkeypatch):
        # Phase 5 (state recovery): this is a read-modify-write of the
        # target's WHOLE profile (tech_stack history, tested_endpoints,
        # hunt_sessions) -- a crash mid-write must never lose it all just
        # because this one sync was interrupted.
        mem_dir = tmp_path / "hunt-memory"
        (mem_dir / "targets").mkdir(parents=True)
        profile_path = mem_dir / "targets" / "t.example.json"
        profile_path.write_text(json.dumps({
            "target": "t.example", "first_hunted": "2026-01-01T00:00:00Z",
            "last_hunted": "2026-01-01T00:00:00Z", "schema_version": 1,
            "tech_stack": ["manual-tag"], "hunt_sessions": 3,
        }))
        original_bytes = profile_path.read_bytes()

        import memory.atomic_write as aw
        monkeypatch.setattr(aw.os, "replace", lambda *a, **kw: (_ for _ in ()).throw(OSError("simulated crash")))
        with pytest.raises(OSError, match="simulated crash"):
            fp.sync_tech_stack("t.example", str(mem_dir), {"framework": "django"})

        assert profile_path.read_bytes() == original_bytes
        restored = json.loads(profile_path.read_text())
        assert restored["hunt_sessions"] == 3
        assert restored["tech_stack"] == ["manual-tag"]


# ─── tech_attack_matrix.json weights reach priority_score() ───────────────


class TestMatrixReachesPriorityScore:
    def test_default_behavior_unchanged_without_matrix(self):
        result = priority_score("auth-bypass", ["nextjs"], "t.example",
                                 patterns=[], failed_patterns=[])
        assert result["components"]["technology_match"] == 20

    def test_matrix_weight_replaces_floor_for_matching_class(self):
        matrix = fp.load_tech_attack_matrix()
        result = priority_score("auth-bypass", ["nextjs"], "t.example",
                                 patterns=[], failed_patterns=[],
                                 tech_attack_matrix=matrix)
        assert result["components"]["technology_match"] == 90

    def test_matrix_no_matching_class_keeps_floor(self):
        matrix = fp.load_tech_attack_matrix()
        result = priority_score("sqli", ["nextjs"], "t.example",
                                 patterns=[], failed_patterns=[],
                                 tech_attack_matrix=matrix)
        assert result["components"]["technology_match"] == 20

    def test_real_affinity_data_still_wins_over_matrix(self):
        matrix = fp.load_tech_attack_matrix()
        patterns = [{"target": "other", "vuln_class": "auth-bypass",
                     "tech_stack": ["nextjs"], "technique": "x"}]
        result = priority_score("auth-bypass", ["nextjs"], "t.example",
                                 patterns=patterns, failed_patterns=[],
                                 tech_attack_matrix=matrix)
        # Real win/loss experience exists -> affinity confidence path used,
        # not the matrix floor-replacement branch at all.
        assert result["components"]["technology_match"] != 90


class TestMergeTechAttackMatrix:
    """Phase 5, Part D — combining the hand-curated static matrix with an
    auto-fetched live-CVE cache. Pure, no network, no mutation of inputs."""

    def test_empty_inputs_yield_empty_matrix(self):
        assert fp.merge_tech_attack_matrix({}, {}) == {}

    def test_static_only_passes_through(self):
        static = {"nextjs": {"version_ranges": [{"range": "*", "vulns": []}]}}
        assert fp.merge_tech_attack_matrix(static, {}) == static

    def test_live_only_passes_through(self):
        live = {"rails": {"version_ranges": [{"range": "*", "vulns": []}]}}
        assert fp.merge_tech_attack_matrix({}, live) == live

    def test_same_tag_concatenates_version_ranges(self):
        static = {"nextjs": {"version_ranges": [{"range": "*", "vulns": [{"class": "ssrf", "weight": 50, "cve": None, "citation": "x"}]}]}}
        live = {"nextjs": {"version_ranges": [{"range": "==14.0.1", "vulns": [{"class": "misconfig", "weight": 90, "cve": "CVE-2024-1234", "citation": "y"}]}]}}
        merged = fp.merge_tech_attack_matrix(static, live)
        assert len(merged["nextjs"]["version_ranges"]) == 2

    def test_inputs_not_mutated(self):
        static = {"nextjs": {"version_ranges": [{"range": "*", "vulns": []}]}}
        live = {"nextjs": {"version_ranges": [{"range": "==1.0.0", "vulns": []}]}}
        fp.merge_tech_attack_matrix(static, live)
        assert len(static["nextjs"]["version_ranges"]) == 1
        assert len(live["nextjs"]["version_ranges"]) == 1

    def test_merged_matrix_still_consumable_by_match_cves_via_has_cve_for(self):
        live = {"rails": {"version_ranges": [{"range": "*", "vulns": [{"class": "misconfig", "weight": 70, "cve": "CVE-2023-9999", "citation": "z"}]}]}}
        merged = fp.merge_tech_attack_matrix({}, live)
        assert fp.has_cve_for("rails", None, merged) is True


class TestHasCveFor:

    def test_no_entry_for_tag_is_false(self):
        assert fp.has_cve_for("unknown-tag", None, {}) is False

    def test_weight_only_entry_is_false(self):
        matrix = {"graphql": {"version_ranges": [{"range": "*", "vulns": [{"class": "idor", "weight": 80, "cve": None, "citation": "x"}]}]}}
        assert fp.has_cve_for("graphql", None, matrix) is False

    def test_real_cve_entry_is_true(self):
        matrix = {"nextjs": {"version_ranges": [{"range": ">=11.1.4,<13.5.9", "vulns": [{"class": "auth-bypass", "weight": 90, "cve": "CVE-2025-29927", "citation": "x"}]}]}}
        assert fp.has_cve_for("nextjs", "12.0.0", matrix) is True

    def test_real_cve_outside_version_range_is_false(self):
        matrix = {"nextjs": {"version_ranges": [{"range": ">=11.1.4,<13.5.9", "vulns": [{"class": "auth-bypass", "weight": 90, "cve": "CVE-2025-29927", "citation": "x"}]}]}}
        assert fp.has_cve_for("nextjs", "14.0.0", matrix) is False

    def test_default_matrix_next_js_known_cve(self):
        matrix = fp.load_tech_attack_matrix()
        assert fp.has_cve_for("nextjs", "12.0.0", matrix) is True


class TestSeverityWeightTier:
    """Reuses _severity_for_weight()'s exact tier boundaries — no new
    heuristic constants, just the inverse mapping of an existing one."""

    def test_critical_maps_to_the_critical_boundary(self):
        assert fp.severity_weight_tier("CRITICAL") == 90

    def test_high_maps_to_the_high_boundary(self):
        assert fp.severity_weight_tier("HIGH") == 70

    def test_medium_maps_to_the_medium_boundary(self):
        assert fp.severity_weight_tier("MEDIUM") == 40

    def test_moderate_treated_same_as_medium(self):
        assert fp.severity_weight_tier("MODERATE") == 40

    def test_low_maps_to_the_existing_cold_start_floor(self):
        assert fp.severity_weight_tier("LOW") == 20

    def test_unknown_severity_falls_to_low_floor(self):
        assert fp.severity_weight_tier("nonsense") == 20
        assert fp.severity_weight_tier("") == 20

    def test_round_trips_through_severity_for_weight(self):
        # severity_weight_tier() is the inverse of the private
        # _severity_for_weight() — the boundary weight for each tier must
        # classify back to that same tier.
        for severity, weight in (("critical", 90), ("high", 70), ("medium", 40), ("low", 20)):
            assert fp._severity_for_weight(weight) == severity


class TestSaveTechAttackMatrixCache:

    def test_writes_valid_json_readable_by_load_tech_attack_matrix(self, tmp_path):
        path = tmp_path / "cache.json"
        matrix = {"nextjs": {"version_ranges": [{"range": "==14.0.1", "vulns": [{"class": "misconfig", "weight": 90, "cve": "CVE-2024-1234", "citation": "x"}]}]}}
        fp.save_tech_attack_matrix_cache(matrix, str(path))
        assert fp.load_tech_attack_matrix(str(path)) == matrix

    def test_creates_parent_directories(self, tmp_path):
        path = tmp_path / "nested" / "dir" / "cache.json"
        fp.save_tech_attack_matrix_cache({}, str(path))
        assert path.exists()

    def test_crash_mid_write_never_corrupts_prior_cached_cves(self, tmp_path, monkeypatch):
        # Phase 5: tools/learn.py always passes the FULL accumulated cache
        # (existing entries + one new tag) -- a crash mid-write must not
        # lose every previously-cached CVE lookup just because this one
        # save was interrupted (each entry only exists after a real,
        # opt-in network fetch -- losing it forces a real re-fetch, not
        # free to regenerate).
        path = tmp_path / "cache.json"
        original = {"nextjs": {"version_ranges": [{"range": "==14.0.1", "vulns": [
            {"class": "misconfig", "weight": 90, "cve": "CVE-2024-1234", "citation": "x"}]}]}}
        fp.save_tech_attack_matrix_cache(original, str(path))
        original_bytes = path.read_bytes()

        import memory.atomic_write as aw
        monkeypatch.setattr(aw.os, "replace", lambda *a, **kw: (_ for _ in ()).throw(OSError("simulated crash")))
        updated = dict(original, django={"version_ranges": []})
        with pytest.raises(OSError, match="simulated crash"):
            fp.save_tech_attack_matrix_cache(updated, str(path))

        assert path.read_bytes() == original_bytes
        assert fp.load_tech_attack_matrix(str(path)) == original


class TestLiveCveLookupCli:
    """Phase 5, Part D — fp.main()'s --live-cve-lookup opt-in flag. Mocks
    tools.learn.fetch_and_cache_cve() so these tests never touch the real
    network (module-level main() only reaches it via a local `from tools
    import learn` — monkeypatching the already-imported module object
    works regardless of that import's timing)."""

    def test_default_run_never_imports_or_calls_learn(self, tmp_path, monkeypatch, capsys):
        from tools import learn as learn_module

        def _boom(*a, **kw):
            raise AssertionError("must not be called without --live-cve-lookup")

        monkeypatch.setattr(learn_module, "fetch_and_cache_cve", _boom)
        rd = tmp_path / "recon" / "t.example"
        _write_httpx(rd, ["https://t.example [200] [Home] [Django,gunicorn]"])
        exit_code = fp.main(["--target", "t.example", "--recon-dir", str(rd), "--quiet"])
        assert exit_code == 0

    def test_live_cve_lookup_fetches_only_for_a_real_gap(self, tmp_path, monkeypatch, capsys):
        from tools import learn as learn_module

        calls = []

        def _fake_fetch(tag, version=None, existing_matrix=None, cache_path=None):
            calls.append((tag, version))
            return {
                "version_ranges": [{
                    "range": "*",
                    "vulns": [{"class": "misconfig", "weight": 70, "cve": "CVE-2024-7777", "citation": "test"}],
                }],
            }

        monkeypatch.setattr(learn_module, "fetch_and_cache_cve", _fake_fetch)

        rd = tmp_path / "recon" / "t.example"
        _write_httpx(rd, ["https://t.example [200] [Home] [Django,gunicorn]"])
        cache_path = tmp_path / "live_cache.json"
        exit_code = fp.main([
            "--target", "t.example", "--recon-dir", str(rd),
            "--live-cve-lookup", "--live-cve-cache", str(cache_path), "--quiet",
        ])
        assert exit_code == 0
        assert calls == [("django", None)]  # django has no version signal in httpx text

    def test_live_cve_lookup_skips_fetch_when_matrix_already_has_a_real_cve(self, tmp_path, monkeypatch):
        from tools import learn as learn_module

        def _boom(*a, **kw):
            raise AssertionError("must not fetch — nextjs 12.0.0 already has a real cve in the static matrix")

        monkeypatch.setattr(learn_module, "fetch_and_cache_cve", _boom)

        rd = tmp_path / "recon" / "t.example"
        # httpx text only (not routes.json) so a VERSION is actually
        # extracted — routes.json's framework_detected wins tier2 with no
        # version attached, which would make has_cve_for() fail closed and
        # defeat this test's premise.
        _write_httpx(rd, ["https://t.example [200] [Home] [Next.js 12.0.0]"])
        cache_path = tmp_path / "live_cache.json"
        exit_code = fp.main([
            "--target", "t.example", "--recon-dir", str(rd),
            "--live-cve-lookup", "--live-cve-cache", str(cache_path), "--quiet",
        ])
        assert exit_code == 0

    def test_fetched_cve_reaches_the_written_fingerprint(self, tmp_path, monkeypatch):
        from tools import learn as learn_module

        def _fake_fetch(tag, version=None, existing_matrix=None, cache_path=None):
            return {
                "version_ranges": [{
                    "range": "*",
                    "vulns": [{"class": "misconfig", "weight": 70, "cve": "CVE-2024-8888", "citation": "test"}],
                }],
            }

        monkeypatch.setattr(learn_module, "fetch_and_cache_cve", _fake_fetch)

        rd = tmp_path / "recon" / "t.example"
        _write_httpx(rd, ["https://t.example [200] [Home] [Django,gunicorn]"])
        cache_path = tmp_path / "live_cache.json"
        fp.main([
            "--target", "t.example", "--recon-dir", str(rd),
            "--live-cve-lookup", "--live-cve-cache", str(cache_path), "--quiet",
        ])
        written = json.loads((rd / "fingerprint.json").read_text())
        assert any(c["id"] == "CVE-2024-8888" for c in written["cves"])

    def test_no_real_cve_found_leaves_cve_null_same_as_today(self, tmp_path, monkeypatch):
        from tools import learn as learn_module

        monkeypatch.setattr(learn_module, "fetch_and_cache_cve", lambda *a, **kw: None)

        rd = tmp_path / "recon" / "t.example"
        _write_httpx(rd, ["https://t.example [200] [Home] [Django,gunicorn]"])
        cache_path = tmp_path / "live_cache.json"
        exit_code = fp.main([
            "--target", "t.example", "--recon-dir", str(rd),
            "--live-cve-lookup", "--live-cve-cache", str(cache_path), "--quiet",
        ])
        assert exit_code == 0
        written = json.loads((rd / "fingerprint.json").read_text())
        assert written["cves"] == []
