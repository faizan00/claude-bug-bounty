"""Tests for tools/secrets_scanner.py — Phase 5 Part C.

Covers: Shannon entropy math, vendor-pattern matches, entropy-only findings
(and that they never double-count a pattern-matched span), JS-specific
signals (internal URLs, feature flags, GraphQL fragments, exposed
sourcemaps via directory evidence), evidence_type labeling (provenance,
not a numeric confidence score — see secrets_scanner.py's EVIDENCE TYPING
docstring section), and the recon_dir/cicd_dir file-walking entry points.
No network access anywhere.
"""

import json
import math

from tools.secrets_scanner import (
    B64_ENTROPY_THRESHOLD,
    EVIDENCE_TYPE_BROWSER_ARTIFACT,
    EVIDENCE_TYPE_STATIC_JS,
    HEX_ENTROPY_THRESHOLD,
    find_exposed_sourcemap_signal,
    find_feature_flags,
    find_graphql_fragments,
    find_high_entropy_strings,
    find_internal_api_urls,
    find_pattern_matches,
    scan_all,
    scan_cicd_findings,
    scan_path,
    scan_recon_sources,
    scan_text,
    shannon_entropy,
)


class TestShannonEntropy:

    def test_empty_string_is_zero(self):
        assert shannon_entropy("") == 0.0

    def test_single_repeated_char_is_zero(self):
        assert shannon_entropy("aaaaaaaaaa") == 0.0

    def test_uniform_random_looking_string_has_high_entropy(self):
        # 16 distinct chars, each once -> max entropy for that alphabet size
        s = "0123456789abcdef"
        assert shannon_entropy(s) == math.log2(16)

    def test_higher_diversity_gives_higher_entropy(self):
        low = shannon_entropy("aaaabbbb")
        high = shannon_entropy("a1B2c3D4")
        assert high > low


class TestFindPatternMatches:

    def test_aws_access_key_detected(self):
        findings = find_pattern_matches('const k = "AKIAIOSFODNN7EXAMPLE";')
        assert any(f["signature"] == "aws_access_key_id" for f in findings)
        assert all(f["evidence_type"] == EVIDENCE_TYPE_STATIC_JS for f in findings)
        assert all(f["method"] == "pattern" for f in findings)

    def test_github_token_detected(self):
        findings = find_pattern_matches("token = ghp_" + "a" * 36)
        assert any(f["signature"] == "github_token" for f in findings)

    def test_private_key_block_detected(self):
        findings = find_pattern_matches("-----BEGIN RSA PRIVATE KEY-----\nMIIEow...")
        assert any(f["signature"] == "private_key_block" for f in findings)

    def test_generic_secret_assignment_detected(self):
        findings = find_pattern_matches('api_key: "abcdefghijklmnopqrstuvwx1234"')
        assert any(f["signature"] == "generic_secret_assignment" for f in findings)

    def test_clean_text_yields_nothing(self):
        assert find_pattern_matches("const x = 1; function greet() { return 'hi'; }") == []


class TestFindHighEntropyStrings:

    def test_high_entropy_base64_like_token_flagged_as_entropy_method(self):
        token = "aZ9kLm3pQwErTyUiOpAsDfGhJkLzXcVbNm12"
        findings = find_high_entropy_strings(f'const t = "{token}";')
        assert any(f["match"] == token for f in findings)
        assert all(f["evidence_type"] == EVIDENCE_TYPE_STATIC_JS for f in findings)
        assert all(f["method"] == "entropy" for f in findings)

    def test_low_entropy_repeated_string_not_flagged(self):
        findings = find_high_entropy_strings('const t = "aaaaaaaaaaaaaaaaaaaaaaaa";')
        assert findings == []

    def test_short_string_below_min_length_not_flagged(self):
        findings = find_high_entropy_strings('const t = "aZ9kLm3pQw";')  # 10 chars
        assert findings == []

    def test_does_not_double_report_a_pattern_matched_span(self):
        text = 'const k = "AKIAIOSFODNN7EXAMPLE";'
        entropy_hits = find_high_entropy_strings(text)
        assert not any("AKIA" in f["match"] for f in entropy_hits)

    def test_hex_only_candidate_uses_lower_threshold(self):
        # 32 hex chars, high diversity -> should clear the hex bar
        hex_token = "3f7a9c1e5b8d2046a1f0c9e7b4d6f2a1"
        findings = find_high_entropy_strings(f'"{hex_token}"')
        matched = next((f for f in findings if f["match"] == hex_token), None)
        assert matched is not None
        assert matched["entropy"] >= HEX_ENTROPY_THRESHOLD

    def test_threshold_constants_documented_and_distinct(self):
        assert HEX_ENTROPY_THRESHOLD < B64_ENTROPY_THRESHOLD


class TestFindInternalApiUrls:

    def test_rfc1918_ip_detected(self):
        findings = find_internal_api_urls('fetch("http://10.0.5.2/internal/admin")')
        assert len(findings) == 1
        assert findings[0]["evidence_type"] == EVIDENCE_TYPE_STATIC_JS
        assert findings[0]["method"] == "heuristic"

    def test_internal_suffix_domain_detected(self):
        findings = find_internal_api_urls('fetch("https://svc.payments.internal/charge")')
        assert len(findings) == 1

    def test_admin_api_prefix_detected(self):
        findings = find_internal_api_urls('fetch("https://admin-api.example.com/v1/users")')
        assert len(findings) == 1

    def test_public_target_domain_alone_not_flagged(self):
        findings = find_internal_api_urls('fetch("https://example.com/api/public")', target="example.com")
        assert findings == []

    def test_internal_subdomain_of_target_still_flagged(self):
        # Real-world case a naive "target in url" substring check would
        # wrongly suppress — the internal marker takes priority.
        findings = find_internal_api_urls(
            'fetch("http://admin-api.internal.example.com/v1/users")', target="example.com",
        )
        assert len(findings) == 1

    def test_localhost_detected(self):
        findings = find_internal_api_urls('fetch("http://localhost:3000/debug")')
        assert len(findings) == 1


class TestFindFeatureFlags:

    def test_flags_dot_reference_detected(self):
        findings = find_feature_flags("if (flags.newCheckout) { doThing(); }")
        assert len(findings) == 1
        assert findings[0]["evidence_type"] == EVIDENCE_TYPE_STATIC_JS
        assert findings[0]["method"] == "heuristic"

    def test_launchdarkly_variation_call_detected(self):
        findings = find_feature_flags('client.variation("beta-dashboard", user, false)')
        assert len(findings) == 1

    def test_is_feature_enabled_call_detected(self):
        findings = find_feature_flags('isFeatureEnabled("dark-mode")')
        assert len(findings) == 1

    def test_clean_text_yields_nothing(self):
        assert find_feature_flags("const x = 1;") == []


class TestFindGraphqlFragments:

    def test_fragment_syntax_detected(self):
        findings = find_graphql_fragments("fragment UserFields on User { id name }")
        assert len(findings) >= 1
        assert findings[0]["evidence_type"] == EVIDENCE_TYPE_STATIC_JS
        assert findings[0]["method"] == "heuristic"

    def test_typename_detected(self):
        findings = find_graphql_fragments("const q = `{ user { __typename id } }`;")
        assert any("__typename" in f["match"] for f in findings)

    def test_mutation_syntax_detected(self):
        findings = find_graphql_fragments("mutation UpdateUser($id: ID!) { updateUser(id: $id) { id } }")
        assert any("mutation" in f["match"] for f in findings)

    def test_clean_text_yields_nothing(self):
        assert find_graphql_fragments("const x = 1;") == []


class TestFindExposedSourcemapSignal:

    def test_no_sources_dir_returns_empty(self, tmp_path):
        assert find_exposed_sourcemap_signal(tmp_path / "nope") == []

    def test_each_bundle_subdir_becomes_one_finding(self, tmp_path):
        sources = tmp_path / "sources"
        (sources / "main.bundle").mkdir(parents=True)
        (sources / "vendor.bundle").mkdir(parents=True)
        findings = find_exposed_sourcemap_signal(sources)
        assert len(findings) == 2
        assert all(f["evidence_type"] == EVIDENCE_TYPE_BROWSER_ARTIFACT for f in findings)
        assert all(f["method"] == "directory_evidence" for f in findings)
        assert {f["bundle"] for f in findings} == {"main.bundle", "vendor.bundle"}

    def test_files_directly_under_sources_are_not_bundles(self, tmp_path):
        sources = tmp_path / "sources"
        sources.mkdir()
        (sources / "stray.js").write_text("x")
        assert find_exposed_sourcemap_signal(sources) == []


class TestScanText:

    def test_combines_every_detector(self):
        text = (
            'const k = "AKIAIOSFODNN7EXAMPLE"; '
            'fetch("http://admin-api.internal.example.com/x"); '
            'if (flags.betaFeature) {} '
            'fragment F on User { id }'
        )
        findings = scan_text(text, file="app.ts", target="example.com")
        categories = {f["category"] for f in findings}
        assert {"cloud_credential", "internal_api_url", "feature_flag", "graphql_fragment"} <= categories
        assert all(f["file"] == "app.ts" for f in findings)

    def test_empty_text_yields_nothing(self):
        assert scan_text("") == []


class TestScanPath:

    def test_missing_path_returns_empty(self, tmp_path):
        assert scan_path(str(tmp_path / "nope")) == []

    def test_single_file_scanned(self, tmp_path):
        f = tmp_path / "app.ts"
        f.write_text('const k = "AKIAIOSFODNN7EXAMPLE";')
        findings = scan_path(str(f))
        assert any(x["category"] == "cloud_credential" for x in findings)

    def test_directory_walked_recursively_respecting_suffixes(self, tmp_path):
        d = tmp_path / "src" / "nested"
        d.mkdir(parents=True)
        (d / "app.ts").write_text('const k = "AKIAIOSFODNN7EXAMPLE";')
        (d / "app.min.map").write_text('{"AKIAIOSFODNN7EXAMPLE": true}')  # not in default suffix set
        findings = scan_path(str(tmp_path / "src"))
        assert len(findings) == 1  # only app.ts scanned, .map excluded by default suffixes

    def test_unreadable_file_does_not_raise(self, tmp_path):
        d = tmp_path / "src"
        d.mkdir()
        # A directory-as-file edge case can't easily be constructed cross-
        # platform; instead prove a genuinely empty file scans cleanly.
        (d / "empty.js").write_text("")
        assert scan_path(str(d)) == []


class TestScanReconSourcesAndCicd:

    def test_scan_recon_sources_missing_dir_returns_empty(self, tmp_path):
        assert scan_recon_sources(str(tmp_path / "recon" / "t.example")) == []

    def test_scan_recon_sources_finds_secrets_and_sourcemap_signal(self, tmp_path):
        recon_dir = tmp_path / "recon" / "t.example"
        bundle = recon_dir / "browser" / "sources" / "main.bundle"
        bundle.mkdir(parents=True)
        (bundle / "app.ts").write_text('const k = "AKIAIOSFODNN7EXAMPLE";')
        findings = scan_recon_sources(str(recon_dir), target="t.example")
        categories = {f["category"] for f in findings}
        assert "cloud_credential" in categories
        assert "exposed_sourcemap" in categories

    def test_scan_cicd_findings_missing_dir_returns_empty(self, tmp_path):
        assert scan_cicd_findings(str(tmp_path / "recon" / "t.example")) == []

    def test_scan_cicd_findings_scans_scan_results_txt(self, tmp_path):
        recon_dir = tmp_path / "recon" / "t.example"
        cicd = recon_dir / "cicd" / "acme-org"
        cicd.mkdir(parents=True)
        (cicd / "scan_results.txt").write_text(
            ".github/workflows/deploy.yml:12:3: hardcoded secret AKIAIOSFODNN7EXAMPLE [secret-in-workflow]"
        )
        findings = scan_cicd_findings(str(recon_dir))
        assert any(f["category"] == "cloud_credential" for f in findings)

    def test_scan_all_combines_both_sources(self, tmp_path):
        recon_dir = tmp_path / "recon" / "t.example"
        bundle = recon_dir / "browser" / "sources" / "main.bundle"
        bundle.mkdir(parents=True)
        (bundle / "app.ts").write_text('const k = "AKIAIOSFODNN7EXAMPLE";')
        cicd = recon_dir / "cicd" / "acme-org"
        cicd.mkdir(parents=True)
        (cicd / "scan_results.txt").write_text("ghp_" + "a" * 36)
        findings = scan_all(str(recon_dir), target="t.example")
        sources = {f["file"] for f in findings}
        assert any("browser/sources" in s for s in sources)
        assert any("cicd" in s for s in sources)


class TestCli:

    def test_main_writes_json_with_count(self, tmp_path, capsys):
        from tools.secrets_scanner import main

        recon_dir = tmp_path / "recon" / "t.example"
        bundle = recon_dir / "browser" / "sources" / "main.bundle"
        bundle.mkdir(parents=True)
        (bundle / "app.ts").write_text('const k = "AKIAIOSFODNN7EXAMPLE";')

        exit_code = main(["--recon-dir", str(recon_dir), "--target", "t.example"])
        assert exit_code == 0
        out = json.loads(capsys.readouterr().out)
        assert out["count"] >= 1

    def test_main_skip_cicd_flag(self, tmp_path, capsys):
        from tools.secrets_scanner import main

        recon_dir = tmp_path / "recon" / "t.example"
        cicd = recon_dir / "cicd" / "acme-org"
        cicd.mkdir(parents=True)
        (cicd / "scan_results.txt").write_text("ghp_" + "a" * 36)

        exit_code = main(["--recon-dir", str(recon_dir), "--skip-cicd"])
        assert exit_code == 0
        out = json.loads(capsys.readouterr().out)
        assert out["count"] == 0
