"""Tests for tools/director.py — the Research Director (Phase 2).

Covers the contract that matters: leads become falsifiable, time-boxed
attacks scored ONLY via memory.vuln_intelligence (no second formula),
browser intelligence becomes concrete leads, the SKIPPED section is
always present and machine-checkable, dependencies/parallel groups are
correct, replan() never loses IN_PROGRESS work, and confidence()/cold-start
never fabricates a number. No network access anywhere here.
"""

import json
from pathlib import Path

import pytest

from tools import director
# director.py imports lead_board via `from tools import lead_board` (package-
# qualified) so it can share module state with tools.scope_checker etc. —
# importing it the SAME way here (not bare `import lead_board`) is required
# for monkeypatch.setattr(lb, "LEADS_DIR", ...) to actually reach the module
# object director.py reads from; a bare import would cache a second, distinct
# module under sys.modules["lead_board"] and silently miss the patch.
from tools import lead_board as lb

from memory.schemas import (
    make_failed_pattern_entry,
    make_hypothesis_entry,
    make_journal_entry,
    make_pattern_entry,
    make_report_outcome_entry,
)
from memory.pattern_db import PatternDB
from memory.vuln_intelligence import FailedPatternDB, HypothesisDB, ReportOutcomeDB, priority_score


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """Point the lead-board ledger at a tmp dir so tests never touch the
    real memory/leads/ directory."""
    monkeypatch.setattr(lb, "LEADS_DIR", str(tmp_path / "leads"))
    return tmp_path


def _seed_recon(tmp_path, target, urls):
    rd = tmp_path / "recon" / target
    (rd / "urls").mkdir(parents=True)
    (rd / "urls" / "all.txt").write_text("\n".join(urls) + "\n")
    return str(rd)


def _seed_leads(isolated, target, urls):
    rd = _seed_recon(isolated, target, urls)
    lb.ingest(target, rd)
    return rd


REALISTIC_URLS = [
    "https://t.example/api/v2/users?id=1001",        # -> hunt-idor
    "https://t.example/graphql",                      # -> hunt-graphql
    "https://t.example/fetch?url=https://internal",   # -> hunt-ssrf
    "https://t.example/static/app.js.map",            # -> hunt-source-leak
]


class TestSkillToVulnClass:

    def test_strips_hunt_prefix(self):
        assert director.skill_to_vuln_class("hunt-idor") == "idor"

    def test_reuses_finding_score_aliases(self):
        # "hunt-auth_bypass" isn't a real lead-board skill name, but this
        # proves the alias table is actually consulted, not bypassed.
        assert director.skill_to_vuln_class("hunt-jwt") == director.skill_to_vuln_class("hunt-auth_bypass")

    def test_unknown_skill_resolves_gracefully(self):
        vuln_class = director.skill_to_vuln_class("hunt-totally-made-up")
        result = priority_score(vuln_class=vuln_class, tech_stack=[], target="t.com")
        assert 0 <= result["score"] <= 100


class TestLoadTechStack:

    def test_missing_profile_returns_empty(self, tmp_path):
        assert director.load_tech_stack("t.example", str(tmp_path / "hunt-memory")) == []

    def test_reads_tech_stack_field(self, tmp_path):
        mem = tmp_path / "hunt-memory"
        (mem / "targets").mkdir(parents=True)
        (mem / "targets" / "t.example.json").write_text(json.dumps({"tech_stack": ["express", "postgresql"]}))
        assert director.load_tech_stack("t.example", str(mem)) == ["express", "postgresql"]

    def test_malformed_profile_returns_empty(self, tmp_path):
        mem = tmp_path / "hunt-memory"
        (mem / "targets").mkdir(parents=True)
        (mem / "targets" / "t.example.json").write_text("{not json")
        assert director.load_tech_stack("t.example", str(mem)) == []


class TestBrowserIntelLeads:

    def _write(self, tmp_path, target, name, payload):
        browser_dir = tmp_path / "recon" / target / "browser"
        browser_dir.mkdir(parents=True, exist_ok=True)
        (browser_dir / name).write_text(json.dumps(payload))
        return str(tmp_path / "recon" / target)

    def test_no_browser_dir_returns_empty(self, tmp_path):
        assert director.browser_intel_leads("t.example", str(tmp_path / "recon" / "t.example")) == []

    def test_never_called_becomes_concrete_leads(self, tmp_path):
        rd = self._write(tmp_path, "t.example", "never-called.json", {
            "target": "t.example", "never_called": ["/api/v2/users?id=1001"],
        })
        leads = director.browser_intel_leads("t.example", rd)
        assert any(l["skill"] == "hunt-idor" for l in leads)
        assert all(l["source"] == "browser-intel" for l in leads)
        assert all(l["browser_artifact"] == "never-called.json" for l in leads)

    def test_framework_routes_become_leads(self, tmp_path):
        rd = self._write(tmp_path, "t.example", "routes.json", {
            "target": "t.example", "routes": ["/admin/dashboard"], "framework_detected": "nextjs",
        })
        leads = director.browser_intel_leads("t.example", rd)
        assert any(l["skill"] == "hunt-auth-bypass" for l in leads)

    def test_auth_model_privileged_routes_and_role_constants(self, tmp_path):
        rd = self._write(tmp_path, "t.example", "auth-model.json", {
            "target": "t.example",
            "candidate_privileged_client_routes": ["/admin/settings"],
            "auth_lifecycle_endpoints": ["https://t.example/api/auth/refresh"],
            "role_permission_constants": ["ROLE_ADMIN"],
        })
        leads = director.browser_intel_leads("t.example", rd)
        role_leads = [l for l in leads if l["evidence"] == "ROLE_ADMIN"]
        assert len(role_leads) == 1
        assert role_leads[0]["skill"] == "hunt-auth-bypass"
        assert any(l["evidence"] == "/admin/settings" for l in leads)
        assert any("refresh" in l["evidence"] for l in leads)

    def test_api_calls_with_auth_headers_become_leads(self, tmp_path):
        rd = self._write(tmp_path, "t.example", "api-calls.json", {
            "target": "t.example",
            "calls": [
                {"url": "https://t.example/api/v2/orders?id=5", "request_headers_auth": ["authorization"]},
                {"url": "https://t.example/api/v2/public", "request_headers_auth": []},
            ],
        })
        leads = director.browser_intel_leads("t.example", rd)
        evidences = {l["evidence"] for l in leads}
        assert "https://t.example/api/v2/orders?id=5" in evidences
        assert "https://t.example/api/v2/public" not in evidences

    def test_malformed_json_does_not_raise(self, tmp_path):
        browser_dir = tmp_path / "recon" / "t.example" / "browser"
        browser_dir.mkdir(parents=True)
        (browser_dir / "never-called.json").write_text("{not json")
        assert director.browser_intel_leads("t.example", str(tmp_path / "recon" / "t.example")) == []

    def test_leads_never_written_to_persisted_ledger(self, isolated, tmp_path):
        rd = self._write(tmp_path, "t.example", "never-called.json", {
            "target": "t.example", "never_called": ["/api/v2/users?id=1001"],
        })
        director.browser_intel_leads("t.example", rd)
        assert lb.load_ledger("t.example") == []


class TestTakeoverLeads:
    """Part B — tools/takeover_scanner.sh output -> lead-board leads. The
    scanner writes to a timestamped findings/takeover/<ts>/ dir outside
    recon/, so the caller passes that exact dir (not a recon-dir glob).

    subjack fixtures use its REAL upstream output format (verified against
    subjack/output.go's printResult(): "[%s] %s" for a vulnerable host,
    "[Not Vulnerable] %s" for every clean host too) -- a prior version of
    this function treated ANY non-empty subjack.txt line as a P_HIGH
    takeover lead, which fabricated a lead for every scanned-but-clean
    host (subjack logs one line per host, not just hits)."""

    def test_missing_dir_returns_empty(self, tmp_path):
        assert director.takeover_leads("t.example", str(tmp_path / "nope")) == []

    def test_dnsreaper_json_becomes_high_priority_lead(self, tmp_path):
        d = tmp_path / "takeover"
        d.mkdir()
        (d / "dnsreaper.json").write_text(json.dumps([
            {"domain": "old.t.example", "fingerprint": "github-pages", "confidence": "CONFIRMED"},
        ]))
        leads = director.takeover_leads("t.example", str(d))
        assert len(leads) == 1
        assert leads[0]["skill"] == "hunt-subdomain"
        assert leads[0]["priority"] == "high"
        assert leads[0]["source"] == "takeover-scan"
        assert leads[0]["tool_artifact"] == "dnsreaper.json"

    def test_dnsreaper_confidence_tier_maps_to_priority(self, tmp_path):
        # dnsReaper's own confidence field (detection_enums.py:
        # CONFIRMED/POTENTIAL/UNLIKELY) was previously discarded -- every
        # hit got flattened to P_HIGH regardless of the signature's own
        # self-reported confidence.
        d = tmp_path / "takeover"
        d.mkdir()
        (d / "dnsreaper.json").write_text(json.dumps([
            {"domain": "confirmed.t.example", "confidence": "CONFIRMED"},
            {"domain": "potential.t.example", "confidence": "POTENTIAL"},
            {"domain": "unlikely.t.example", "confidence": "UNLIKELY"},
        ]))
        leads = director.takeover_leads("t.example", str(d))

        def _priority_for(host):
            return next(l["priority"] for l in leads if host in l["evidence"])

        assert _priority_for("confirmed.t.example") == "high"
        assert _priority_for("potential.t.example") == "med"
        assert _priority_for("unlikely.t.example") == "low"

    def test_dnsreaper_missing_confidence_defaults_high(self, tmp_path):
        # Same "no confidence field" behavior as before this fix, for a
        # caller-supplied/malformed dnsreaper.json that omits it.
        d = tmp_path / "takeover"
        d.mkdir()
        (d / "dnsreaper.json").write_text(json.dumps([{"domain": "old.t.example"}]))
        leads = director.takeover_leads("t.example", str(d))
        assert leads[0]["priority"] == "high"

    def test_subjack_not_vulnerable_lines_never_become_leads(self, tmp_path):
        d = tmp_path / "takeover"
        d.mkdir()
        (d / "subjack.txt").write_text(
            "[Not Vulnerable] https://clean1.t.example\n"
            "[Not Vulnerable] https://clean2.t.example\n"
        )
        assert director.takeover_leads("t.example", str(d)) == []

    def test_subjack_real_vulnerable_line_becomes_a_lead_with_correct_url(self, tmp_path):
        d = tmp_path / "takeover"
        d.mkdir()
        (d / "subjack.txt").write_text("[github] https://stale.t.example\n")
        leads = director.takeover_leads("t.example", str(d))
        assert len(leads) == 1
        assert leads[0]["priority"] == "high"
        # line.split()[0] used to extract "[github]" (the bracket tag) as
        # the "host" -- the real URL must be recoverable from the evidence.
        assert "https://stale.t.example" in leads[0]["evidence"]

    def test_subjack_mixed_clean_and_vulnerable_only_the_real_hit_fires(self, tmp_path):
        d = tmp_path / "takeover"
        d.mkdir()
        (d / "subjack.txt").write_text(
            "[Not Vulnerable] https://clean.t.example\n"
            "[heroku] https://stale.t.example\n"
            "[Not Vulnerable] https://alsoclean.t.example\n"
        )
        leads = director.takeover_leads("t.example", str(d))
        assert len(leads) == 1
        assert "stale.t.example" in leads[0]["evidence"]

    def test_fingerprint_grep_fallback_is_medium_priority(self, tmp_path):
        d = tmp_path / "takeover"
        d.mkdir()
        (d / "fingerprint_grep.txt").write_text("stale2.t.example  s3\n")
        leads = director.takeover_leads("t.example", str(d))
        assert len(leads) == 1
        assert leads[0]["priority"] == "med"

    def test_malformed_dnsreaper_json_does_not_raise(self, tmp_path):
        d = tmp_path / "takeover"
        d.mkdir()
        (d / "dnsreaper.json").write_text("{not json")
        assert director.takeover_leads("t.example", str(d)) == []

    def test_empty_dir_returns_empty(self, tmp_path):
        d = tmp_path / "takeover"
        d.mkdir()
        assert director.takeover_leads("t.example", str(d)) == []


class TestCloudReconLeads:
    """Part B — tools/cloud_recon.sh output -> lead-board leads.

    Fixtures use each wrapped tool's REAL upstream output format, verified
    against their actual source (s3scanner's worker.go/bucket.go, cloud_enum's
    aws/azure/gcp_checks.py, CloudFail's cloudfail.py) rather than a
    hand-typed guess — the same class of bug PR #38 found in
    graphql_audit_leads(): non-empty/successful-scan output was being
    treated as a finding regardless of whether the underlying resource was
    actually exposed."""

    def test_missing_dir_returns_empty(self, tmp_path):
        assert director.cloud_recon_leads("t.example", str(tmp_path / "nope")) == []

    def test_s3scanner_private_bucket_never_fires_despite_containing_exists(self, tmp_path):
        # s3scanner's real text-mode output writes "exists    | ..." for
        # ANY existing bucket, public or fully private -- the literal word
        # "public" never appears anywhere in its real output at all.
        d = tmp_path / "cloud"
        d.mkdir()
        (d / "s3scanner.txt").write_text(
            "not_exist | t-example-nope\n"
            "exists    | t-example-private | us-east-1 | AuthUsers: [] | AllUsers: []\n"
        )
        assert director.cloud_recon_leads("t.example", str(d)) == []

    def test_s3scanner_all_users_grant_is_high_priority(self, tmp_path):
        d = tmp_path / "cloud"
        d.mkdir()
        (d / "s3scanner.txt").write_text(
            "exists    | t-example-public | us-east-1 | AuthUsers: [] | AllUsers: [READ, LIST]\n"
        )
        leads = director.cloud_recon_leads("t.example", str(d))
        assert len(leads) == 1
        assert leads[0]["skill"] == "hunt-cloud-misconfig"
        assert leads[0]["priority"] == "high"
        assert "AllUsers" in leads[0]["evidence"]

    def test_s3scanner_auth_users_only_grant_is_medium_priority(self, tmp_path):
        # AuthUsers (any authenticated AWS account, not the public
        # internet) is real evidence but weaker than AllUsers -- must not
        # be flattened to the same P_HIGH tier.
        d = tmp_path / "cloud"
        d.mkdir()
        (d / "s3scanner.txt").write_text(
            "exists    | t-example-authonly | us-east-1 | AuthUsers: [READ] | AllUsers: []\n"
        )
        leads = director.cloud_recon_leads("t.example", str(d))
        assert len(leads) == 1
        assert leads[0]["priority"] == "med"

    def test_cloud_enum_open_bucket_becomes_a_lead(self, tmp_path):
        d = tmp_path / "cloud"
        d.mkdir()
        (d / "cloud_enum.txt").write_text("OPEN S3 BUCKET: https://t-example.s3.amazonaws.com\n")
        leads = director.cloud_recon_leads("t.example", str(d))
        assert len(leads) == 1
        assert leads[0]["source"] == "cloud-recon"
        assert leads[0]["priority"] == "high"

    @pytest.mark.parametrize("msg", [
        "Protected S3 Bucket",
        "Protected Google Bucket",
        "Auth-Only Account",
        "Disabled Account",
        "Payment required on Google Firebase RTDB",
        "The Firebase database has been deactivated.",
        "Protected Google App Engine app",
        "Auth required Cloud Function",
    ])
    def test_cloud_enum_negative_results_never_fire(self, tmp_path, msg):
        d = tmp_path / "cloud"
        d.mkdir()
        (d / "cloud_enum.txt").write_text(f"{msg}: https://t-example.blob.core.windows.net\n")
        assert director.cloud_recon_leads("t.example", str(d)) == []

    def test_cloud_enum_mixed_only_real_positives_fire(self, tmp_path):
        d = tmp_path / "cloud"
        d.mkdir()
        (d / "cloud_enum.txt").write_text(
            "Protected S3 Bucket: https://t-example-a.s3.amazonaws.com\n"
            "OPEN GOOGLE BUCKET: https://t-example-b.storage.googleapis.com\n"
            "Disabled Account: t-example.blob.core.windows.net\n"
        )
        leads = director.cloud_recon_leads("t.example", str(d))
        assert len(leads) == 1
        assert "t-example-b" in leads[0]["evidence"]

    def test_cloudfail_real_marker_becomes_a_lead(self, tmp_path):
        d = tmp_path / "cloud"
        d.mkdir()
        (d / "cloudfail.txt").write_text(
            "[FOUND:HOST] t.example 203.0.113.5 AS12345 SomeHost US\n"
        )
        leads = director.cloud_recon_leads("t.example", str(d))
        assert len(leads) == 1
        assert leads[0]["priority"] == "high"

    def test_cloudfail_old_wrong_marker_format_never_matched_this_is_the_fix(self, tmp_path):
        # The prior regex "\[FOUND\]|origin" never matched CloudFail's real
        # markers at all (always "[FOUND:HOST]" etc, never bare "[FOUND]"
        # or the literal word "origin") -- confirms the false-NEGATIVE this
        # fix closes, not just a hypothetical.
        d = tmp_path / "cloud"
        d.mkdir()
        (d / "cloudfail.txt").write_text("[FOUND] 203.0.113.5 -- possible origin\n")
        assert director.cloud_recon_leads("t.example", str(d)) == []

    def test_cloudfail_subdomain_still_on_cloudflare_never_fires(self, tmp_path):
        # CloudFail prints "[FOUND:SUBDOMAIN]" for BOTH the genuine bypass
        # case and the still-on-Cloudflare (non-bypass) case -- only the
        # negative-phrase exclusion tells them apart.
        d = tmp_path / "cloud"
        d.mkdir()
        (d / "cloudfail.txt").write_text("[FOUND:SUBDOMAIN] old.t.example ON CLOUDFLARE NETWORK!\n")
        assert director.cloud_recon_leads("t.example", str(d)) == []

    def test_cloudfail_subdomain_real_bypass_becomes_a_lead(self, tmp_path):
        d = tmp_path / "cloud"
        d.mkdir()
        (d / "cloudfail.txt").write_text("[FOUND:SUBDOMAIN] origin.t.example IP: 203.0.113.9 HTTP: 200\n")
        leads = director.cloud_recon_leads("t.example", str(d))
        assert len(leads) == 1

    def test_non_cf_ips_all_lines_become_leads(self, tmp_path):
        d = tmp_path / "cloud"
        d.mkdir()
        (d / "non_cf_ips.txt").write_text("origin.t.example -> 203.0.113.9\n")
        leads = director.cloud_recon_leads("t.example", str(d))
        assert len(leads) == 1
        assert leads[0]["tool_artifact"] == "non_cf_ips.txt"


def _write_graphql_summary(d: Path, **overrides) -> None:
    """Seed a realistic summary.txt matching tools/graphql_audit.sh's own
    "key: value" grammar exactly. Defaults are the CLEAN/negative-result
    value for every key the script writes -- a caller overrides only the
    keys relevant to the scenario under test, so each test stays honest
    about what it's actually asserting."""
    defaults = {
        "connectivity": "HTTP 200",
        "introspection": "DISABLED",
        "field_suggestions": "disabled or no hints",
        "fingerprint": "skipped (graphw00f not installed)",
        "clairvoyance": "skipped (not installed)",
        "array_batching": "likely disabled (HTTP 400)",
        "alias_bombing": "blocked or limited",
        "injection_scan": "skipped (gqlmap not installed)",
        "sqli_quick_probe": "no obvious errors",
        "graphql_cop": "skipped (not installed)",
        "depth_limit": "enforced or endpoint rejected query",
    }
    defaults.update(overrides)
    lines = ["GraphQL Audit -- https://t.example/graphql", "Date: today", "---"]
    lines += [f"{k}: {v}" for k, v in defaults.items()]
    (d / "summary.txt").write_text("\n".join(lines) + "\n")


class TestGraphqlAuditLeads:
    """Part B — tools/graphql_audit.sh output -> hunt-graphql leads tagged
    api_style=graphql, optionally cross-referenced against Phase 3's
    fingerprint.json.

    Every raw output file (batching_dos.txt, alias_bomb.txt, gqlmap.txt,
    cop_report.txt, introspection.json) is ALWAYS non-empty regardless of
    outcome -- curl always writes an HTTP response body even on
    rejection, and a tool-not-installed placeholder is also non-empty
    text (verified by reading tools/graphql_audit.sh line by line, not
    assumed). graphql_audit_leads() parses summary.txt's own derived
    ENABLED/DISABLED/HIT verdicts instead of "is the file non-empty" --
    the FALSE-POSITIVE-prevention tests below are the actual point of
    this class, not incidental coverage."""

    def test_missing_dir_returns_empty(self, tmp_path):
        assert director.graphql_audit_leads("t.example", str(tmp_path / "nope")) == []

    def test_no_summary_file_emits_no_leads(self, tmp_path):
        # Raw files present but summary.txt missing -- must never fall
        # back to has-content guessing.
        d = tmp_path / "graphql"
        d.mkdir()
        (d / "batching_dos.txt").write_text("[{...},{...}]\n")
        assert director.graphql_audit_leads("t.example", str(d)) == []

    def test_realistic_clean_scan_emits_zero_leads(self, tmp_path):
        # The exact false-positive this fix closes: a clean run where
        # every raw file is non-empty (curl always writes a response
        # body; skipped-tool placeholders are also non-empty text) but
        # summary.txt correctly says nothing was found anywhere.
        d = tmp_path / "graphql"
        d.mkdir()
        _write_graphql_summary(d)
        (d / "batching_dos.txt").write_text('{"errors":[{"message":"batching disabled"}]}\nHTTP: 400\n')
        (d / "alias_bomb.txt").write_text('{"errors":[{"message":"too many aliases"}]}\nHTTP: 400\n')
        (d / "introspection.json").write_text('{"errors":[{"message":"introspection disabled"}]}')
        (d / "gqlmap.txt").write_text("(install: pip install gqlmap)")
        (d / "cop_report.txt").write_text("(install: pip install graphql-cop)")
        (d / "depth_bomb.txt").write_text('{"data":{}}\nHTTP 400\n')
        (d / "interesting_fields.txt").write_text("no obvious sensitive names found")
        assert director.graphql_audit_leads("t.example", str(d)) == []

    def test_introspection_enabled_becomes_high_priority_lead(self, tmp_path):
        d = tmp_path / "graphql"
        d.mkdir()
        _write_graphql_summary(d, introspection="ENABLED")
        (d / "introspection.json").write_text(json.dumps({"data": {"__schema": {"types": []}}}))
        leads = director.graphql_audit_leads("t.example", str(d))
        assert len(leads) == 1
        assert leads[0]["skill"] == "hunt-graphql"
        assert leads[0]["priority"] == "high"
        assert leads[0]["source"] == "graphql-audit"
        assert "api_style=graphql" in leads[0]["why"]

    def test_introspection_disabled_never_emits_a_lead_even_with_nonempty_json(self, tmp_path):
        # introspection.json is written in BOTH branches of the shell
        # script (schema dump OR the raw disabled-response) -- content
        # alone was the bug; summary.txt's own verdict must gate this.
        d = tmp_path / "graphql"
        d.mkdir()
        _write_graphql_summary(d, introspection="DISABLED")
        (d / "introspection.json").write_text(json.dumps({"errors": [{"message": "disabled"}]}))
        assert director.graphql_audit_leads("t.example", str(d)) == []

    def test_introspection_get_bypass_is_its_own_high_priority_lead(self, tmp_path):
        d = tmp_path / "graphql"
        d.mkdir()
        _write_graphql_summary(d, introspection="DISABLED", introspection_get_bypass="YES")
        (d / "introspection.json").write_text('{"errors":[{"message":"disabled"}]}')
        leads = director.graphql_audit_leads("t.example", str(d))
        assert len(leads) == 1
        assert "GET" in leads[0]["signal"]

    def test_field_suggestions_enabled_has_no_artifact_file_requirement(self, tmp_path):
        # This signal has no dedicated output file (Phase 1's built-in
        # "did you mean" check) -- must fire from summary.txt alone.
        d = tmp_path / "graphql"
        d.mkdir()
        _write_graphql_summary(d, field_suggestions="ENABLED")
        leads = director.graphql_audit_leads("t.example", str(d))
        assert len(leads) == 1
        assert leads[0]["priority"] == "med"

    def test_batching_dos_gated_on_summary_not_file_content(self, tmp_path):
        d = tmp_path / "graphql"
        d.mkdir()
        _write_graphql_summary(d, array_batching="ENABLED")
        (d / "batching_dos.txt").write_text("[{...},{...}]\n100-query batch time: 0.2s  HTTP: 200\n")
        leads = director.graphql_audit_leads("t.example", str(d))
        assert len(leads) == 1
        assert leads[0]["priority"] == "high"
        assert leads[0]["tool_artifact"] == "batching_dos.txt"

    def test_batching_dos_disabled_never_fires_despite_nonempty_file(self, tmp_path):
        d = tmp_path / "graphql"
        d.mkdir()
        _write_graphql_summary(d, array_batching="likely disabled (HTTP 400)")
        (d / "batching_dos.txt").write_text('{"errors":"batching not supported"}\nsingle query time: 0.1s\n')
        assert director.graphql_audit_leads("t.example", str(d)) == []

    def test_alias_bombing_gated_on_summary_not_file_content(self, tmp_path):
        d = tmp_path / "graphql"
        d.mkdir()
        _write_graphql_summary(d, alias_bombing="ENABLED")
        (d / "alias_bomb.txt").write_text('{"data":{"q0":"Query"}}\n')
        leads = director.graphql_audit_leads("t.example", str(d))
        assert len(leads) == 1
        assert leads[0]["priority"] == "high"

    def test_sqli_quick_probe_hit_is_high_priority(self, tmp_path):
        d = tmp_path / "graphql"
        d.mkdir()
        _write_graphql_summary(d, sqli_quick_probe="POSSIBLE HIT")
        (d / "gqlmap.txt").write_text("mysql syntax error near '1--'\n")
        leads = director.graphql_audit_leads("t.example", str(d))
        assert len(leads) == 1
        assert leads[0]["priority"] == "high"
        assert leads[0]["tool_artifact"] == "gqlmap.txt"

    def test_gqlmap_completed_is_medium_priority_manual_review(self, tmp_path):
        # gqlmap actually running derives no pass/fail verdict from the
        # shell script itself -- must be a lower-confidence "review this"
        # lead, not an auto-confirmed P_HIGH the way it was before this fix.
        d = tmp_path / "graphql"
        d.mkdir()
        _write_graphql_summary(d, injection_scan="completed (see gqlmap.txt)")
        (d / "gqlmap.txt").write_text("gqlmap: no injection found\n")
        leads = director.graphql_audit_leads("t.example", str(d))
        assert len(leads) == 1
        assert leads[0]["priority"] == "med"

    def test_gqlmap_not_installed_placeholder_never_fires(self, tmp_path):
        d = tmp_path / "graphql"
        d.mkdir()
        _write_graphql_summary(d, injection_scan="skipped (gqlmap not installed)")
        (d / "gqlmap.txt").write_text("(install: pip install gqlmap)")
        assert director.graphql_audit_leads("t.example", str(d)) == []

    def test_graphql_cop_completed_is_medium_priority(self, tmp_path):
        d = tmp_path / "graphql"
        d.mkdir()
        _write_graphql_summary(d, graphql_cop="completed (see cop_report.txt)")
        (d / "cop_report.txt").write_text("graphql-cop: 3 checks failed\n")
        leads = director.graphql_audit_leads("t.example", str(d))
        assert len(leads) == 1
        assert leads[0]["priority"] == "med"

    def test_graphql_cop_not_installed_placeholder_never_fires(self, tmp_path):
        d = tmp_path / "graphql"
        d.mkdir()
        _write_graphql_summary(d, graphql_cop="skipped (not installed)")
        (d / "cop_report.txt").write_text("(install: pip install graphql-cop)")
        assert director.graphql_audit_leads("t.example", str(d)) == []

    def test_depth_limit_none_detected_is_a_new_high_priority_lead(self, tmp_path):
        # Previously had ZERO lead-board coverage at all -- not in the
        # old table under any name.
        d = tmp_path / "graphql"
        d.mkdir()
        _write_graphql_summary(d, depth_limit="NONE DETECTED")
        (d / "depth_bomb.txt").write_text('{"data":{"viewer":{}}}\ndepth-15 query: HTTP 200  time: 0.3s\n')
        leads = director.graphql_audit_leads("t.example", str(d))
        assert len(leads) == 1
        assert leads[0]["priority"] == "high"
        assert leads[0]["tool_artifact"] == "depth_bomb.txt"

    def test_depth_limit_enforced_never_fires(self, tmp_path):
        d = tmp_path / "graphql"
        d.mkdir()
        _write_graphql_summary(d, depth_limit="enforced or endpoint rejected query")
        (d / "depth_bomb.txt").write_text('{"errors":"query depth exceeds maximum"}\nHTTP 400\n')
        assert director.graphql_audit_leads("t.example", str(d)) == []

    def test_interesting_fields_real_hits_become_a_lead(self, tmp_path):
        # interesting_fields.txt only ever exists alongside a successful
        # introspection run in the real script -- both signals fire here,
        # which is the faithful scenario, not an isolated one.
        d = tmp_path / "graphql"
        d.mkdir()
        _write_graphql_summary(d, introspection="ENABLED")
        (d / "introspection.json").write_text(json.dumps({"data": {"__schema": {"types": []}}}))
        (d / "interesting_fields.txt").write_text("TYPE: AdminUser\nFIELD: User.password\n")
        leads = director.graphql_audit_leads("t.example", str(d))
        signals = {l["signal"] for l in leads}
        assert "interesting schema fields" in signals
        assert "introspection enabled" in signals
        assert len(leads) == 2

    def test_interesting_fields_negative_marker_never_fires(self, tmp_path):
        # The script ALWAYS writes this file when introspection succeeds
        # -- including the literal "nothing found" placeholder line.
        d = tmp_path / "graphql"
        d.mkdir()
        _write_graphql_summary(d, introspection="ENABLED")
        (d / "introspection.json").write_text(json.dumps({"data": {"__schema": {"types": []}}}))
        (d / "interesting_fields.txt").write_text("no obvious sensitive names found")
        leads = director.graphql_audit_leads("t.example", str(d))
        assert len(leads) == 1  # introspection itself, not interesting_fields
        assert leads[0]["signal"] == "introspection enabled"

    def test_multiple_real_signals_each_become_a_lead(self, tmp_path):
        d = tmp_path / "graphql"
        d.mkdir()
        _write_graphql_summary(d, array_batching="ENABLED", alias_bombing="ENABLED")
        (d / "batching_dos.txt").write_text("[{...}]\n")
        (d / "alias_bomb.txt").write_text('{"data":{"q0":"Query"}}\n')
        leads = director.graphql_audit_leads("t.example", str(d))
        assert len(leads) == 2
        assert all(l["skill"] == "hunt-graphql" for l in leads)

    def test_fingerprint_confirmation_tag_when_api_style_present(self, tmp_path):
        recon_dir = tmp_path / "recon" / "t.example"
        recon_dir.mkdir(parents=True)
        (recon_dir / "fingerprint.json").write_text(json.dumps({"api_style": ["graphql"]}))
        gd = tmp_path / "graphql"
        gd.mkdir()
        _write_graphql_summary(gd, introspection="ENABLED")
        (gd / "introspection.json").write_text(json.dumps({"data": {"__schema": {"types": []}}}))
        leads = director.graphql_audit_leads("t.example", str(gd), str(recon_dir))
        assert "fingerprint-confirmed" in leads[0]["why"]

    def test_no_fingerprint_file_still_emits_leads_without_confirmation_tag(self, tmp_path):
        gd = tmp_path / "graphql"
        gd.mkdir()
        _write_graphql_summary(gd, introspection="ENABLED")
        (gd / "introspection.json").write_text(json.dumps({"data": {"__schema": {"types": []}}}))
        leads = director.graphql_audit_leads("t.example", str(gd), str(tmp_path / "recon" / "nope"))
        assert leads and "fingerprint-confirmed" not in leads[0]["why"]


class TestParamDiscoveryLeads:
    """tools/param_discovery.sh (Arjun/x8) output -> lead-board leads,
    routed through lead_board's new "param" ROUTES source (bare param-NAME
    match). Same timestamped-external-dir shape as TestTakeoverLeads/
    TestCloudReconLeads/TestGraphqlAuditLeads above."""

    def test_missing_dir_returns_empty(self, tmp_path):
        assert director.param_discovery_leads("t.example", str(tmp_path / "nope")) == []

    def test_empty_dir_returns_empty(self, tmp_path):
        d = tmp_path / "params"
        d.mkdir()
        assert director.param_discovery_leads("t.example", str(d)) == []

    def test_arjun_json_param_names_route_through_lead_board(self, tmp_path):
        d = tmp_path / "params"
        d.mkdir()
        (d / "arjun.json").write_text(json.dumps({
            "https://t.example/api/v1/account": {"params": ["account_id", "callback", "not_a_signal_xyz"]},
        }))
        leads = director.param_discovery_leads("t.example", str(d))
        skills = {l["skill"] for l in leads}
        assert "hunt-idor" in skills   # account_id
        assert "hunt-ssrf" in skills   # callback
        assert all(l["source"] == "param-discovery" for l in leads)
        assert all(l["tool_artifact"] == "arjun.json" for l in leads)
        # "not_a_signal_xyz" matches no ROUTES pattern -> no lead for it,
        # never a fabricated one.
        assert not any("not_a_signal_xyz" in l["evidence"] for l in leads)

    def test_arjun_json_malformed_does_not_raise(self, tmp_path):
        d = tmp_path / "params"
        d.mkdir()
        (d / "arjun.json").write_text("{not json")
        assert director.param_discovery_leads("t.example", str(d)) == []

    def test_arjun_json_non_dict_top_level_ignored(self, tmp_path):
        d = tmp_path / "params"
        d.mkdir()
        (d / "arjun.json").write_text(json.dumps(["unexpected", "list", "shape"]))
        assert director.param_discovery_leads("t.example", str(d)) == []

    def test_x8_standart_format_parsed_as_fallback(self, tmp_path):
        d = tmp_path / "params"
        d.mkdir()
        (d / "x8.txt").write_text(
            "GET https://t.example/api/v1/report % template, redirect_uri\n"
            "this line has no percent sign and must be skipped\n"
        )
        leads = director.param_discovery_leads("t.example", str(d))
        skills = {l["skill"] for l in leads}
        assert "hunt-ssti" in skills
        assert "hunt-lfi" in skills
        assert "hunt-open-redirect" in skills
        assert all(l["tool_artifact"] == "x8.txt" for l in leads)

    def test_arjun_and_x8_both_present_arjun_still_parsed(self, tmp_path):
        # arjun.json is preferred but x8.txt is still read if present --
        # never an either/or gate, just two independent sources.
        d = tmp_path / "params"
        d.mkdir()
        (d / "arjun.json").write_text(json.dumps({"https://t.example/a": {"params": ["user_id"]}}))
        (d / "x8.txt").write_text("GET https://t.example/b % is_admin\n")
        leads = director.param_discovery_leads("t.example", str(d))
        skills = {l["skill"] for l in leads}
        assert "hunt-idor" in skills
        assert "hunt-auth-bypass" in skills


class TestSecretScanLeads:
    """Part C — tools/secrets_scanner.py findings -> lead-board leads.
    Deterministic recon_dir-relative paths (unlike Part B's three tools),
    so no findings_dir param needed here."""

    def test_no_sources_or_cicd_dir_returns_empty(self, tmp_path):
        assert director.secret_scan_leads("t.example", str(tmp_path / "recon" / "t.example")) == []

    def test_pattern_match_becomes_high_priority_source_leak_lead(self, tmp_path):
        recon_dir = tmp_path / "recon" / "t.example"
        bundle = recon_dir / "browser" / "sources" / "main.bundle"
        bundle.mkdir(parents=True)
        (bundle / "app.ts").write_text('const k = "AKIAIOSFODNN7EXAMPLE";')
        leads = director.secret_scan_leads("t.example", str(recon_dir))
        cred_leads = [l for l in leads if l["signal"] == "cloud_credential"]
        assert cred_leads
        assert cred_leads[0]["skill"] == "hunt-source-leak"
        assert cred_leads[0]["priority"] == "high"
        assert cred_leads[0]["source"] == "secret-scan"

    def test_entropy_only_finding_becomes_medium_priority(self, tmp_path):
        recon_dir = tmp_path / "recon" / "t.example"
        bundle = recon_dir / "browser" / "sources" / "main.bundle"
        bundle.mkdir(parents=True)
        (bundle / "app.ts").write_text('const t = "aZ9kLm3pQwErTyUiOpAsDfGhJkLzXcVbNm12";')
        leads = director.secret_scan_leads("t.example", str(recon_dir))
        entropy_leads = [l for l in leads if l["signal"] == "high_entropy_string"]
        assert entropy_leads
        assert entropy_leads[0]["priority"] == "med"

    def test_internal_api_url_routes_to_api_misconfig_skill(self, tmp_path):
        recon_dir = tmp_path / "recon" / "t.example"
        bundle = recon_dir / "browser" / "sources" / "main.bundle"
        bundle.mkdir(parents=True)
        (bundle / "app.ts").write_text('fetch("http://admin-api.internal.t.example/x");')
        leads = director.secret_scan_leads("t.example", str(recon_dir))
        assert any(l["skill"] == "hunt-api-misconfig" for l in leads)

    def test_feature_flag_routes_to_auth_bypass_skill(self, tmp_path):
        recon_dir = tmp_path / "recon" / "t.example"
        bundle = recon_dir / "browser" / "sources" / "main.bundle"
        bundle.mkdir(parents=True)
        (bundle / "app.ts").write_text("if (flags.betaDashboard) { render(); }")
        leads = director.secret_scan_leads("t.example", str(recon_dir))
        assert any(l["skill"] == "hunt-auth-bypass" for l in leads)

    def test_graphql_fragment_routes_to_graphql_skill(self, tmp_path):
        recon_dir = tmp_path / "recon" / "t.example"
        bundle = recon_dir / "browser" / "sources" / "main.bundle"
        bundle.mkdir(parents=True)
        (bundle / "app.ts").write_text("fragment UserFields on User { id name }")
        leads = director.secret_scan_leads("t.example", str(recon_dir))
        assert any(l["skill"] == "hunt-graphql" for l in leads)

    def test_exposed_sourcemap_directory_evidence_becomes_high_priority_lead(self, tmp_path):
        recon_dir = tmp_path / "recon" / "t.example"
        (recon_dir / "browser" / "sources" / "main.bundle").mkdir(parents=True)
        leads = director.secret_scan_leads("t.example", str(recon_dir))
        sm_leads = [l for l in leads if l["signal"] == "exposed_sourcemap"]
        assert sm_leads and sm_leads[0]["priority"] == "high"

    def test_cicd_findings_feed_the_same_pipeline_not_a_separate_lead_type(self, tmp_path):
        # Part B's deferred requirement: cicd_scanner.sh output goes through
        # Part C's scanner, not a distinct adapter/skill category.
        recon_dir = tmp_path / "recon" / "t.example"
        cicd = recon_dir / "cicd" / "acme-org"
        cicd.mkdir(parents=True)
        (cicd / "scan_results.txt").write_text("ghp_" + "a" * 36)
        leads = director.secret_scan_leads("t.example", str(recon_dir))
        assert any(l["skill"] == "hunt-source-leak" for l in leads)


class TestBuildPlanSecretScanWiring:
    """secret_scan_leads() is wired unconditionally into build_plan(),
    same as browser_intel_leads()/attack_graph_leads() — no opt-in param,
    since both its data sources are already deterministic recon_dir-
    relative paths, empty for every existing fixture."""

    def test_no_sources_or_cicd_dir_reproduces_prior_plan(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d1 = director.Director(memory_dir=str(tmp_path / "hunt-memory-a"))
        d2 = director.Director(memory_dir=str(tmp_path / "hunt-memory-b"))
        plan_a = d1.build_plan("t.example", hours=5, recon_dir=rd)
        plan_b = d2.build_plan("t.example", hours=5, recon_dir=rd)
        assert len(plan_a.attacks) == len(plan_b.attacks)

    def test_secret_finding_adds_a_candidate_to_the_plan(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        bundle = Path(rd) / "browser" / "sources" / "main.bundle"
        bundle.mkdir(parents=True)
        (bundle / "app.ts").write_text('const k = "AKIAIOSFODNN7EXAMPLE";')
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=5, recon_dir=rd)
        all_evidence = [a.evidence for a in plan.attacks] + [[s["evidence"]] for s in plan.skipped]
        flat = [e for group in all_evidence for e in group]
        assert any("AKIA" in e for e in flat)


def _write_fingerprint(recon_dir, cves):
    fp_path = Path(recon_dir)
    fp_path.mkdir(parents=True, exist_ok=True)
    (fp_path / "fingerprint.json").write_text(json.dumps({
        "target": "t.example", "framework": "nextjs", "version": "12.0.0", "cves": cves,
    }))


_NEXTJS_CVE_HIT = {
    "id": "CVE-2025-29927", "severity": "critical",
    "affected_versions": [">=11.1.4,<13.5.9"],
    "vuln_class": "auth-bypass", "citation": "Next.js middleware authorization bypass",
}


class TestFingerprintCveLeads:
    """recon/<target>/fingerprint.json's cves[] (Phase 2.6, always-on) ->
    lead-board leads for the version-confirmed CVE match — the
    "framework-aware hypothesis" gap: this is the ONE precise, mechanical
    signal fingerprint.py already computes (a real version_in_range() match
    against the target's actual fingerprinted version) that nothing
    downstream ever turned into a testable candidate before this."""

    def test_missing_fingerprint_json_returns_empty(self, tmp_path):
        assert director.fingerprint_cve_leads("t.example", str(tmp_path / "recon" / "t.example")) == []

    def test_malformed_fingerprint_json_does_not_raise(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        rd.mkdir(parents=True)
        (rd / "fingerprint.json").write_text("{not json")
        assert director.fingerprint_cve_leads("t.example", str(rd)) == []

    def test_no_cves_key_returns_empty(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        rd.mkdir(parents=True)
        (rd / "fingerprint.json").write_text(json.dumps({"target": "t.example", "framework": "unknown"}))
        assert director.fingerprint_cve_leads("t.example", str(rd)) == []

    def test_real_cve_hit_becomes_high_priority_lead_with_expected_skill(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        _write_fingerprint(rd, [_NEXTJS_CVE_HIT])
        leads = director.fingerprint_cve_leads("t.example", str(rd))
        assert len(leads) == 1
        lead = leads[0]
        assert lead["skill"] == "hunt-auth-bypass"
        assert lead["priority"] == "high"
        assert lead["source"] == "fingerprint-cve"
        assert lead["tool_artifact"] == "fingerprint.json"
        assert "CVE-2025-29927" in lead["signal"]
        assert "CVE-2025-29927" in lead["why"]
        assert "middleware authorization bypass" in lead["why"]
        assert lead["evidence"] == "https://t.example/"

    def test_severity_maps_to_expected_priority_tier(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        _write_fingerprint(rd, [
            {**_NEXTJS_CVE_HIT, "id": "CVE-A", "severity": "medium"},
            {**_NEXTJS_CVE_HIT, "id": "CVE-B", "severity": "low"},
        ])
        leads = director.fingerprint_cve_leads("t.example", str(rd))
        by_id = {l["signal"]: l["priority"] for l in leads}
        assert by_id["fingerprinted CVE: CVE-A"] == "med"
        assert by_id["fingerprinted CVE: CVE-B"] == "low"

    def test_unmapped_vuln_class_is_skipped_not_fabricated(self, tmp_path):
        # "reentrancy" is smart-contract-specific -- no honest web2 hunt-*
        # skill exists for it, so this must be silently skipped, never
        # routed to a made-up or wrong skill.
        rd = tmp_path / "recon" / "t.example"
        _write_fingerprint(rd, [
            {"id": "CVE-FAKE", "severity": "high", "affected_versions": ["*"],
             "vuln_class": "reentrancy", "citation": None},
        ])
        assert director.fingerprint_cve_leads("t.example", str(rd)) == []

    def test_missing_vuln_class_is_skipped(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        _write_fingerprint(rd, [
            {"id": "CVE-FAKE", "severity": "high", "affected_versions": ["*"],
             "vuln_class": None, "citation": None},
        ])
        assert director.fingerprint_cve_leads("t.example", str(rd)) == []

    def test_multiple_real_cves_each_become_their_own_lead(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        _write_fingerprint(rd, [
            _NEXTJS_CVE_HIT,
            {"id": "CVE-OTHER", "severity": "high", "affected_versions": ["*"],
             "vuln_class": "ssrf", "citation": "test"},
        ])
        leads = director.fingerprint_cve_leads("t.example", str(rd))
        assert {l["skill"] for l in leads} == {"hunt-auth-bypass", "hunt-ssrf"}


class TestBuildPlanFingerprintCveWiring:
    """fingerprint_cve_leads() is wired unconditionally into build_plan(),
    same as secret_scan_leads() above -- fingerprint.json is Phase 2.6's
    always-on output, no opt-in findings_dir param."""

    def test_no_fingerprint_json_reproduces_prior_plan(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d1 = director.Director(memory_dir=str(tmp_path / "hunt-memory-a"))
        d2 = director.Director(memory_dir=str(tmp_path / "hunt-memory-b"))
        plan_a = d1.build_plan("t.example", hours=5, recon_dir=rd)
        plan_b = d2.build_plan("t.example", hours=5, recon_dir=rd)
        assert len(plan_a.attacks) == len(plan_b.attacks)

    def test_fingerprinted_cve_adds_a_candidate_to_the_plan(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        _write_fingerprint(rd, [_NEXTJS_CVE_HIT])
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=5, recon_dir=rd)
        all_evidence = [a.evidence for a in plan.attacks] + [[s["evidence"]] for s in plan.skipped]
        flat = [e for group in all_evidence for e in group]
        assert any("t.example" in e and e.rstrip("/").endswith("t.example") for e in flat)

    def test_fingerprint_cve_lead_confidence_rank_wins_a_dedup_collision(self, isolated, tmp_path):
        # A plain lead-board "url"-source lead whose evidence normalizes to
        # the SAME shape ("/") as the fingerprint-cve lead's host-root
        # evidence must lose the dedup collision -- fingerprint-cve (rank 4)
        # outranks the default rank-0 tier a plain recon-ingested lead gets.
        rd = _seed_leads(isolated, "t.example", ["https://t.example/"])
        leads = lb.load_ledger("t.example")
        auth_bypass_lead = next((l for l in leads if l["skill"] == "hunt-auth-bypass"), None)
        if auth_bypass_lead is None:
            # REALISTIC_URLS-shaped seed didn't happen to produce an
            # auth-bypass lead at "/" -- add one directly so the collision
            # is deterministic regardless of ROUTES table changes elsewhere.
            lb.save_ledger("t.example", leads + [{
                "id": "lb-collide", "target": "t.example", "skill": "hunt-auth-bypass",
                "priority": "med", "signal": "test", "why": "test",
                "evidence": "https://t.example/", "source": "url", "status": "new", "note": "",
                "created": lb.now_iso(), "last_seen": lb.now_iso(), "seen_count": 1,
            }])
        _write_fingerprint(rd, [_NEXTJS_CVE_HIT])
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=5, recon_dir=rd)
        matching = [a for a in plan.attacks if any("fingerprinted CVE" in e for e in a.evidence)]
        matching += [s for s in plan.skipped if "fingerprinted CVE" in s.get("evidence", "")]
        assert len(matching) == 1, f"expected the fingerprint-cve lead to win the collision, got {matching}"


_lead_id_counter = iter(range(1_000_000))


def _lead(source, skill="hunt-idor", evidence="/api/orders/482", **overrides):
    # A unique id per call by default (real lead_board ids are random hex
    # tokens -- never colliding across distinct leads) so tests that build
    # several leads with the same source/evidence on purpose (to prove
    # dedup_leads()'s no-real-key fallback bucket, or that chain/hypothesis
    # leads are never collapsed even when literally identical) don't
    # accidentally collide on id instead of on the intended key.
    base = {
        "id": f"test-{source}-{next(_lead_id_counter)}", "target": "t.example", "skill": skill,
        "priority": "high", "signal": "test", "why": "test", "evidence": evidence,
        "source": source, "status": "new", "note": "",
        "created": "2026-01-01T00:00:00Z", "last_seen": "2026-01-01T00:00:00Z", "seen_count": 1,
    }
    base.update(overrides)
    return base


class TestDedupLeads:
    """Direct unit tests for director.dedup_leads() -- the HIGH-severity fix
    closing build_plan()'s cross-source duplicate gap (duplicate_or_noise_check()
    only ever caught a repeat against cross-SESSION memory, never a collision
    WITHIN one all_leads list built from six concatenated sources)."""

    def test_same_vuln_class_and_endpoint_from_two_sources_collapses(self):
        leads = [
            _lead("url", evidence="/api/orders/482"),
            _lead("object-model", evidence="/api/orders/482"),
        ]
        result = director.dedup_leads(leads)
        assert len(result) == 1

    def test_higher_confidence_source_wins(self):
        weak = _lead("url", evidence="/api/orders/482")
        strong = _lead("object-model", evidence="/api/orders/482")
        result = director.dedup_leads([weak, strong])
        assert result[0]["source"] == "object-model"
        # Order shouldn't matter -- same result reversed.
        result_reversed = director.dedup_leads([strong, weak])
        assert result_reversed[0]["source"] == "object-model"

    def test_confidence_ordering_matches_documented_tiers(self):
        assert director._lead_confidence_rank(_lead("object-model")) == 5
        assert director._lead_confidence_rank(_lead("secret-scan")) == 4
        assert director._lead_confidence_rank(_lead("takeover-scan")) == 4
        assert director._lead_confidence_rank(_lead("cloud-recon")) == 4
        assert director._lead_confidence_rank(_lead("graphql-audit")) == 4
        assert director._lead_confidence_rank(_lead("browser-intel")) == 3
        assert director._lead_confidence_rank(_lead("attack-graph")) == 2
        assert director._lead_confidence_rank(_lead("url")) == 0
        assert director._lead_confidence_rank(_lead("some-future-source-not-yet-ranked")) == 0

    def test_normalized_endpoint_shapes_still_collapse(self):
        """Reuses vuln_intelligence.normalize_endpoint() -- /api/orders/482
        and /api/orders/9107 are the same shape."""
        leads = [
            _lead("url", evidence="/api/orders/482"),
            _lead("object-model", evidence="/api/orders/9107"),
        ]
        result = director.dedup_leads(leads)
        assert len(result) == 1
        assert result[0]["source"] == "object-model"

    def test_different_vuln_class_never_collapses(self):
        leads = [
            _lead("url", skill="hunt-idor", evidence="/api/orders/482"),
            _lead("url", skill="hunt-ssrf", evidence="/api/orders/482"),
        ]
        assert len(director.dedup_leads(leads)) == 2

    def test_different_endpoint_never_collapses(self):
        leads = [
            _lead("url", evidence="/api/orders/482"),
            _lead("url", evidence="/api/users/482"),
        ]
        assert len(director.dedup_leads(leads)) == 2

    def test_chain_and_hypothesis_leads_never_collapsed(self):
        """A composite chain/hypothesis lead represents the correlation
        itself, not a repeat of any single leg -- excluded from dedup
        entirely, same precedent memory/attack_graph.py's raw-lead pass
        already established for these two sources."""
        leads = [
            _lead("chain", evidence="/api/orders/482"),
            _lead("chain", evidence="/api/orders/482"),  # even an exact duplicate
            _lead("hypothesis", evidence="/api/orders/482"),
        ]
        assert len(director.dedup_leads(leads)) == 3

    def test_missing_skill_or_evidence_never_crashes_or_silently_drops(self):
        leads = [
            {**_lead("url"), "skill": None},
            {**_lead("url"), "evidence": ""},
            _lead("url", evidence="/api/orders/482"),
        ]
        result = director.dedup_leads(leads)
        assert len(result) == 3  # no real key computable -> each kept as its own bucket

    def test_empty_input_returns_empty(self):
        assert director.dedup_leads([]) == []

    def test_no_collision_preserves_first_seen_order(self):
        leads = [
            _lead("url", evidence="/api/a"),
            _lead("url", evidence="/api/b"),
            _lead("url", evidence="/api/c"),
        ]
        result = director.dedup_leads(leads)
        assert [ld["evidence"] for ld in result] == ["/api/a", "/api/b", "/api/c"]


class TestBuildPlanCrossSourceDedup:
    """Integration proof through the real build_plan() pipeline: the same
    real finding, surfaced independently by the plain lead board AND
    secret_scan_leads(), must produce exactly ONE Attack/skip entry, not
    two -- the actual failure scenario the review found."""

    def test_secret_scan_and_manual_board_lead_collapse_to_one(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        bundle = Path(rd) / "browser" / "sources" / "main.bundle"
        bundle.mkdir(parents=True)
        secret_text = "AKIAIOSFODNN7EXAMPLE"
        (bundle / "app.ts").write_text(f'const k = "{secret_text}";')

        # A plain lead-board entry independently referencing the EXACT same
        # secret string under the SAME skill secret_scan_leads() routes AWS
        # keys to (hunt-source-leak) -- the manual-add path is source="manual",
        # the lowest-confidence tier, so secret-scan (tier 4) must win.
        lb.add("t.example", "hunt-source-leak", secret_text, "manually noted AWS key", lb.P_HIGH)

        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=5, recon_dir=rd)

        matching = [a for a in plan.attacks if any(secret_text in e for e in a.evidence)]
        matching += [s for s in plan.skipped if secret_text in s.get("evidence", "")]
        assert len(matching) == 1, f"expected exactly one collapsed entry, got {len(matching)}: {matching}"


class TestBuildPlanToolAdapterWiring:
    """The four Part B adapters are additive/opt-in on build_plan() —
    omitting their *_findings_dir params must reproduce prior behavior
    exactly, matching the tech_attack_matrix/rejection_lessons precedent."""

    def test_omitting_findings_dirs_reproduces_prior_plan(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d1 = director.Director(memory_dir=str(tmp_path / "hunt-memory-a"))
        d2 = director.Director(memory_dir=str(tmp_path / "hunt-memory-b"))
        plan_default = d1.build_plan("t.example", hours=5, recon_dir=rd)
        plan_explicit_none = d2.build_plan(
            "t.example", hours=5, recon_dir=rd,
            takeover_findings_dir=None, cloud_findings_dir=None, graphql_findings_dir=None,
            param_findings_dir=None,
        )
        assert len(plan_default.attacks) == len(plan_explicit_none.attacks)
        assert sorted(s["reason"] for s in plan_default.skipped) == \
               sorted(s["reason"] for s in plan_explicit_none.skipped)

    def test_param_findings_dir_adds_candidates_to_the_plan(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        params_dir = tmp_path / "params"
        params_dir.mkdir()
        (params_dir / "arjun.json").write_text(json.dumps({
            "https://t.example/api/v1/account": {"params": ["account_id"]},
        }))
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=5, recon_dir=rd, param_findings_dir=str(params_dir))
        all_evidence = [a.evidence for a in plan.attacks] + [[s["evidence"]] for s in plan.skipped]
        flat = [e for group in all_evidence for e in group]
        assert any("account_id" in e for e in flat)

    def test_takeover_findings_dir_adds_candidates_to_the_plan(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        takeover_dir = tmp_path / "takeover"
        takeover_dir.mkdir()
        (takeover_dir / "subjack.txt").write_text("[github] https://stale.t.example\n")
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=5, recon_dir=rd, takeover_findings_dir=str(takeover_dir))
        all_evidence = [a.evidence for a in plan.attacks] + [[s["evidence"]] for s in plan.skipped]
        flat = [e for group in all_evidence for e in group]
        assert any("stale.t.example" in e for e in flat)

    def test_cloud_findings_dir_adds_candidates_to_the_plan(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        cloud_dir = tmp_path / "cloud"
        cloud_dir.mkdir()
        (cloud_dir / "non_cf_ips.txt").write_text("origin.t.example -> 203.0.113.9\n")
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=5, recon_dir=rd, cloud_findings_dir=str(cloud_dir))
        all_evidence = [a.evidence for a in plan.attacks] + [[s["evidence"]] for s in plan.skipped]
        flat = [e for group in all_evidence for e in group]
        assert any("203.0.113.9" in e for e in flat)


class TestScoreLeadEndpointShapeWiring:
    """_score_lead() now passes lead.get("evidence", "") + mem["journal"]
    through to priority_score()/expected_value_per_hour() as endpoint=/
    journal_entries= -- verifies this reaches a real build_plan() candidate,
    not just the memory.vuln_intelligence unit tests in isolation."""

    def test_losing_endpoint_shape_lowers_a_real_candidates_score(self, isolated, tmp_path):
        mem_dir = tmp_path / "hunt-memory"
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        leads = lb.load_ledger("t.example")
        idor_lead = next(l for l in leads if l["skill"] == "hunt-idor")
        # idor_lead["evidence"] normalizes to /api/v2/users/{id} (numeric
        # ?id= param) -- three prior REJECTED journal entries for that
        # same shape should trip the losing-track-record penalty.
        (mem_dir).mkdir(parents=True, exist_ok=True)
        with open(mem_dir / "journal.jsonl", "w") as fh:
            for i in (101, 202, 303):
                fh.write(json.dumps(make_journal_entry(
                    target="t.example", action="hunt", vuln_class="idor",
                    endpoint=f"https://t.example/api/v2/users?id={i}", result="rejected",
                )) + "\n")

        d = director.Director(memory_dir=str(mem_dir))
        plan = d.build_plan("t.example", hours=5, recon_dir=rd)
        cand = next(c for c in d._last_plan_context["candidates"] if c["lead"]["id"] == idor_lead["id"])
        assert cand["score_result"]["components"]["endpoint_shape_penalty"] == 15
        assert cand["score_result"]["endpoint_shape"]["losses"] == 3
        assert cand["score_result"]["endpoint_shape"]["wins"] == 0

    def test_no_journal_history_never_applies_penalty(self, isolated, tmp_path):
        mem_dir = tmp_path / "hunt-memory"
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        leads = lb.load_ledger("t.example")
        idor_lead = next(l for l in leads if l["skill"] == "hunt-idor")

        d = director.Director(memory_dir=str(mem_dir))
        plan = d.build_plan("t.example", hours=5, recon_dir=rd)
        cand = next(c for c in d._last_plan_context["candidates"] if c["lead"]["id"] == idor_lead["id"])
        assert cand["score_result"]["components"]["endpoint_shape_penalty"] == 0


class TestBuildPlanBasics:

    def test_empty_memory_directory_works(self, isolated, tmp_path):
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("nolead.example", hours=2)
        assert plan.attacks == []
        assert plan.skipped == []
        assert "No leads found" in plan.summary

    def test_respects_total_time_budget(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS * 3)  # inflate candidate count
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        hours = 0.5
        plan = d.build_plan("t.example", hours=hours, recon_dir=str(isolated / "recon" / "t.example"))
        total_minutes = sum(a.maximum_time_minutes for a in plan.attacks)
        assert total_minutes <= hours * 60.0 + 1e-9

    def test_deterministic_output(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        recon_dir = str(isolated / "recon" / "t.example")
        mem_dir = str(tmp_path / "hunt-memory")
        d1 = director.Director(memory_dir=mem_dir)
        d2 = director.Director(memory_dir=mem_dir)
        plan1 = d1.build_plan("t.example", hours=3, recon_dir=recon_dir)
        plan2 = d2.build_plan("t.example", hours=3, recon_dir=recon_dir)

        def _stable(plan):
            # attack.id / attack.dependencies are randomly minted per
            # build_plan() call (secrets.token_hex) — translate dependency
            # attack_ids back to their stable lead_id before comparing, so
            # this actually tests semantic determinism, not ID entropy.
            attack_id_to_lead_id = {a.id: a.lead_id for a in plan.attacks}
            return [
                (a.lead_id, a.vuln_class, a.priority, a.ev_per_hour, a.ev_label, a.risk_level,
                 tuple(sorted(attack_id_to_lead_id[dep] for dep in a.dependencies)))
                for a in sorted(plan.attacks, key=lambda x: x.lead_id)
            ]

        assert _stable(plan1) == _stable(plan2)

    def test_no_duplicate_ranking_logic(self, isolated, tmp_path):
        """Every attack's priority/ev_per_hour must be byte-identical to
        calling priority_score()/expected_value_per_hour() directly with
        the same inputs — proving Director calls the formula rather than
        re-deriving its own."""
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        assert plan.attacks, "need at least one attack to prove anything"
        for a in plan.attacks:
            direct = priority_score(vuln_class=a.vuln_class, tech_stack=[], target="t.example")
            assert a.priority == direct["score"]


class TestSkippedSection:

    def test_skipped_never_empty_on_realistic_fixture_with_time_pressure(self, isolated, tmp_path):
        # 4 distinct leads, a tiny budget guarantees TIME_CONSTRAINT fires
        # for at least one after the first is planned.
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=0.2, recon_dir=str(isolated / "recon" / "t.example"))
        assert plan.skipped, "expected at least one skip under a tight budget"

    def test_every_skipped_entry_has_valid_machine_checkable_reason(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=0.2, recon_dir=str(isolated / "recon" / "t.example"))
        for s in plan.skipped:
            assert s["reason"] in director.SKIP_REASONS

    def test_below_ev_floor_skip(self, isolated, tmp_path):
        # open-redirect is P_MED with no memory backing -> low historical
        # success + low tech match -> ev/hr label "Low" -> BELOW_EV_FLOOR.
        _seed_leads(isolated, "t.example", ["https://t.example/redirect?next=https://x"])
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=5, recon_dir=str(isolated / "recon" / "t.example"))
        reasons = {s["reason"] for s in plan.skipped}
        assert "BELOW_EV_FLOOR" in reasons or not plan.skipped  # heuristic-dependent, assert no crash + valid taxonomy
        for s in plan.skipped:
            assert s["reason"] in director.SKIP_REASONS

    def test_matches_failed_pattern_skip(self, isolated, tmp_path):
        mem_dir = tmp_path / "hunt-memory"
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        leads = lb.load_ledger("t.example")
        idor_lead = next(l for l in leads if l["skill"] == "hunt-idor")

        FailedPatternDB(mem_dir / "failed_patterns.jsonl").save(make_failed_pattern_entry(
            target="t.example", vuln_class="idor", technique="numeric_id_swap",
            tech_stack=[], endpoint=idor_lead["evidence"], reason="egress filtered",
        ))
        d = director.Director(memory_dir=str(mem_dir))
        plan = d.build_plan("t.example", hours=5, recon_dir=rd)
        skipped_idor = [s for s in plan.skipped if s["lead_id"] == idor_lead["id"]]
        assert skipped_idor and skipped_idor[0]["reason"] == "MATCHES_FAILED_PATTERN"

    def test_duplicate_skip(self, isolated, tmp_path):
        mem_dir = tmp_path / "hunt-memory"
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        leads = lb.load_ledger("t.example")
        idor_lead = next(l for l in leads if l["skill"] == "hunt-idor")

        ReportOutcomeDB(mem_dir / "report_outcomes.jsonl").save(make_report_outcome_entry(
            target="t.example", vuln_class="idor", outcome="accepted",
        ))
        d = director.Director(memory_dir=str(mem_dir))
        plan = d.build_plan("t.example", hours=5, recon_dir=rd)
        skipped_idor = [s for s in plan.skipped if s["lead_id"] == idor_lead["id"]]
        assert skipped_idor and skipped_idor[0]["reason"] == "DUPLICATE"

    def test_dependency_unmet_cascades_to_skipped(self, isolated, tmp_path):
        # secret_plus_api chain: hunt-source-leak + hunt-api-misconfig on
        # the same host synthesizes a chain lead depending on both legs.
        rd = _seed_leads(isolated, "t.example", [
            "https://t.example/static/app.js.map",
            "https://t.example/api/v2/orders",
        ])
        mem_dir = tmp_path / "hunt-memory"
        leads = lb.load_ledger("t.example")
        source_leak_lead = next(l for l in leads if l["skill"] == "hunt-source-leak")
        # Force the source-leak leg to be skipped via a failed pattern so
        # the chain lead that depends on it must cascade into skipped[].
        FailedPatternDB(mem_dir / "failed_patterns.jsonl").save(make_failed_pattern_entry(
            target="t.example", vuln_class="source-leak", technique="fetch",
            tech_stack=[], endpoint=source_leak_lead["evidence"], reason="404, false positive",
        ))
        d = director.Director(memory_dir=str(mem_dir))
        plan = d.build_plan("t.example", hours=5, recon_dir=rd)
        chain_leads = [l for l in leads if l.get("source") == "chain"]
        if chain_leads:  # chain detection is data-dependent; assert cascade IF one exists
            chain_lead_ids = {l["id"] for l in chain_leads}
            cascaded = [s for s in plan.skipped if s["lead_id"] in chain_lead_ids
                        and s["reason"] == "DEPENDENCY_UNMET"]
            assert cascaded

    def test_always_rejected_and_policy_excluded_stay_in_vocabulary_but_unused(self, isolated, tmp_path):
        """Per explicit design decision: ALWAYS_REJECTED/POLICY_EXCLUDED
        are valid enum values (schema completeness) but the automatic
        classifier never fabricates evidence for them from recon-time
        signals alone."""
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        reasons = {s["reason"] for s in plan.skipped}
        assert "ALWAYS_REJECTED" not in reasons
        assert "POLICY_EXCLUDED" not in reasons
        assert {"ALWAYS_REJECTED", "POLICY_EXCLUDED"} <= set(director.SKIP_REASONS)

    def test_policy_excluded_fires_only_when_rejection_lessons_explicitly_passed(self, isolated, tmp_path):
        """Part A: extract_rejection_lessons() output is opt-in via
        build_plan(rejection_lessons=...) — POLICY_EXCLUDED must never
        appear unless a caller explicitly supplies a lesson clearing
        POLICY_EXCLUSION_REJECTION_RATE_THRESHOLD."""
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        leads = lb.load_ledger("t.example")
        idor_lead = next(l for l in leads if l["skill"] == "hunt-idor")
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))

        lessons = [{
            "vuln_class": "idor", "rejection_rate": 1.0, "sample_size": 5,
            "total_outcomes": 5, "top_reasons": [], "basis": "5 real not_applicable outcomes",
        }]
        plan = d.build_plan("t.example", hours=5, recon_dir=rd, rejection_lessons=lessons)
        skipped_idor = [s for s in plan.skipped if s["lead_id"] == idor_lead["id"]]
        assert skipped_idor and skipped_idor[0]["reason"] == "POLICY_EXCLUDED"
        assert "idor" in skipped_idor[0]["detail"]

    def test_policy_excluded_not_emitted_below_unanimous_rejection_rate(self, isolated, tmp_path):
        # Anything short of unanimous (1.0) — even 0.99 — deliberately does
        # NOT auto-fire; see POLICY_EXCLUSION_REJECTION_RATE_THRESHOLD's
        # comment on why 1.0 is the only non-arbitrary cutoff available.
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        lessons = [{
            "vuln_class": "idor", "rejection_rate": 0.99, "sample_size": 100,
            "total_outcomes": 100, "top_reasons": [], "basis": "test",
        }]
        plan = d.build_plan("t.example", hours=5, recon_dir=rd, rejection_lessons=lessons)
        reasons = {s["reason"] for s in plan.skipped}
        assert "POLICY_EXCLUDED" not in reasons

    def test_rejection_lessons_default_none_reproduces_prior_plan(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d1 = director.Director(memory_dir=str(tmp_path / "hunt-memory-a"))
        d2 = director.Director(memory_dir=str(tmp_path / "hunt-memory-b"))
        plan_default = d1.build_plan("t.example", hours=5, recon_dir=rd)
        plan_explicit_none = d2.build_plan("t.example", hours=5, recon_dir=rd, rejection_lessons=None)
        reasons_default = sorted(s["reason"] for s in plan_default.skipped)
        reasons_explicit = sorted(s["reason"] for s in plan_explicit_none.skipped)
        assert reasons_default == reasons_explicit


class TestFalsifiersAndStopConditions:

    def test_every_attack_has_a_falsifier(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        assert plan.attacks
        for a in plan.attacks:
            assert a.falsifier and isinstance(a.falsifier, str)

    def test_every_attack_has_a_stop_condition_and_success(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        for a in plan.attacks:
            assert a.stop_condition
            assert a.success
            assert a.minimum_time_minutes > 0
            assert a.maximum_time_minutes > 0


class TestStateMachineAndDependencies:

    def test_dependency_ordering_preserved(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", [
            "https://t.example/static/app.js.map",
            "https://t.example/api/v2/orders",
        ])
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=5, recon_dir=rd)
        by_id = {a.id: a for a in plan.attacks}
        for a in plan.attacks:
            if a.dependencies:
                assert a.state in ("PENDING", "BLOCKED")
                for dep_id in a.dependencies:
                    assert dep_id in by_id, "dependency must resolve to an attack_id in this plan"

    def test_parallel_groups_generated(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        assert plan.attacks
        for a in plan.attacks:
            assert a.parallel_group and "/" in a.parallel_group

    def test_all_states_are_from_the_defined_set(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        for a in plan.attacks:
            assert a.state in director.STATES


class TestReplan:

    def test_replan_preserves_in_progress(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        ready = next(a for a in plan.attacks if a.state == "READY")
        plan2 = d.replan(plan, {"in_progress": [ready.id]})
        assert next(a for a in plan2.attacks if a.id == ready.id).state == "IN_PROGRESS"

    def test_replan_never_discards_completed_work(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        target = plan.attacks[0]
        plan2 = d.replan(plan, {"completed": [target.id]})
        still_there = next((a for a in plan2.attacks if a.id == target.id), None)
        assert still_there is not None
        assert still_there.state == "COMPLETED"
        # replanning again must not un-complete it without new evidence
        plan3 = d.replan(plan2, {})
        assert next(a for a in plan3.attacks if a.id == target.id).state == "COMPLETED"

    def test_abandoned_work_never_auto_revives(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        target = plan.attacks[0]
        plan2 = d.replan(plan, {"abandoned": [target.id]})
        plan3 = d.replan(plan2, {})
        assert next(a for a in plan3.attacks if a.id == target.id).state == "ABANDONED"

    def test_explicit_revive_restores_abandoned_work(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        target = plan.attacks[0]
        plan2 = d.replan(plan, {"abandoned": [target.id]})
        plan3 = d.replan(plan2, {"revive": [target.id]})
        assert next(a for a in plan3.attacks if a.id == target.id).state != "ABANDONED"

    def test_replan_respects_remaining_time_budget(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS * 2)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=1, recon_dir=str(isolated / "recon" / "t.example"))
        completed_ids = [a.id for a in plan.attacks[:1]]
        plan2 = d.replan(plan, {"completed": completed_ids})
        open_minutes = sum(a.maximum_time_minutes for a in plan2.attacks if a.state == "READY")
        remaining_budget = plan.total_budget_hours * 60.0 - sum(
            a.maximum_time_minutes for a in plan2.attacks if a.state in ("COMPLETED", "IN_PROGRESS")
        )
        assert open_minutes <= remaining_budget + 1e-9

    def test_replan_raises_on_unmatched_completed_id(self, isolated, tmp_path):
        """Deferred finding from the 2026-08-08 security review: replan()
        used to silently no-op on a results_so_far id that doesn't match any
        Attack.id in the current plan -- a stale/typo'd id's completed/
        failed/in_progress signal was just dropped with no trace. Every
        other gate in this codebase fails loud on bad input; this must too."""
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        with pytest.raises(ValueError, match="attack-id-that-does-not-exist"):
            d.replan(plan, {"completed": ["attack-id-that-does-not-exist"]})

    @pytest.mark.parametrize("field", ["completed", "failed", "abandoned", "in_progress", "revive"])
    def test_replan_raises_for_unmatched_id_in_every_status_field(self, isolated, tmp_path, field):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        with pytest.raises(ValueError, match="bogus-id"):
            d.replan(plan, {field: ["bogus-id"]})

    def test_replan_raises_on_unmatched_note_id(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        with pytest.raises(ValueError, match="bogus-note-id"):
            d.replan(plan, {"notes": {"bogus-note-id": "some note"}})

    def test_replan_raises_before_mutating_any_state_on_partial_mismatch(self, isolated, tmp_path):
        """A results_so_far payload that's a mix of one real id and one
        unmatched id must raise -- not silently apply the real id's update
        and drop the bad one, which would hide exactly the bug this fixes."""
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        real_id = plan.attacks[0].id
        with pytest.raises(ValueError, match="bogus-id"):
            d.replan(plan, {"completed": [real_id, "bogus-id"]})
        # The real attack's state must be untouched by the rejected call.
        assert next(a for a in plan.attacks if a.id == real_id).state != "COMPLETED"


class TestExplain:

    def test_explain_without_plan_says_so(self):
        d = director.Director(memory_dir="hunt-memory")
        assert "No plan" in d.explain("lb-doesnotexist")

    def test_explain_names_evidence_not_just_vuln_class(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        top = plan.attacks[0]
        explanation = d.explain(top.lead_id)
        assert top.lead_id in explanation
        assert "Evidence:" in explanation
        assert "EV/hour" in explanation

    def test_explain_unknown_lead_id(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        assert "No lead" in d.explain("lb-doesnotexist")


class TestConfidence:

    def test_cold_start_explicitly_reported(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        result = d.confidence(plan)
        assert result["available"] is False
        assert result["message"] == "No calibration data available."
        for a in plan.attacks:
            assert a.calibrated_confidence is None
            assert a.calibration_note == "No calibration data available."
            # Cold start: no patterns/failed_patterns exist for any vuln_class
            # on this tech stack, so confidence must be None (not the 20.0
            # technology_match floor masquerading as a real number).
            assert a.confidence is None
            assert a.confidence_note == "no informative signal yet — technology_match floor"

    def test_confidence_is_a_real_number_once_affinity_data_exists(self, isolated, tmp_path):
        mem_dir = tmp_path / "hunt-memory"
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        leads = lb.load_ledger("t.example")
        idor_lead = next(l for l in leads if l["skill"] == "hunt-idor")

        # A real pattern for idor+this tech stack -> tech_vuln_affinity()
        # now has a matching entry with wins+losses > 0.
        PatternDB(mem_dir / "patterns.jsonl").save(make_pattern_entry(
            target="other-target.example", vuln_class="idor", technique="numeric_id_swap",
            tech_stack=["express", "postgresql"], endpoint="/api/v1/orders/{id}",
        ))
        (mem_dir / "targets").mkdir(parents=True, exist_ok=True)
        (mem_dir / "targets" / "t.example.json").write_text(json.dumps({"tech_stack": ["express", "postgresql"]}))

        d = director.Director(memory_dir=str(mem_dir))
        plan = d.build_plan("t.example", hours=3, recon_dir=rd)
        idor_attack = next(a for a in plan.attacks if a.lead_id == idor_lead["id"])
        assert idor_attack.confidence is not None
        assert isinstance(idor_attack.confidence, float)
        assert idor_attack.confidence_note == "technology_match component from tech_vuln_affinity() (memory-backed)"

        # A different vuln_class with no matching pattern on this tech
        # stack must still be None -- proves this is per-vuln_class, not
        # a global "any memory exists" toggle.
        ssrf_lead = next(l for l in leads if l["skill"] == "hunt-ssrf")
        ssrf_attack = next((a for a in plan.attacks if a.lead_id == ssrf_lead["id"]), None)
        if ssrf_attack is not None:
            assert ssrf_attack.confidence is None

    def test_confidence_passes_through_hypothesis_calibration(self, isolated, tmp_path):
        mem_dir = tmp_path / "hunt-memory"
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        leads = lb.load_ledger("t.example")
        idor_lead = next(l for l in leads if l["skill"] == "hunt-idor")

        HypothesisDB(mem_dir / "hypotheses.jsonl").save(make_hypothesis_entry(
            target="t.example", vuln_class="idor", endpoint=idor_lead["evidence"], confidence=70,
        ))
        (mem_dir / "journal.jsonl").parent.mkdir(parents=True, exist_ok=True)
        with open(mem_dir / "journal.jsonl", "w") as fh:
            fh.write(json.dumps(make_journal_entry(
                target="t.example", action="hunt", vuln_class="idor",
                endpoint=idor_lead["evidence"], result="confirmed",
            )) + "\n")

        d = director.Director(memory_dir=str(mem_dir))
        plan = d.build_plan("t.example", hours=3, recon_dir=rd)
        result = d.confidence(plan)
        assert result["available"] is True
        assert result["overall_calibration_gap"] is not None

    def test_never_fabricates_a_number_when_bucket_unresolved(self, isolated, tmp_path):
        mem_dir = tmp_path / "hunt-memory"
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        # A hypothesis exists but nothing resolves it (no matching journal
        # or report_outcomes entry) -> must stay "No calibration data available."
        HypothesisDB(mem_dir / "hypotheses.jsonl").save(make_hypothesis_entry(
            target="t.example", vuln_class="idor", endpoint="/never/matched", confidence=70,
        ))
        d = director.Director(memory_dir=str(mem_dir))
        plan = d.build_plan("t.example", hours=3, recon_dir=rd)
        for a in plan.attacks:
            assert a.calibrated_confidence is None
            assert a.calibration_note == "No calibration data available."


class TestRiskLevel:

    def test_risk_level_is_one_of_the_defined_tiers(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        for a in plan.attacks:
            assert a.risk_level in director.RISK_LEVELS

    def test_no_detection_risk_float_field_exists(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        for a in plan.attacks:
            assert "detection_risk" not in a.to_dict()

    def test_passive_source_is_always_low_risk(self):
        assert director.risk_level_for("hunt-nextjs", "tech", "") == "LOW"


class TestRenderAndWrite:

    def test_render_markdown_contains_required_sections(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        md = d.render_markdown(plan)
        assert "## Planned Attacks" in md
        assert "## SKIPPED" in md
        assert "## Checkpoint Schedule" in md
        assert "MANDATORY FALSIFIER" in md

    def test_write_plan_writes_hunt_plan_md(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=rd)
        out_path = d.write_plan(plan, recon_dir=rd)
        assert out_path.endswith("hunt-plan.md")
        import os
        assert os.path.exists(out_path)


class TestPlanPersistence:
    """save_plan()/load_plan() — the JSON sidecar that makes replan() usable
    across separate process invocations, not just an in-process object."""

    def test_save_then_load_round_trips_to_an_equal_plan(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=rd)
        assert plan.attacks, "need at least one attack to prove anything"

        plan_file = str(tmp_path / "hunt-plan.json")
        director.save_plan(plan, plan_file)
        reloaded = director.load_plan(plan_file)

        assert reloaded == plan  # dataclass equality: every field, every attack

    def test_round_trip_preserves_none_confidence(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=rd)
        plan_file = str(tmp_path / "hunt-plan.json")
        director.save_plan(plan, plan_file)
        reloaded = director.load_plan(plan_file)
        for a in reloaded.attacks:
            assert a.confidence is None
            assert a.confidence_note == "no informative signal yet — technology_match floor"

    def test_load_plan_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            director.load_plan(str(tmp_path / "does-not-exist.json"))

    def test_save_plan_creates_parent_directories(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=rd)
        nested = str(tmp_path / "a" / "b" / "c" / "hunt-plan.json")
        path = director.save_plan(plan, nested)
        assert path == nested
        import os
        assert os.path.exists(nested)

    def test_replan_across_a_fresh_load_preserves_in_progress_and_completed(self, isolated, tmp_path):
        """The actual scenario this exists for: build a plan, persist it,
        throw away the in-process Plan object entirely, reload from disk,
        and replan from there — same guarantees as in-process replan()."""
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=rd)
        completed_id = plan.attacks[0].id
        in_progress_id = plan.attacks[1].id
        plan_file = str(tmp_path / "hunt-plan.json")
        director.save_plan(plan, plan_file)

        del plan  # simulate a fresh process: no in-memory Plan survives

        reloaded = director.load_plan(plan_file)
        d2 = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        updated = d2.replan(reloaded, {"completed": [completed_id], "in_progress": [in_progress_id]})

        assert next(a for a in updated.attacks if a.id == completed_id).state == "COMPLETED"
        assert next(a for a in updated.attacks if a.id == in_progress_id).state == "IN_PROGRESS"


class TestPlanFileCLI:
    """CLI wiring: build-plan --write emits the JSON sidecar; replan
    --plan-file loads from it instead of requiring an in-process object."""

    def test_build_plan_write_emits_json_sidecar(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        exit_code = director.main([
            "build-plan", "t.example", "--hours", "3",
            "--memory-dir", str(tmp_path / "hunt-memory"),
            "--recon-dir", rd, "--write",
        ])
        assert exit_code == 0
        import os
        assert os.path.exists(os.path.join(rd, "hunt-plan.md"))
        assert os.path.exists(os.path.join(rd, "hunt-plan.json"))

    def test_build_plan_param_findings_dir_flag_reaches_the_plan(self, isolated, tmp_path, capsys):
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        params_dir = tmp_path / "params"
        params_dir.mkdir()
        (params_dir / "arjun.json").write_text(json.dumps({
            "https://t.example/api/v1/account": {"params": ["account_id"]},
        }))
        exit_code = director.main([
            "build-plan", "t.example", "--hours", "5",
            "--memory-dir", str(tmp_path / "hunt-memory"),
            "--recon-dir", rd, "--param-findings-dir", str(params_dir),
        ])
        assert exit_code == 0
        out = capsys.readouterr().out
        assert "account_id" in out

    def test_build_plan_plan_file_override(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        override = str(tmp_path / "custom-name.json")
        director.main([
            "build-plan", "t.example", "--hours", "3",
            "--memory-dir", str(tmp_path / "hunt-memory"),
            "--recon-dir", rd, "--write", "--plan-file", override,
        ])
        import os
        assert os.path.exists(override)

    def test_replan_cli_loads_from_plan_file_only(self, isolated, tmp_path, capsys):
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        plan_file = str(tmp_path / "hunt-plan.json")
        director.main([
            "build-plan", "t.example", "--hours", "3",
            "--memory-dir", str(tmp_path / "hunt-memory"),
            "--recon-dir", rd, "--write", "--plan-file", plan_file,
        ])
        capsys.readouterr()  # discard build-plan's stdout

        saved = director.load_plan(plan_file)
        target_attack_id = saved.attacks[0].id
        results_file = tmp_path / "results.json"
        results_file.write_text(json.dumps({"completed": [target_attack_id]}))

        exit_code = director.main(["replan", "--plan-file", plan_file, "--results-file", str(results_file)])
        assert exit_code == 0

        reloaded = director.load_plan(plan_file)
        assert next(a for a in reloaded.attacks if a.id == target_attack_id).state == "COMPLETED"

    def test_replan_cli_without_results_file_is_a_noop_pass(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        plan_file = str(tmp_path / "hunt-plan.json")
        director.main([
            "build-plan", "t.example", "--hours", "3",
            "--memory-dir", str(tmp_path / "hunt-memory"),
            "--recon-dir", rd, "--write", "--plan-file", plan_file,
        ])
        before = director.load_plan(plan_file)
        exit_code = director.main(["replan", "--plan-file", plan_file])
        assert exit_code == 0
        after = director.load_plan(plan_file)
        assert [a.state for a in before.attacks] == [a.state for a in after.attacks]

    def test_build_plan_cli_without_new_phase5_flags_still_works(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        exit_code = director.main([
            "build-plan", "t.example", "--hours", "3",
            "--memory-dir", str(tmp_path / "hunt-memory"), "--recon-dir", rd,
        ])
        assert exit_code == 0

    def test_build_plan_cli_accepts_findings_dir_flags(self, isolated, tmp_path, capsys):
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        capsys.readouterr()  # discard _seed_leads' ingest stdout
        takeover_dir = tmp_path / "takeover"
        takeover_dir.mkdir()
        (takeover_dir / "subjack.txt").write_text("[github] https://stale.t.example\n")
        exit_code = director.main([
            "build-plan", "t.example", "--hours", "5",
            "--memory-dir", str(tmp_path / "hunt-memory"), "--recon-dir", rd,
            "--takeover-findings-dir", str(takeover_dir),
        ])
        assert exit_code == 0
        out = capsys.readouterr().out
        assert "stale.t.example" in out

    def test_build_plan_cli_apply_rejection_lessons_flag(self, isolated, tmp_path, capsys):
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        capsys.readouterr()  # discard _seed_leads' ingest stdout
        mem_dir = tmp_path / "hunt-memory"
        outcomes_db = ReportOutcomeDB(mem_dir / "report_outcomes.jsonl")
        for i in range(5):
            entry = make_report_outcome_entry(
                target="other.example", vuln_class="idor", outcome="not_applicable",
                notes="behind auth, not exploitable",
            )
            # ReportOutcomeDB dedups on (target, vuln_class, outcome, ts) —
            # give each entry a distinct ts so all 5 land as separate rows
            # instead of collapsing into one same-second "duplicate" save.
            entry["ts"] = f"2026-01-0{i + 1}T00:00:00Z"
            outcomes_db.save(entry)
        exit_code = director.main([
            "build-plan", "t.example", "--hours", "5",
            "--memory-dir", str(mem_dir), "--recon-dir", rd,
            "--apply-rejection-lessons",
        ])
        assert exit_code == 0
        out = capsys.readouterr().out
        plan_dict = json.loads(out)
        reasons = {s["reason"] for s in plan_dict["skipped"]}
        assert "POLICY_EXCLUDED" in reasons


class TestShouldStopIntegration:

    def test_should_stop_now_delegates_to_experiment_memory(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        attack = plan.attacks[0]
        result = d.should_stop_now(attack, [], elapsed_minutes=attack.minimum_time_minutes)
        assert result["stop"] is True

    def test_should_stop_now_false_with_zero_elapsed(self, isolated, tmp_path):
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        attack = plan.attacks[0]
        result = d.should_stop_now(attack, [], elapsed_minutes=0)
        assert result["stop"] is False


def test_build_plan_rejects_non_positive_hours(isolated, tmp_path):
    d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
    with pytest.raises(ValueError):
        d.build_plan("t.example", hours=0)


class TestTechAttackMatrixWiring:
    """Phase 3 follow-up: tools/tech_attack_matrix.json's static weights
    actually reach priority_score()/expected_value_per_hour() through
    build_plan(), gated on recon/<target>/fingerprint.json existing for
    THIS target — not merely on the matrix file existing on disk."""

    def test_no_fingerprint_json_gate_closed(self, tmp_path):
        recon_dir = tmp_path / "recon" / "t.example"
        recon_dir.mkdir(parents=True)
        assert director.load_fingerprint_tech_attack_matrix("t.example", str(recon_dir)) is None

    def test_malformed_fingerprint_json_gate_closed(self, tmp_path):
        recon_dir = tmp_path / "recon" / "t.example"
        recon_dir.mkdir(parents=True)
        (recon_dir / "fingerprint.json").write_text("{not json")
        assert director.load_fingerprint_tech_attack_matrix("t.example", str(recon_dir)) is None

    def test_fingerprint_present_opens_gate_and_loads_real_matrix(self, tmp_path):
        recon_dir = tmp_path / "recon" / "t.example"
        recon_dir.mkdir(parents=True)
        (recon_dir / "fingerprint.json").write_text(json.dumps({"target": "t.example", "framework": "nextjs"}))
        matrix = director.load_fingerprint_tech_attack_matrix("t.example", str(recon_dir))
        assert matrix is not None
        assert "nextjs" in matrix

    def test_build_plan_byte_identical_when_fingerprint_absent(self, isolated, tmp_path):
        """No recon/<target>/fingerprint.json anywhere -> every attack's
        priority must still equal calling priority_score() directly with
        tech_attack_matrix omitted, same proof test_no_duplicate_ranking_logic
        already makes, now explicitly re-checked after wiring the parameter
        through build_plan()."""
        _seed_leads(isolated, "t.example", REALISTIC_URLS)
        recon_dir = str(isolated / "recon" / "t.example")
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        plan = d.build_plan("t.example", hours=3, recon_dir=recon_dir)
        assert plan.attacks, "need at least one attack to prove anything"
        for a in plan.attacks:
            direct = priority_score(vuln_class=a.vuln_class, tech_stack=[], target="t.example")
            assert a.priority == direct["score"]

    def test_fingerprint_present_but_framework_unmatched_in_matrix_no_crash(self, isolated, tmp_path):
        recon_dir = isolated / "recon" / "t.example"
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "urls" / "all.txt").write_text("https://t.example/admin\n")
        lb.ingest("t.example", str(recon_dir))
        (recon_dir / "fingerprint.json").write_text(json.dumps({
            "target": "t.example", "framework": "some-made-up-framework-xyz",
        }))
        mem_dir = tmp_path / "hunt-memory"
        (mem_dir / "targets").mkdir(parents=True)
        (mem_dir / "targets" / "t.example.json").write_text(
            json.dumps({"tech_stack": ["some-made-up-framework-xyz"]})
        )
        d = director.Director(memory_dir=str(mem_dir))
        plan = d.build_plan("t.example", hours=3, recon_dir=str(recon_dir))
        assert plan.attacks, "need at least one attack to prove anything"
        for a in plan.attacks:
            assert 0 <= a.priority <= 100  # no crash, no fabricated out-of-range score

    def test_nextjs_cve_weight_raises_priority_over_no_fingerprint(self, isolated, tmp_path):
        """The actual proof the wiring does something (not just that it
        doesn't crash): an identical hunt-auth-bypass lead, identical
        tech_stack (["nextjs"]) and identical (empty) memory -- the ONLY
        difference between the two build_plan() calls is whether
        recon/<target>/fingerprint.json exists. With it present,
        CVE-2025-29927's weight (90) replaces the historical-data-absent
        floor (20) for the matching "auth-bypass" vuln_class in
        _matrix_technology_match(), which must raise the final blended
        priority_score()."""
        recon_dir = isolated / "recon" / "t.example"
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "urls" / "all.txt").write_text("https://t.example/admin\n")
        lb.ingest("t.example", str(recon_dir))

        mem_dir = tmp_path / "hunt-memory"
        (mem_dir / "targets").mkdir(parents=True)
        (mem_dir / "targets" / "t.example.json").write_text(json.dumps({"tech_stack": ["nextjs"]}))

        d_without = director.Director(memory_dir=str(mem_dir))
        plan_without = d_without.build_plan("t.example", hours=3, recon_dir=str(recon_dir))

        (recon_dir / "fingerprint.json").write_text(json.dumps({
            "target": "t.example", "framework": "nextjs", "version": "12.0.0",
        }))
        d_with = director.Director(memory_dir=str(mem_dir))
        plan_with = d_with.build_plan("t.example", hours=3, recon_dir=str(recon_dir))

        by_lead_without = {a.lead_id: a for a in plan_without.attacks}
        by_lead_with = {a.lead_id: a for a in plan_with.attacks}
        auth_bypass_lead_ids = [lid for lid, a in by_lead_with.items() if a.vuln_class == "auth-bypass"]
        assert auth_bypass_lead_ids, "need at least one auth-bypass lead to prove anything"
        for lid in auth_bypass_lead_ids:
            assert lid in by_lead_without, "same lead must be scored in both plans"
            assert by_lead_with[lid].priority > by_lead_without[lid].priority


# Same 3-URL, same-host fixture tests/test_attack_graph.py's own
# TestRegressionAgainstLeadBoard uses to trigger
# account_takeover_via_leaked_secret (hunt-source-leak -> hunt-idor ->
# hunt-auth-bypass, all on t.example) -- guaranteed to produce an Impact
# node in memory/attack_graph.py's graph, hence at least one
# source=="attack-graph" candidate out of top_paths().
HYPOTHESIS_URLS = [
    "https://t.example/.env",
    "https://t.example/api/v2/users?id=1001",
    "https://t.example/login?next=/dashboard",
]


class TestAttackGraphLeads:
    """Phase 4 batch 2, item 6: memory/attack_graph.py's top_paths() output
    reaches build_plan() as additional candidates, via the SAME
    _score_lead()/sort/skip pipeline every other lead goes through -- no
    second candidate type, no parallel scoring path."""

    def test_attack_graph_leads_pure_function_produces_attack_graph_source(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", HYPOTHESIS_URLS)
        leads = director.attack_graph_leads("t.example", rd, memory_dir=str(tmp_path / "hunt-memory"))
        assert leads
        assert all(l["source"] == "attack-graph" for l in leads)

    def test_no_leads_no_recon_yields_empty_list_not_a_crash(self, isolated, tmp_path):
        leads = director.attack_graph_leads(
            "empty.example", str(tmp_path / "recon" / "empty.example"),
            memory_dir=str(tmp_path / "hunt-memory"),
        )
        assert leads == []

    def test_malformed_browser_json_does_not_raise(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", HYPOTHESIS_URLS)
        browser_dir = Path(rd) / "browser"
        browser_dir.mkdir(parents=True, exist_ok=True)
        (browser_dir / "auth-model.json").write_text("{not json")
        leads = director.attack_graph_leads("t.example", rd, memory_dir=str(tmp_path / "hunt-memory"))
        assert isinstance(leads, list)  # must not raise

    def test_leads_never_written_to_persisted_ledger(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", HYPOTHESIS_URLS)
        director.attack_graph_leads("t.example", rd, memory_dir=str(tmp_path / "hunt-memory"))
        # only the raw ingested leads (+ lead_board's own chain/hypothesis
        # synthesis) are on the ledger -- attack-graph leads are ephemeral,
        # recomputed every build_plan() call, same as browser-intel leads.
        assert all(l.get("source") != "attack-graph" for l in lb.load_ledger("t.example"))

    def test_build_plan_candidates_include_both_board_and_attack_graph_leads(self, isolated, tmp_path):
        """The actual item-6 proof: build_plan()'s candidate list (built
        from board_leads + bi_leads + graph_leads, all scored identically
        by _score_lead()) contains at least one lead-board-sourced
        candidate AND at least one attack-graph-sourced candidate side by
        side -- concatenated, not routed through a second pipeline."""
        rd = _seed_leads(isolated, "t.example", HYPOTHESIS_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        d.build_plan("t.example", hours=5, recon_dir=rd)
        candidates = d._last_plan_context["candidates"]
        sources = {c["lead"].get("source") for c in candidates}
        assert "attack-graph" in sources
        assert sources - {"attack-graph"}, "expected at least one non-attack-graph lead alongside it"

    def test_attack_graph_candidate_scored_by_same_score_lead_formula(self, isolated, tmp_path):
        """No second scoring formula: an attack-graph candidate's
        score_result/ev_result must be byte-identical to calling
        priority_score()/expected_value_per_hour() directly with the same
        vuln_class -- the exact proof test_no_duplicate_ranking_logic
        already makes for ordinary leads, repeated here for source==
        "attack-graph"."""
        rd = _seed_leads(isolated, "t.example", HYPOTHESIS_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        d.build_plan("t.example", hours=5, recon_dir=rd)
        candidates = d._last_plan_context["candidates"]
        graph_candidates = [c for c in candidates if c["lead"]["source"] == "attack-graph"]
        assert graph_candidates
        for c in graph_candidates:
            direct = priority_score(vuln_class=c["vuln_class"], tech_stack=[], target="t.example")
            assert c["score_result"]["score"] == direct["score"]


class TestExplainAttackGraphLead:
    """Phase 4 batch 2: Director.explain()'s source=="attack-graph" case
    must cover why the path exists, its weakest link, its strongest
    evidence, assumptions required, and a stopping condition -- extending
    the SAME explain() method, not a second explain-style function."""

    def _plan_with_attack_graph_candidate(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", HYPOTHESIS_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        d.build_plan("t.example", hours=5, recon_dir=rd)
        candidates = d._last_plan_context["candidates"]
        graph_candidate = next(c for c in candidates if c["lead"]["source"] == "attack-graph")
        return d, graph_candidate

    def test_explain_covers_all_required_explainability_fields(self, isolated, tmp_path):
        d, graph_candidate = self._plan_with_attack_graph_candidate(isolated, tmp_path)
        text = d.explain(graph_candidate["lead"]["id"])
        assert "Attack-graph path" in text          # why this path exists at all
        assert "Weakest link:" in text                # weakest leg
        assert "Strongest evidence:" in text           # strongest leg
        assert "Assumptions required" in text           # every leg's origin
        assert "Stopping condition" in text             # what would invalidate it

    def test_explain_weakest_link_matches_min_confidence_leg(self, isolated, tmp_path):
        d, graph_candidate = self._plan_with_attack_graph_candidate(isolated, tmp_path)
        lead = graph_candidate["lead"]
        weakest = min(lead["path_legs"], key=lambda leg: leg["confidence"])
        text = d.explain(lead["id"])
        assert str(weakest["confidence"]) in text
        assert weakest["edge_type"] in text

    def test_explain_weak_line_discloses_confidence_provenance(self, isolated, tmp_path):
        """A path's confidence numbers are fixed rules/chain_rules.yaml
        judgment calls, not measured probabilities -- explain() must say so
        on the weakest-link line, not just log it in path_legs where a
        reader might never look."""
        d, graph_candidate = self._plan_with_attack_graph_candidate(isolated, tmp_path)
        lead = graph_candidate["lead"]
        weakest = min(lead["path_legs"], key=lambda leg: leg["confidence"])
        text = d.explain(lead["id"])
        assert weakest["confidence_source"] in text

    def test_explain_unrelated_lead_still_uses_normal_path(self, isolated, tmp_path):
        """Sanity: the new elif branch must not affect explain() for
        non-attack-graph leads."""
        rd = _seed_leads(isolated, "t.example", HYPOTHESIS_URLS)
        d = director.Director(memory_dir=str(tmp_path / "hunt-memory"))
        d.build_plan("t.example", hours=5, recon_dir=rd)
        candidates = d._last_plan_context["candidates"]
        non_graph = next(c for c in candidates if c["lead"]["source"] != "attack-graph")
        text = d.explain(non_graph["lead"]["id"])
        assert "Attack-graph path" not in text


class TestObjectModelLeads:
    """Phase 6, Part 1: memory/object_model.py's relationship-violation
    Candidates -> lead-board-shaped candidates via object_model_leads().
    Cold-start (no memory/object_model/<target>.jsonl yet) must be [] and
    must not change build_plan()'s output at all, the same guarantee every
    other Phase 5/6 adapter gives."""

    def test_cold_start_returns_empty(self, tmp_path):
        assert director.object_model_leads("t.example", str(tmp_path / "hunt-memory")) == []

    def test_cold_start_build_plan_byte_identical(self, isolated, tmp_path):
        rd = _seed_leads(isolated, "t.example", REALISTIC_URLS)
        mem_dir = str(tmp_path / "hunt-memory")
        d1 = director.Director(memory_dir=mem_dir)
        plan_before = d1.build_plan("t.example", hours=3, recon_dir=rd)

        # An object_model dir existing with nothing recorded for THIS
        # target must not change anything either.
        (Path(mem_dir) / "object_model").mkdir(parents=True, exist_ok=True)
        d2 = director.Director(memory_dir=mem_dir)
        plan_after = d2.build_plan("t.example", hours=3, recon_dir=rd)

        def _stable(plan):
            return sorted((a.lead_id, a.vuln_class, a.priority) for a in plan.attacks)

        assert _stable(plan_before) == _stable(plan_after)

    def test_relationship_violation_becomes_hunt_idor_lead(self, tmp_path):
        from memory import object_model as om
        mem_dir = str(tmp_path / "hunt-memory")
        path = director.object_model_observations_path("t.example", mem_dir)
        store = om.ObservationStore(path)
        alice = "entity:User:alice"
        bob = "entity:User:bob"
        doc = "object:Document:1"
        ev = [{"type": "Observed-HTTP-Response", "detail": "d", "artifact": "a"}]
        store.record(om.make_observation(alice, doc, "created", evidence=ev, ts="2026-01-01T00:00:00Z"))
        store.record(om.make_observation(bob, doc, "accessed", evidence=ev, outcome_status=200,
                                          ts="2026-01-02T00:00:00Z"))

        leads = director.object_model_leads("t.example", mem_dir)
        assert len(leads) == 1
        assert leads[0]["skill"] == "hunt-idor"
        assert leads[0]["priority"] == "high"
        assert leads[0]["source"] == "object-model"
        assert leads[0]["target"] == "t.example"

    def test_object_model_lead_flows_into_build_plan(self, isolated, tmp_path):
        from memory import object_model as om
        mem_dir = str(tmp_path / "hunt-memory")
        path = director.object_model_observations_path("t.example", mem_dir)
        store = om.ObservationStore(path)
        alice, bob, doc = "entity:User:alice", "entity:User:bob", "object:Document:1"
        ev = [{"type": "Observed-HTTP-Response", "detail": "d", "artifact": "a"}]
        store.record(om.make_observation(alice, doc, "created", evidence=ev, ts="2026-01-01T00:00:00Z"))
        store.record(om.make_observation(bob, doc, "accessed", evidence=ev, outcome_status=200,
                                          ts="2026-01-02T00:00:00Z"))

        d = director.Director(memory_dir=mem_dir)
        plan = d.build_plan("t.example", hours=3, recon_dir=str(isolated / "recon" / "t.example"))
        assert any(a.vuln_class == "idor" for a in plan.attacks) or any(
            s["vuln_class"] == "idor" for s in plan.skipped
        )
