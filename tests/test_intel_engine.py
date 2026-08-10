"""Tests for intel_engine.py — memory-aware intel prioritization."""

import json
import os
import pytest

import intel_engine
from intel_engine import format_output, load_memory_context, prioritize_intel


@pytest.fixture
def memory_dir(tmp_path):
    """Create a mock hunt-memory directory with test data."""
    targets_dir = tmp_path / "targets"
    targets_dir.mkdir()

    # Target profile
    profile = {
        "target": "target.com",
        "tech_stack": ["nextjs", "graphql", "postgresql"],
        "tested_endpoints": ["/api/v1/users", "/api/v1/login"],
        "findings": [{"vuln_class": "idor", "severity": "high"}],
        "last_hunted": "2026-03-24",
        "hunt_sessions": 3,
    }
    (targets_dir / "target-com.json").write_text(json.dumps(profile))

    # Journal with tested CVE
    journal_entries = [
        {
            "ts": "2026-03-24T10:00:00Z",
            "target": "target.com",
            "action": "test",
            "vuln_class": "ssrf",
            "endpoint": "/api/v1/proxy",
            "result": "rejected",
            "tags": ["CVE-2026-1234"],
            "schema_version": 1,
        },
        {
            "ts": "2026-03-24T11:00:00Z",
            "target": "other.com",
            "action": "test",
            "vuln_class": "xss",
            "endpoint": "/search",
            "result": "confirmed",
            "tags": [],
            "schema_version": 1,
        },
    ]
    journal_path = tmp_path / "journal.jsonl"
    with open(journal_path, "w") as f:
        for entry in journal_entries:
            f.write(json.dumps(entry) + "\n")

    # Patterns
    patterns = [
        {
            "target": "alpha.com",
            "vuln_class": "idor",
            "technique": "numeric_id_swap_put",
            "tech_stack": ["nextjs", "express"],
            "payout": 800,
            "schema_version": 1,
        },
        {
            "target": "beta.com",
            "vuln_class": "ssrf",
            "technique": "dns_rebinding",
            "tech_stack": ["django", "celery"],
            "payout": 1500,
            "schema_version": 1,
        },
    ]
    patterns_path = tmp_path / "patterns.jsonl"
    with open(patterns_path, "w") as f:
        for p in patterns:
            f.write(json.dumps(p) + "\n")

    return tmp_path


class TestLoadMemoryContext:

    def test_loads_target_profile(self, memory_dir):
        ctx = load_memory_context(str(memory_dir), "target.com")
        assert ctx["tech_stack"] == ["nextjs", "graphql", "postgresql"]
        assert ctx["last_hunted"] == "2026-03-24"
        assert ctx["hunt_sessions"] == 3
        assert "/api/v1/users" in ctx["tested_endpoints"]

    def test_loads_tested_cves(self, memory_dir):
        ctx = load_memory_context(str(memory_dir), "target.com")
        assert "CVE-2026-1234" in ctx["tested_cves"]

    def test_loads_patterns(self, memory_dir):
        ctx = load_memory_context(str(memory_dir), "target.com")
        assert len(ctx["patterns"]) == 2

    def test_nonexistent_target(self, memory_dir):
        ctx = load_memory_context(str(memory_dir), "unknown.com")
        assert ctx["tested_endpoints"] == []
        assert ctx["tech_stack"] == []

    def test_nonexistent_directory(self):
        ctx = load_memory_context("/nonexistent/path", "target.com")
        assert ctx["tested_endpoints"] == []

    def test_empty_memory_dir(self):
        ctx = load_memory_context("", "target.com")
        assert ctx["tested_endpoints"] == []

    def test_corrupted_journal(self, memory_dir):
        journal_path = memory_dir / "journal.jsonl"
        with open(journal_path, "a") as f:
            f.write("not valid json\n")
        ctx = load_memory_context(str(memory_dir), "target.com")
        # Should still load the valid entries
        assert "CVE-2026-1234" in ctx["tested_cves"]


class TestPrioritizeIntel:

    def test_critical_untested(self):
        results = [
            {"id": "CVE-2026-9999", "severity": "CRITICAL", "summary": "RCE in Next.js"},
        ]
        memory = {"tested_cves": [], "tested_endpoints": [], "patterns": []}
        intel = prioritize_intel(results, memory)
        assert len(intel["critical"]) == 1
        assert intel["critical"][0]["note"] == "Untested critical vulnerability. Hunt candidate."

    def test_already_tested_cve(self):
        results = [
            {"id": "CVE-2026-1234", "severity": "CRITICAL", "summary": "Old vuln"},
        ]
        memory = {"tested_cves": ["CVE-2026-1234"], "tested_endpoints": [], "patterns": []}
        intel = prioritize_intel(results, memory)
        assert len(intel["critical"]) == 0
        assert len(intel["info"]) == 1
        assert intel["info"][0]["already_tested"] is True

    def test_high_severity(self):
        results = [
            {"id": "CVE-2026-5555", "severity": "HIGH", "summary": "Auth bypass"},
        ]
        memory = {"tested_cves": [], "tested_endpoints": [], "patterns": []}
        intel = prioritize_intel(results, memory)
        assert len(intel["high"]) == 1

    def test_medium_goes_to_info(self):
        results = [
            {"id": "CVE-2026-3333", "severity": "MEDIUM", "summary": "Info leak"},
        ]
        memory = {"tested_cves": [], "tested_endpoints": [], "patterns": []}
        intel = prioritize_intel(results, memory)
        assert len(intel["info"]) == 1

    def test_matching_patterns(self, memory_dir):
        results = []
        memory = load_memory_context(str(memory_dir), "target.com")
        intel = prioritize_intel(results, memory)
        # alpha.com pattern has nextjs overlap with target.com
        patterns = intel["memory_context"].get("matching_patterns", [])
        assert len(patterns) >= 1
        assert any(p["target"] == "alpha.com" for p in patterns)

    def test_memory_context_fields(self):
        results = []
        memory = {
            "tested_cves": ["CVE-1", "CVE-2"],
            "tested_endpoints": ["/a", "/b", "/c"],
            "patterns": [],
            "last_hunted": "2026-03-20",
            "hunt_sessions": 5,
            "tech_stack": ["react"],
        }
        intel = prioritize_intel(results, memory)
        mc = intel["memory_context"]
        assert mc["tested_endpoints_count"] == 3
        assert mc["tested_cves_count"] == 2
        assert mc["last_hunted"] == "2026-03-20"

    def test_total_count(self):
        results = [
            {"id": "1", "severity": "CRITICAL", "summary": "a"},
            {"id": "2", "severity": "HIGH", "summary": "b"},
            {"id": "3", "severity": "LOW", "summary": "c"},
        ]
        memory = {"tested_cves": [], "tested_endpoints": [], "patterns": []}
        intel = prioritize_intel(results, memory)
        assert intel["total"] == 3


class TestProgramMetaRouting:
    """category="program_meta" entries (program stats + policy/scope) get
    their own bucket -- never misfiled as an "already tested" CVE (their
    id never starts with "CVE"), never silently folded into the invisible
    info-count the way they were before this existed."""

    def test_program_meta_entry_routed_to_its_own_bucket(self):
        results = [
            {"id": "program-policy:acme", "source": "HackerOne/policy",
             "category": "program_meta", "severity": "INFO", "summary": "acme scope: 3 asset(s)"},
        ]
        memory = {"tested_cves": [], "tested_endpoints": [], "patterns": []}
        intel = prioritize_intel(results, memory)
        assert len(intel["program_meta"]) == 1
        assert intel["critical"] == intel["high"] == intel["info"] == []

    def test_program_meta_never_gets_already_tested_note(self):
        # A program-meta id ("program-policy:acme") never starts with
        # "CVE" so the already_tested branch can't fire for it anyway --
        # this pins that the category check short-circuits BEFORE that
        # logic even runs, not just that it happens to be false.
        results = [
            {"id": "program:acme", "source": "HackerOne/stats",
             "category": "program_meta", "severity": "INFO", "summary": "acme: bounty"},
        ]
        memory = {"tested_cves": [], "tested_endpoints": [], "patterns": []}
        intel = prioritize_intel(results, memory)
        assert "already_tested" not in intel["program_meta"][0]

    def test_total_count_includes_program_meta(self):
        results = [
            {"id": "program:acme", "category": "program_meta", "severity": "INFO", "summary": "s"},
            {"id": "CVE-1", "severity": "HIGH", "summary": "h"},
        ]
        memory = {"tested_cves": [], "tested_endpoints": [], "patterns": []}
        intel = prioritize_intel(results, memory)
        assert intel["total"] == 2

    def test_no_program_meta_gives_empty_bucket(self):
        intel = prioritize_intel([], {"tested_cves": [], "tested_endpoints": [], "patterns": []})
        assert intel["program_meta"] == []


class TestFormatOutputProgramSection:

    def _base_intel(self, **overrides):
        base = {"critical": [], "high": [], "info": [], "program_meta": [],
                "memory_context": {}, "total": 0}
        base.update(overrides)
        return base

    def test_no_program_meta_omits_section(self):
        out = format_output("t.example", self._base_intel())
        assert "PROGRAM:" not in out

    def test_program_meta_entry_renders_summary(self):
        intel = self._base_intel(program_meta=[
            {"source": "HackerOne/stats", "summary": "acme: bounty, 42 resolved, avg 3d response"},
        ])
        out = format_output("t.example", intel)
        assert "PROGRAM:" in out
        assert "acme: bounty, 42 resolved, avg 3d response" in out

    def test_policy_scopes_render_as_bulleted_list(self):
        intel = self._base_intel(program_meta=[
            {
                "source": "HackerOne/policy", "summary": "acme scope: 2 asset(s)",
                "policy": {"scopes": [
                    {"identifier": "*.acme.com", "type": "URL", "bounty_eligible": True, "submission_eligible": True},
                    {"identifier": "legacy.acme.com", "type": "URL", "bounty_eligible": False, "submission_eligible": False},
                ]},
            },
        ])
        out = format_output("t.example", intel)
        assert "*.acme.com" in out and "bounty" in out
        assert "legacy.acme.com" in out and "OUT OF SCOPE" in out

    def test_more_than_ten_scopes_truncates_with_a_count(self):
        scopes = [{"identifier": f"asset{i}.acme.com", "type": "URL",
                    "bounty_eligible": True, "submission_eligible": True} for i in range(15)]
        intel = self._base_intel(program_meta=[
            {"source": "HackerOne/policy", "summary": "s", "policy": {"scopes": scopes}},
        ])
        out = format_output("t.example", intel)
        assert "asset0.acme.com" in out
        assert "asset14.acme.com" not in out
        assert "5 more asset(s)" in out


class TestFetchAllIntelProgramMeta:
    """fetch_all_intel()'s program-stats/policy branch -- monkeypatches the
    module-level get_program_stats/get_program_policy functions rather than
    re-testing their own network layer (already covered by
    tests/test_hackerone_server.py)."""

    def test_program_policy_is_fetched_and_tagged(self, monkeypatch):
        monkeypatch.setattr(intel_engine, "H1_MCP_AVAILABLE", True)
        monkeypatch.setattr(intel_engine, "search_disclosed_reports", lambda **kw: [])
        monkeypatch.setattr(intel_engine, "get_program_stats", lambda program: {
            "name": "acme", "offers_bounties": True, "resolved_reports": 10,
            "avg_days_to_first_response": 2, "launched_at": "2020-01-01",
        })
        monkeypatch.setattr(intel_engine, "get_program_policy", lambda program: {
            "program": program, "name": "acme", "offers_bounties": True,
            "policy_text": "safe harbor...",
            "scopes": [
                {"type": "URL", "identifier": "*.acme.com", "bounty_eligible": True,
                 "submission_eligible": True, "instruction": ""},
                {"type": "URL", "identifier": "beta.acme.com", "bounty_eligible": False,
                 "submission_eligible": True, "instruction": "submission only, no payout"},
            ],
        })
        results = intel_engine.fetch_all_intel([], "acme.com", program="acme")
        policy_entries = [r for r in results if r.get("source") == "HackerOne/policy"]
        assert len(policy_entries) == 1
        entry = policy_entries[0]
        assert entry["category"] == "program_meta"
        assert entry["policy"]["scopes"][0]["identifier"] == "*.acme.com"
        assert "1 bounty-eligible" in entry["summary"]
        assert "1 submission-only" in entry["summary"]

    def test_program_policy_error_response_produces_no_entry(self, monkeypatch):
        monkeypatch.setattr(intel_engine, "H1_MCP_AVAILABLE", True)
        monkeypatch.setattr(intel_engine, "search_disclosed_reports", lambda **kw: [])
        monkeypatch.setattr(intel_engine, "get_program_stats", lambda program: {"error": "not found"})
        monkeypatch.setattr(intel_engine, "get_program_policy",
                             lambda program: {"error": f"Program '{program}' not found", "program": program})
        results = intel_engine.fetch_all_intel([], "ghost.com", program="ghost")
        assert not [r for r in results if r.get("source") in ("HackerOne/policy", "HackerOne/stats")]

    def test_no_bounties_flagged_in_summary(self, monkeypatch):
        monkeypatch.setattr(intel_engine, "H1_MCP_AVAILABLE", True)
        monkeypatch.setattr(intel_engine, "search_disclosed_reports", lambda **kw: [])
        monkeypatch.setattr(intel_engine, "get_program_stats", lambda program: {"error": "x"})
        monkeypatch.setattr(intel_engine, "get_program_policy", lambda program: {
            "program": program, "name": "nobounty", "offers_bounties": False,
            "policy_text": "", "scopes": [],
        })
        results = intel_engine.fetch_all_intel([], "nobounty.com", program="nobounty")
        entry = next(r for r in results if r.get("source") == "HackerOne/policy")
        assert "NO BOUNTIES" in entry["summary"]

    def test_no_program_given_never_calls_policy(self, monkeypatch):
        monkeypatch.setattr(intel_engine, "H1_MCP_AVAILABLE", True)
        monkeypatch.setattr(intel_engine, "search_disclosed_reports", lambda **kw: [])

        def _boom(program):
            raise AssertionError("get_program_policy must not be called without --program")
        monkeypatch.setattr(intel_engine, "get_program_policy", _boom)
        monkeypatch.setattr(intel_engine, "get_program_stats", _boom)
        # techs=[] -- avoids a real network call to fetch_github_advisories/
        # fetch_nvd_cves (learn.py), irrelevant to what this test verifies.
        results = intel_engine.fetch_all_intel([], "t.example", program="")
        assert not [r for r in results if r.get("category") == "program_meta"]
