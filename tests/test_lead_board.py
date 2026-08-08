"""Tests for tools/lead_board.py — recon->skill routing + persistent lead ledger.

Covers the contract that matters: every recon signal maps to the right hunt-*
skill, re-ingesting never wipes a lead's status, and the privileged-path router
does not false-positive on keywords that appear inside a query value.
"""

import json
import multiprocessing as mp

import pytest

import lead_board as lb  # tools/ is on sys.path via tests/conftest.py


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """Point the ledger at a tmp dir so tests never touch real memory/leads/."""
    monkeypatch.setattr(lb, "LEADS_DIR", str(tmp_path / "leads"))
    return tmp_path


def _lead_writer_proc(leads_dir: str, target: str, marker: str, count: int) -> None:
    """Worker for the concurrent-write stress test (top-level so `spawn` can
    pickle it -- mirrors tests/test_rotation.py's _writer_proc convention).

    Sets LEADS_DIR directly rather than relying on inherited/monkeypatched
    module state: under the "fork" start method a child inherits the
    parent's already-patched lb.LEADS_DIR for free, but under "spawn" the
    child re-imports lead_board fresh, so the patch wouldn't survive --
    setting it explicitly here is correct under either start method.
    """
    import lead_board as lb2

    lb2.LEADS_DIR = leads_dir
    for i in range(count):
        lb2.add(target, "hunt-idor", f"https://{target}/api/{marker}/{i}",
                f"{marker}-{i}", "med")


def _lead_touch_proc(leads_dir: str, target: str, lead_id: str, status: str, note: str) -> None:
    """Worker for the touch-vs-add race test -- same explicit-LEADS_DIR
    portability reasoning as _lead_writer_proc above. A bare
    `ctx.Process(target=lb.touch, ...)` would silently operate on the real
    memory/leads/ dir under a "spawn" start method, since a spawned child
    re-imports lead_board fresh and loses the isolated fixture's monkeypatch."""
    import lead_board as lb2

    lb2.LEADS_DIR = leads_dir
    lb2.touch(target, lead_id, status, note)


def _make_recon(tmp_path, urls):
    rd = tmp_path / "recon"
    (rd / "urls").mkdir(parents=True)
    (rd / "urls" / "all.txt").write_text("\n".join(urls) + "\n")
    return str(rd)


def test_routing_maps_signals_to_skills(isolated):
    rd = _make_recon(isolated, [
        "https://t.example/api/v2/users?id=1001",       # -> hunt-idor
        "https://t.example/graphql",                     # -> hunt-graphql
        "https://t.example/fetch?url=https://internal",  # -> hunt-ssrf
        "https://t.example/static/app.js.map",           # -> hunt-source-leak
        "https://t.example/saml2/acs",                   # -> hunt-saml
        "https://t.example/api/chat",                    # -> hunt-llm-ai
    ])
    skills = {l["skill"] for l in lb.ingest("t.example", rd)}
    for expected in ("hunt-idor", "hunt-graphql", "hunt-ssrf",
                     "hunt-source-leak", "hunt-saml", "hunt-llm-ai"):
        assert expected in skills, f"{expected} not routed; got {sorted(skills)}"


def test_reingest_preserves_status_and_dedups(isolated):
    rd = _make_recon(isolated, ["https://t.example/graphql"])
    leads = lb.ingest("t.example", rd)
    n = len(leads)
    gid = next(l["id"] for l in leads if l["skill"] == "hunt-graphql")

    lb.touch("t.example", gid, "investigating", "introspection open")

    leads2 = lb.ingest("t.example", rd)               # same recon, re-run
    assert len(leads2) == n                            # dedup: no growth
    g = next(l for l in leads2 if l["id"] == gid)
    assert g["status"] == "investigating"              # progress preserved
    assert g["note"] == "introspection open"


def test_privileged_path_not_triggered_by_query_value(isolated):
    # 'dashboard' lives in the query string, not the path -> no auth-bypass lead.
    rd = _make_recon(isolated, ["https://t.example/login?next=/dashboard"])
    skills = {l["skill"] for l in lb.ingest("t.example", rd)}
    assert "hunt-auth-bypass" not in skills
    assert "hunt-open-redirect" in skills              # the real signal here


def test_touch_unknown_lead_is_safe(isolated):
    rd = _make_recon(isolated, ["https://t.example/graphql"])
    lb.ingest("t.example", rd)
    lb.touch("t.example", "lb-doesnotexist", "killed", None)  # must not raise
    leads = lb.load_ledger("t.example")
    assert all(l["status"] != "killed" for l in leads)


class TestChainDetection:
    """Correlation: two independently-routed leads on the same target/host
    should synthesize a composite high-priority chain lead."""

    def test_secret_plus_api_same_host_detected(self, isolated):
        rd = _make_recon(isolated, [
            "https://api.t.example/.env",
            "https://api.t.example/api/v2/users?id=1001",
        ])
        leads = lb.ingest("t.example", rd)
        chains = [l for l in leads if l.get("source") == "chain"]
        assert chains, "expected a secret+API chain lead"
        assert chains[0]["priority"] == "high"
        assert chains[0]["chain_name"] == "secret_plus_api"
        assert len(chains[0]["chain_of"]) == 2

    def test_no_chain_without_both_legs(self, isolated):
        rd = _make_recon(isolated, ["https://api.t.example/api/v2/users?id=1001"])
        leads = lb.ingest("t.example", rd)
        assert not [l for l in leads if l.get("source") == "chain"]

    def test_cross_host_chain_is_med_not_high(self, isolated):
        rd = _make_recon(isolated, [
            "https://admin.t.example/.env",
            "https://api.t.example/api/v2/users?id=1001",
        ])
        leads = lb.ingest("t.example", rd)
        chains = [l for l in leads if l.get("source") == "chain"]
        assert chains
        assert all(c["priority"] == "med" for c in chains)

    def test_reingest_does_not_duplicate_chains(self, isolated):
        rd = _make_recon(isolated, [
            "https://api.t.example/.env",
            "https://api.t.example/api/v2/users?id=1001",
        ])
        leads1 = lb.ingest("t.example", rd)
        n_chains_1 = len([l for l in leads1 if l.get("source") == "chain"])
        leads2 = lb.ingest("t.example", rd)
        n_chains_2 = len([l for l in leads2 if l.get("source") == "chain"])
        assert n_chains_1 == n_chains_2
        assert n_chains_1 > 0

    def test_chain_leads_appear_in_show_output(self, isolated, capsys):
        rd = _make_recon(isolated, [
            "https://api.t.example/.env",
            "https://api.t.example/api/v2/users?id=1001",
        ])
        lb.ingest("t.example", rd)
        lb.show("t.example", None)
        out = capsys.readouterr().out
        assert "CHAINS DETECTED" in out

    def test_dot_tar_in_hostname_does_not_false_positive_source_leak(self, isolated):
        # api.target.com contains the substring ".tar" (api.**tar**get.com) —
        # regression guard for the unanchored \.tar false positive.
        rd = _make_recon(isolated, ["https://api.target.com/api/v2/users?id=1001"])
        leads = lb.ingest("target.com", rd)
        assert "hunt-source-leak" not in {l["skill"] for l in leads}

    def test_api_dot_hostname_does_not_false_positive_rest_api_surface(self, isolated):
        # api.t.example contains "//api." right after the scheme -- regression
        # guard for the unanchored /api\b false positive matching the host
        # instead of a real /api path.
        rd = _make_recon(isolated, ["https://api.t.example/.env"])
        leads = lb.ingest("t.example", rd)
        env_leads = [l for l in leads if l["evidence"] == "https://api.t.example/.env"]
        assert "hunt-api-misconfig" not in {l["skill"] for l in env_leads}

    def test_real_api_path_still_matches_rest_api_surface(self, isolated):
        rd = _make_recon(isolated, ["https://t.example/api/v2/orders"])
        leads = lb.ingest("t.example", rd)
        assert "hunt-api-misconfig" in {l["skill"] for l in leads}


class TestHypothesisEngine:
    """3-way correlations (Phase 3 attack graph): secret + API + weak auth,
    all on the same host, should rise to a named vulnerability hypothesis
    with an explicit impact — not just an elevated chain lead."""

    def test_three_way_same_host_produces_hypothesis(self, isolated):
        rd = _make_recon(isolated, [
            "https://api.t.example/.env",
            "https://api.t.example/api/v2/users?id=1001",
            "https://api.t.example/login?next=/dashboard",
        ])
        leads = lb.ingest("t.example", rd)
        hyps = [l for l in leads if l.get("source") == "hypothesis"]
        assert hyps, "expected an account-takeover hypothesis"
        assert hyps[0]["chain_name"] == "account_takeover_via_leaked_secret"
        assert hyps[0]["impact"] == "critical"
        assert len(hyps[0]["chain_of"]) == 3

    def test_cross_host_does_not_produce_hypothesis(self, isolated):
        rd = _make_recon(isolated, [
            "https://admin.t.example/.env",
            "https://api.t.example/api/v2/users?id=1001",
            "https://other.t.example/login?next=/dashboard",
        ])
        leads = lb.ingest("t.example", rd)
        assert not [l for l in leads if l.get("source") == "hypothesis"]

    def test_missing_leg_produces_no_hypothesis(self, isolated):
        rd = _make_recon(isolated, [
            "https://api.t.example/.env",
            "https://api.t.example/api/v2/users?id=1001",
        ])
        leads = lb.ingest("t.example", rd)
        assert not [l for l in leads if l.get("source") == "hypothesis"]

    def test_same_url_cannot_fill_two_legs(self, isolated):
        # A single URL matching multiple skills in one leg's skill set is one
        # real artifact, not grounds for a duplicate hypothesis.
        rd = _make_recon(isolated, [
            "https://api.t.example/.env",
            "https://api.t.example/api/v2/users?id=1001",  # matches idor AND api-misconfig
            "https://api.t.example/login?next=/dashboard",
        ])
        leads = lb.ingest("t.example", rd)
        hyps = [l for l in leads if l.get("source") == "hypothesis"]
        # exactly one hypothesis, not one per (idor-lead, api-misconfig-lead) pairing
        assert len(hyps) == 1

    def test_reingest_does_not_duplicate_hypotheses(self, isolated):
        rd = _make_recon(isolated, [
            "https://api.t.example/.env",
            "https://api.t.example/api/v2/users?id=1001",
            "https://api.t.example/login?next=/dashboard",
        ])
        leads1 = lb.ingest("t.example", rd)
        n1 = len([l for l in leads1 if l.get("source") == "hypothesis"])
        leads2 = lb.ingest("t.example", rd)
        n2 = len([l for l in leads2 if l.get("source") == "hypothesis"])
        assert n1 == n2 > 0

    def test_hypothesis_leads_appear_in_show_output(self, isolated, capsys):
        rd = _make_recon(isolated, [
            "https://api.t.example/.env",
            "https://api.t.example/api/v2/users?id=1001",
            "https://api.t.example/login?next=/dashboard",
        ])
        lb.ingest("t.example", rd)
        lb.show("t.example", None)
        out = capsys.readouterr().out
        assert "VULNERABILITY HYPOTHESES" in out
        assert "Account Takeover" in out


class TestAttackGraph:

    def test_graph_has_asset_and_endpoint_nodes(self, isolated):
        rd = _make_recon(isolated, ["https://t.example/graphql"])
        lb.ingest("t.example", rd)
        g = lb.build_graph("t.example")
        types = {n["type"] for n in g["nodes"]}
        assert "asset" in types
        assert "endpoint" in types

    def test_graph_links_hypothesis_to_impact(self, isolated):
        rd = _make_recon(isolated, [
            "https://api.t.example/.env",
            "https://api.t.example/api/v2/users?id=1001",
            "https://api.t.example/login?next=/dashboard",
        ])
        lb.ingest("t.example", rd)
        g = lb.build_graph("t.example")
        hyp_nodes = [n for n in g["nodes"] if n["type"] == "vulnerability_hypothesis"]
        impact_nodes = [n for n in g["nodes"] if n["type"] == "impact"]
        assert hyp_nodes and impact_nodes
        hyp_id = hyp_nodes[0]["id"]
        assert any(e["from"] == hyp_id and e["to"] == impact_nodes[0]["id"] for e in g["edges"])

    def test_graph_json_serializable(self, isolated):
        rd = _make_recon(isolated, ["https://t.example/graphql"])
        lb.ingest("t.example", rd)
        g = lb.build_graph("t.example")
        import json
        json.dumps(g)  # must not raise

    def test_print_graph_handles_no_hypotheses(self, isolated, capsys):
        rd = _make_recon(isolated, ["https://t.example/graphql"])
        lb.ingest("t.example", rd)
        lb.print_graph("t.example")
        out = capsys.readouterr().out
        assert "ATTACK SURFACE GRAPH" in out
        assert "no correlated hypotheses" in out


class TestConcurrentWrites:
    """Critical finding (security review, 2026-08-08): save_ledger() was a
    plain unlocked open(path, "w") full-rewrite and load_ledger() an
    unlocked read -- two concurrent add()/touch()/ingest() calls on the
    same target could each read the same pre-mutation state and the
    second writer's save_ledger() would silently clobber the first
    writer's leads. _locked_ledger() now holds a single fcntl.flock(LOCK_EX)
    (mirroring memory/rotation.py's rotate_if_needed() exactly) across the
    whole load -> mutate -> save cycle, so this must hold under REAL
    concurrent OS processes, not sequential calls in one test process.
    """

    def test_concurrent_add_no_lost_leads(self, isolated):
        target = "race.example"
        leads_dir = str(isolated / "leads")
        n_writers = 4
        per_writer = 25

        ctx = mp.get_context("fork") if "fork" in mp.get_all_start_methods() else mp.get_context()
        procs = [
            ctx.Process(target=_lead_writer_proc, args=(leads_dir, target, f"w{i}", per_writer))
            for i in range(n_writers)
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join(timeout=60)
            assert p.exitcode == 0, f"writer {p.pid} crashed: {p.exitcode}"

        # Every writer's leads must have survived -- this is the actual
        # "no lead is lost" assertion. Without the lock, concurrent
        # save_ledger() overwrites make this count come up short and flaky.
        leads = lb.load_ledger(target)
        assert len(leads) == n_writers * per_writer, (
            f"expected {n_writers * per_writer} leads, got {len(leads)} -- "
            "a concurrent save_ledger() overwrite lost leads"
        )

        # No duplicates, no truncated/corrupted lines, every (marker, i)
        # pair present -- proves the ledger file itself is intact, not
        # just the right line count by coincidence.
        seen = {tuple(ld["signal"].split("-")) for ld in leads}
        expected = {(f"w{w}", str(i)) for w in range(n_writers) for i in range(per_writer)}
        assert seen == expected

        # File on disk must also be well-formed JSONL end to end (no torn
        # writes interleaved by the race).
        with open(lb.ledger_path(target)) as fh:
            lines = [ln for ln in fh if ln.strip()]
        assert len(lines) == n_writers * per_writer
        for ln in lines:
            json.loads(ln)  # must not raise

    def test_concurrent_ingest_and_touch_no_lost_leads(self, isolated):
        """ingest() and touch() share the same lock as add() -- prove a
        write-heavy ingest race doesn't drop leads either, using the same
        real-process harness as the add() test above."""
        target = "race2.example"
        leads_dir = str(isolated / "leads")
        n_writers = 3
        per_writer = 20

        ctx = mp.get_context("fork") if "fork" in mp.get_all_start_methods() else mp.get_context()
        procs = [
            ctx.Process(target=_lead_writer_proc, args=(leads_dir, target, f"m{i}", per_writer))
            for i in range(n_writers)
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join(timeout=60)
            assert p.exitcode == 0

        leads = lb.load_ledger(target)
        assert len(leads) == n_writers * per_writer

        # Concurrently touch a lead that definitely exists (written by w0)
        # while re-adding more leads -- same race shape ingest() hits when
        # a hunter re-runs recon while marking leads investigating.
        first_id = next(l["id"] for l in leads if l["signal"] == "m0-0")
        touch_procs = [
            ctx.Process(target=_lead_writer_proc, args=(leads_dir, target, "extra", 10)),
            ctx.Process(target=_lead_touch_proc, args=(leads_dir, target, first_id, "investigating", "racing")),
        ]
        for p in touch_procs:
            p.start()
        for p in touch_procs:
            p.join(timeout=60)
            assert p.exitcode == 0

        final = lb.load_ledger(target)
        assert len(final) == n_writers * per_writer + 10  # no leads lost to the touch race
        touched = next(l for l in final if l["id"] == first_id)
        assert touched["status"] == "investigating"
