#!/usr/bin/env python3
"""
incremental_recon.py — the "DISCOVER NEW INFORMATION -> RECON AGAIN" step
recon_engine.sh's pipeline never had.

THE GAP THIS CLOSES: recon_engine.sh's 10 phases are strictly linear and
run once — Phase 1 (subdomain enum) never sees anything Phase 4 (URL
collection) or Phase 2.5 (browser intelligence) discover, so a hostname
first referenced by a crawled URL or a real captured API call never gets
probed, fingerprinted, or fed to any downstream tool. `director.py`'s
DEFAULT_CHECKPOINTS (Phase 4 batch) even names this exact gap in prose --
"After browser intelligence exhausted -- re-ingest lead board, look for
new never-called endpoints" -- but nothing ever executes that reminder.

WHERE THE REAL SIGNAL ACTUALLY IS (verified by reading the code, not
assumed): tools/browser_recon.py's own JS-endpoint extraction
(extract_endpoint_strings()) is deliberately path-only ("Pull path-like
string literals... leading '/'") and recon_engine.sh's Phase 5 JS
extraction regex has no `:` in its character class, so neither
js/endpoints.txt nor browser/never-called.json nor browser/routes.json
can ever carry a new HOSTNAME -- only paths. The two sources that
genuinely can are:
  1. urls/all.txt (Phase 4: gau/wayback/katana) -- real crawled/historical
     URLs, already carrying scheme+host, not regex-guessed from JS text.
  2. browser/api-calls.json's calls[].url (Phase 2.5, opt-in) -- real
     browser-observed requests captured by tools/browser_recon.py's
     capture_runtime_api(), the most trustworthy signal of all (an actual
     XHR/fetch a real browser actually made, e.g. app.target.com calling
     api-internal.target.com).

SAFETY: every probe goes through the exact same ScopeChecker + Fetcher
tools/browser_recon.py already uses everywhere else in this codebase --
no new safety model. A candidate host that isn't in scope is filtered out
before any request fires, same fail-closed behavior recon_engine.sh's own
Phase 1.5 already established. Read-only (GET, no_mutate=True) and
capped (--max-new-hosts) -- this is the same class of action as Phase 2's
httpx probing of already-known subdomains, just extended to hosts
revealed later in the same run.

WHAT THIS DELIBERATELY DOES NOT DO: recursively re-crawl a newly
discovered host's own JS for yet more hosts within this one invocation --
that would risk unbounded runtime, against this project's "5-minute
rule"/bounded-execution discipline. A newly merged host becomes a normal
entry in subdomains/all.txt and live/urls.txt, so it's automatically
in scope for --api-capture/browser_recon.py's OWN next run (its own
entry_urls default to ReconAdapter(recon_dir).get_live_hosts()) --
genuine iteration happens by re-running the pipeline, not by an unbounded
loop hidden inside this one tool.

Usage:
  python3 incremental_recon.py TARGET --recon-dir recon/TARGET \\
      --domain '*.TARGET' --i-understand
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from tools.browser_recon import Fetcher, _FETCH_ERRORS, _split_patterns  # noqa: E402
from tools.recon_adapter import ReconAdapter  # noqa: E402
from tools.scope_checker import ScopeChecker  # noqa: E402
from memory.audit_log import AutopilotGuard, RateLimiter  # noqa: E402

DEFAULT_MAX_NEW_HOSTS = 20


_DEFAULT_PORTS = {"https": 443, "http": 80}


def _origin_of(url: str) -> str | None:
    """"scheme://host[:port]" (no path/query) -- preserves the EXACT port a
    URL was actually observed on. Dropping to a bare hostname and
    re-probing on the assumed default port would silently miss a real
    discovery like an internal API on :8443 (a non-standard port is often
    the whole point of it being "hidden"). Port is omitted only when it's
    the scheme's own default, so "https://x.com" and "https://x.com:443"
    dedupe to the same origin."""
    try:
        p = urlparse(url)
    except ValueError:
        return None
    if p.scheme not in ("http", "https") or not p.hostname:
        return None
    host = p.hostname.lower()
    if p.port and p.port != _DEFAULT_PORTS[p.scheme]:
        return f"{p.scheme}://{host}:{p.port}"
    return f"{p.scheme}://{host}"


def discover_candidate_origins(recon_dir: str) -> Counter:
    """"scheme://host[:port]" origins referenced by urls/all.txt (Phase 4:
    real crawled/historical URLs) and browser/api-calls.json's calls[].url
    (Phase 2.5, opt-in: real browser-observed requests), counted by how
    many times each is referenced -- used only to prioritize which origin
    gets probed first when --max-new-hosts caps the list, never as a
    confidence signal. Never raises on missing/malformed input."""
    counts: Counter = Counter()
    adapter = ReconAdapter(recon_dir)
    for url in adapter.get_urls():
        origin = _origin_of(url)
        if origin:
            counts[origin] += 1

    api_calls_path = Path(recon_dir) / "browser" / "api-calls.json"
    if api_calls_path.exists():
        try:
            payload = json.loads(api_calls_path.read_text())
        except (ValueError, OSError):
            payload = None
        if payload is not None:
            calls = payload.get("calls", []) if isinstance(payload, dict) else payload
            if isinstance(calls, list):
                for c in calls:
                    if isinstance(c, dict) and c.get("url"):
                        origin = _origin_of(c["url"])
                        if origin:
                            counts[origin] += 1
    return counts


def new_in_scope_origins(
    recon_dir: str, scope_checker: ScopeChecker, max_new_hosts: int = DEFAULT_MAX_NEW_HOSTS
) -> list[str]:
    """Candidate origins whose HOSTNAME isn't already in subdomains/all.txt
    (a known host on a newly-seen port is still worth a look, but isn't
    the "brand-new asset" case this cap prioritizes -- port-level surface
    is Phase 3's port scan's job, not this tool's), minus anything out of
    scope, most-referenced first (ties broken alphabetically for
    determinism), capped."""
    known_hosts = {h.lower() for h in ReconAdapter(recon_dir).get_subdomains()}
    candidates = discover_candidate_origins(recon_dir)
    new = [o for o in candidates if urlparse(o).hostname not in known_hosts]
    new = [o for o in new if scope_checker.is_in_scope(o + "/")]
    new.sort(key=lambda o: (-candidates[o], o))
    return new[:max_new_hosts]


class IncrementalRecon:
    def __init__(
        self,
        recon_dir: str,
        scope_checker: ScopeChecker,
        *,
        recon_rps: float = 2.0,
        timeout: float = 10.0,
        max_requests: int = 50,
    ):
        self.recon_dir = Path(recon_dir)
        limiter = RateLimiter(recon_rps=recon_rps, test_rps=recon_rps)
        guard = AutopilotGuard(safe_methods_only=True)  # GET-only: this is discovery, never mutation
        self.fetcher = Fetcher(
            scope_checker, no_mutate=True, recon_rps=recon_rps,
            timeout=timeout, max_requests=max_requests, guard=guard, limiter=limiter,
        )

    def probe_origin(self, origin: str) -> dict:
        """One real GET against the EXACT origin that was actually
        observed (no scheme/port guessing -- that's the whole point of
        preserving the real origin instead of a bare hostname). Never
        raises -- every outcome (live, blocked, error) is returned as
        data."""
        host = urlparse(origin).hostname
        url = origin + "/"
        try:
            resp = self.fetcher.get(url)
            return {"host": host, "origin": origin, "url": url, "status": resp.status_code,
                    "live": True, "error": None}
        except _FETCH_ERRORS as exc:
            return {"host": host, "origin": origin, "url": None, "status": None,
                    "live": False, "error": str(exc)}

    def merge_origin(self, host: str, url: str) -> None:
        """Append-if-new to subdomains/all.txt and live/urls.txt -- the
        exact files every downstream tool (lead_board.py ingest,
        director.py build_plan, fingerprint.py, vuln_scanner.sh) already
        reads, so a newly discovered host becomes a first-class citizen of
        the rest of the pipeline with zero new integration surface."""
        subs_path = self.recon_dir / "subdomains" / "all.txt"
        subs_path.parent.mkdir(parents=True, exist_ok=True)
        known = set(ReconAdapter(str(self.recon_dir)).get_subdomains())
        if host not in known:
            with open(subs_path, "a", encoding="utf-8") as f:
                f.write(host + "\n")

        live_path = self.recon_dir / "live" / "urls.txt"
        live_path.parent.mkdir(parents=True, exist_ok=True)
        known_urls = set(ReconAdapter(str(self.recon_dir)).get_live_hosts())
        if url not in known_urls:
            with open(live_path, "a", encoding="utf-8") as f:
                f.write(url + "\n")

    def run(self, origins: list[str]) -> list[dict]:
        results = []
        for origin in origins:
            r = self.probe_origin(origin)
            if r["live"]:
                self.merge_origin(r["host"], r["url"])
            results.append(r)
        return results


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Probe hosts newly referenced in urls/all.txt or browser/api-calls.json "
                     "that aren't already in subdomains/all.txt, and merge the live ones back "
                     "in -- the 'recon again' step recon_engine.sh's linear pipeline never had."
    )
    ap.add_argument("target")
    ap.add_argument("--recon-dir", default=None, help="default: recon/<target>")
    ap.add_argument("--domain", action="append", default=[], required=True,
                     help="In-scope domain pattern (repeatable/comma-separated)")
    ap.add_argument("--exclude-domain", action="append", default=[])
    ap.add_argument("--max-new-hosts", type=int, default=DEFAULT_MAX_NEW_HOSTS)
    ap.add_argument("--recon-rps", type=float, default=2.0)
    ap.add_argument("--i-understand", action="store_true",
                     help="Actually probe candidate hosts. Without this flag, prints what "
                          "would be probed and exits without any network call.")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    recon_dir = args.recon_dir or os.path.join("recon", args.target)
    domains = _split_patterns(args.domain)
    checker = ScopeChecker(domains, _split_patterns(args.exclude_domain))

    candidates = new_in_scope_origins(recon_dir, checker, args.max_new_hosts)

    if not args.i_understand:
        print(f"[DRY-RUN] {len(candidates)} new in-scope origin(s) would be probed:")
        for o in candidates:
            print(f"  {o}")
        print("Pass --i-understand to actually probe them.")
        return 0

    if not candidates:
        print("No new in-scope hosts found (nothing referenced beyond what's already known).")
        return 0

    runner = IncrementalRecon(recon_dir, checker, recon_rps=args.recon_rps)
    results = runner.run(candidates)
    live = [r for r in results if r["live"]]

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            if r["live"]:
                print(f"[+] {r['host']} -> {r['url']} [{r['status']}] (merged)")
            else:
                print(f"[-] {r['host']} -- {r['error']}")
        print(f"\n{len(live)}/{len(results)} new host(s) live and merged into "
              f"subdomains/all.txt + live/urls.txt")

    return 0


if __name__ == "__main__":
    sys.exit(main())
