#!/usr/bin/env python3
"""
idor_diff.py — generic cross-session IDOR/BOLA diff tester for arbitrary
bug-bounty targets.

THE GAP THIS CLOSES: skills/web2-vuln-classes/SKILL.md's IDOR section (and
agents/autopilot.md's Step "For IDOR / privilege-escalation hunts, ask
whether a second low-priv session is available so we can diff behavior
between identities") both describe the two-session-diff methodology in
prose only — "load both via --auth-file and diff" — but nothing in the
codebase actually executes that diff. tools/h1_idor_scanner.py has the
right diff DISCIPLINE (never auto-flag on a non-null response; require
B's response to genuinely reproduce A's data) but is hardcoded to
HackerOne's own GraphQL/REST schema (query shapes like `report(id:)`,
`team(handle:)`) — it cannot be pointed at an arbitrary target's API and
was never meant to be generalized that way. This module reuses
h1_idor_scanner.py's diff discipline, generalized to arbitrary JSON/text
HTTP responses, driven by tools/browser_recon.py's already scope-gated,
rate-limited, circuit-breaker-protected Fetcher (no new HTTP client, no
new safety model) instead of a bespoke urllib client.

SECOND GAP THIS CLOSES: memory/object_model.py's detect_relationship_
violations() has been real, tested, and wired to tools/director.py's
object_model_leads() since Phase 6 — but nothing in the live pipeline ever
recorded a relationship-ESTABLISHING Observation (the module's own
discipline forbids inferring OWNS from a URL/field name; it requires "a
human, an agent, or a Part 3 stateful-session workflow" to assert it from
genuine out-of-band knowledge). --owner is exactly that: the hunter
asserting "I know Account A legitimately owns this specific resource"
(e.g. they created it under Account A during recon), which is real
out-of-band knowledge, not a naming-based guess. When a candidate URL is
flagged AND --owner is given, this module now records that assertion as a
real `created` Observation (establishes OWNS) alongside the non-owner's
`accessed` Observation -- the first real producer detect_relationship_
violations() has ever had in a live hunt.

DISCLOSED LIMITATION (inherited from h1_idor_scanner.py, not solved here):
identical data returned to two identities is evidence of a POSSIBLE IDOR,
never proof — it cannot distinguish "B illegitimately saw A's private
data" from "this field/endpoint is legitimately public/shared for every
authenticated user" (e.g. a public product catalog). A human or a
downstream validation step must still judge sensitivity before this
becomes a reportable finding. Never auto-escalates past "candidate."

Usage:
  python3 idor_diff.py TARGET --recon-dir recon/TARGET \\
      --session-a-file .private/account_a.json \\
      --session-b-file .private/account_b.json \\
      --domain '*.TARGET' --auto --i-understand

  python3 idor_diff.py TARGET --url https://TARGET/api/orders/1042 \\
      --session-a-file .private/account_a.json \\
      --session-b-file .private/account_b.json \\
      --owner a --domain '*.TARGET' --i-understand
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from tools.auth_session import AuthSession  # noqa: E402
from tools.browser_recon import Fetcher, _split_patterns  # noqa: E402
from tools.scope_checker import ScopeChecker  # noqa: E402
import tools.lead_board as lead_board  # noqa: E402
from memory.audit_log import AutopilotGuard, RateLimiter  # noqa: E402
from memory.identity import entity_id, object_id  # noqa: E402
from memory.object_model import ObservationStore, make_observation  # noqa: E402

import requests  # noqa: E402

DEFAULT_MAX_URLS = 25
_MIN_BODY_LEN_FOR_TEXT_MATCH = 20  # avoid flagging trivially-identical short bodies ("OK", "{}")

# Mirrors tools/lead_board.py's own hunt-idor routing regex (query-param
# numeric object ref) plus a path-segment variant it doesn't cover — kept
# as a local copy rather than importing lead_board.ROUTES's internals,
# which aren't structured for external reuse of one pattern.
_ID_QUERY_RE = re.compile(
    r"[?&](id|uid|user_id|userid|account|account_id|order|order_id|invoice|doc|doc_id|"
    r"file_id|record|profile|customer|cid|pid|num|no|key)=[\w-]+",
    re.I,
)
_ID_PATH_RE = re.compile(
    r"/(?:\d{2,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[/?]|$)",
    re.I,
)


def looks_object_scoped(url: str) -> bool:
    """True if `url` plausibly references a specific object (numeric/UUID
    id in a query param or a path segment) -- the same class of signal
    lead_board.py's hunt-idor router already keys on, generalized to also
    catch path-segment ids."""
    return bool(_ID_QUERY_RE.search(url) or _ID_PATH_RE.search(url))


def discover_candidate_urls(recon_dir: str, max_urls: int) -> list[str]:
    """Best-effort: recon/<target>/urls/{with_params,api_endpoints}.txt,
    filtered to object-scoped-looking URLs, deduped, capped. Never raises
    on a missing/malformed recon dir -- returns []."""
    urls: list[str] = []
    seen: set[str] = set()
    for fname in ("with_params.txt", "api_endpoints.txt"):
        path = Path(recon_dir) / "urls" / fname
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line or line in seen or not looks_object_scoped(line):
                continue
            seen.add(line)
            urls.append(line)
            if len(urls) >= max_urls:
                return urls
    return urls


# ─── Diff logic (generalizes h1_idor_scanner.py's is_same_data()/check()) ──

def _parse_json_or_none(text: str):
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def is_meaningfully_equal(resp_a: requests.Response, resp_b: requests.Response) -> tuple[bool, str]:
    """Returns (matched, reason). Never flags on "B got SOME non-null
    response" alone -- same discipline as h1_idor_scanner.py's check():
    B's response must genuinely reproduce A's substantive data, not merely
    exist. Both responses must be 2xx (a shared error page is not evidence
    of anything)."""
    if not (200 <= resp_a.status_code < 300 and 200 <= resp_b.status_code < 300):
        return False, f"status codes not both 2xx (A={resp_a.status_code}, B={resp_b.status_code})"

    json_a = _parse_json_or_none(resp_a.text)
    json_b = _parse_json_or_none(resp_b.text)
    if json_a is not None or json_b is not None:
        if json_a is None or json_b is None:
            return False, "one response is JSON, the other isn't"
        if json_a in (None, {}, []) or json_b in (None, {}, []):
            return False, "empty/null JSON body -- nothing to compare"
        if json_a == json_b:
            return True, "identical JSON body returned to both sessions"
        return False, "JSON bodies differ"

    # Neither is JSON -- fall back to raw text equality, guarded against
    # trivially-identical short bodies (an empty-ish error page, "OK", …).
    body_a, body_b = resp_a.text.strip(), resp_b.text.strip()
    if len(body_a) < _MIN_BODY_LEN_FOR_TEXT_MATCH:
        return False, "body too short to be meaningful evidence"
    if body_a == body_b:
        return True, "identical response body returned to both sessions"
    return False, "response bodies differ"


class IdorDiffRunner:
    def __init__(
        self,
        target: str,
        scope_checker: ScopeChecker,
        session_a: AuthSession,
        session_b: AuthSession,
        *,
        owner: str | None = None,
        memory_dir: str | None = None,
        recon_rps: float = 2.0,
        timeout: float = 15.0,
        max_requests: int = 200,
    ):
        self.target = target
        self.owner = owner
        self.memory_dir = memory_dir
        self.session_a, self.session_b = session_a, session_b
        self.findings: list[dict] = []

        limiter = RateLimiter(recon_rps=recon_rps, test_rps=recon_rps)
        guard = AutopilotGuard(safe_methods_only=True)  # GET-only: read-only comparison, never mutate
        req_a = requests.Session()
        req_a.headers.update(session_a.headers_dict())
        req_b = requests.Session()
        req_b.headers.update(session_b.headers_dict())
        self.fetcher_a = Fetcher(scope_checker, no_mutate=True, recon_rps=recon_rps,
                                  timeout=timeout, max_requests=max_requests, guard=guard,
                                  limiter=limiter, session=req_a)
        self.fetcher_b = Fetcher(scope_checker, no_mutate=True, recon_rps=recon_rps,
                                  timeout=timeout, max_requests=max_requests, guard=guard,
                                  limiter=limiter, session=req_b)

        self._observation_store = None
        if memory_dir:
            om_path = Path(memory_dir) / "object_model" / f"{target}.jsonl"
            self._observation_store = ObservationStore(om_path)

    def _record_observations(self, url: str, resp_a: requests.Response, resp_b: requests.Response) -> None:
        if self._observation_store is None:
            return
        obj_ref = object_id("http-endpoint", url)
        owner_session, owner_resp, other_session, other_resp = (
            (self.session_a, resp_a, self.session_b, resp_b) if self.owner == "a"
            else (self.session_b, resp_b, self.session_a, resp_a) if self.owner == "b"
            else (None, None, None, None)
        )
        if owner_session is not None:
            self._observation_store.record(make_observation(
                subject_id=entity_id("User", owner_session.session_id()),
                object_ref=obj_ref,
                event="created",
                evidence=[{
                    "type": "Human-Input",
                    "detail": f"hunter-asserted resource owner via idor_diff.py --owner "
                              f"(genuine out-of-band knowledge, not inferred from the URL)",
                    "artifact": url,
                }],
                outcome_status=owner_resp.status_code,
                metadata={"target": self.target, "tool": "idor_diff"},
            ))
            other_obs_session, other_obs_resp = other_session, other_resp
        else:
            # No --owner given -- record both sides as plain behavioral
            # "accessed" facts only (matches api_call_observer.py's own
            # conservative default: real evidence, but no relationship
            # claim without an explicit establishing event).
            for s, r in ((self.session_a, resp_a), (self.session_b, resp_b)):
                self._observation_store.record(make_observation(
                    subject_id=entity_id("User", s.session_id()),
                    object_ref=obj_ref,
                    event="accessed",
                    evidence=[{
                        "type": "Observed-HTTP-Response",
                        "detail": f"idor_diff.py cross-session match on {url} -> {r.status_code}",
                        "artifact": url,
                    }],
                    outcome_status=r.status_code,
                    metadata={"target": self.target, "tool": "idor_diff"},
                ))
            return
        self._observation_store.record(make_observation(
            subject_id=entity_id("User", other_obs_session.session_id()),
            object_ref=obj_ref,
            event="accessed",
            evidence=[{
                "type": "Observed-HTTP-Response",
                "detail": f"idor_diff.py cross-session match on {url} -> {other_obs_resp.status_code}",
                "artifact": url,
            }],
            outcome_status=other_obs_resp.status_code,
            metadata={"target": self.target, "tool": "idor_diff"},
        ))

    def test_url(self, url: str) -> dict:
        result = {"url": url, "matched": False, "reason": None, "error": None}
        try:
            resp_a = self.fetcher_a.get(url)
            resp_b = self.fetcher_b.get(url)
        except Exception as exc:  # ScopeViolation, RequestBlocked, RequestCapExceeded, network errors
            result["error"] = str(exc)
            return result

        matched, reason = is_meaningfully_equal(resp_a, resp_b)
        result["matched"] = matched
        result["reason"] = reason
        result["status_a"] = resp_a.status_code
        result["status_b"] = resp_b.status_code

        if matched:
            self.findings.append(result)
            lead_board.add(
                self.target, "hunt-idor", url,
                signal="idor_diff cross-session match",
                priority="high",
            )
            self._record_observations(url, resp_a, resp_b)
        return result

    def run(self, urls: list[str]) -> list[dict]:
        return [self.test_url(u) for u in urls]


def print_result(r: dict) -> None:
    if r["error"]:
        print(f"  [ERROR] {r['url']} — {r['error']}")
    elif r["matched"]:
        print(f"\n{'='*60}")
        print(f"  [CANDIDATE IDOR] {r['url']}")
        print(f"  {r['reason']}")
        print(f"  Session A: HTTP {r['status_a']}   Session B: HTTP {r['status_b']}")
        print(f"  NOT PROOF on its own — could be legitimately public/shared data.")
        print(f"  A human (or a downstream validation step) must judge sensitivity")
        print(f"  before this is a reportable finding.")
        print(f"{'='*60}")
    else:
        print(f"  [{r['reason'] or 'no match'}] {r['url']}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Generic cross-session IDOR/BOLA diff tester — generalizes "
                     "h1_idor_scanner.py's diff discipline to arbitrary targets."
    )
    ap.add_argument("target")
    ap.add_argument("--recon-dir", default=None, help="default: recon/<target> (used by --auto)")
    ap.add_argument("--memory-dir", default="hunt-memory",
                     help="Where to record Object Model observations (default: hunt-memory)")
    ap.add_argument("--session-a-file", required=True, help="AuthSession JSON/.env file — the resource owner's session")
    ap.add_argument("--session-b-file", required=True, help="AuthSession JSON/.env file — the session being tested for cross-access")
    ap.add_argument("--owner", choices=["a", "b"], default=None,
                     help="Assert which session genuinely owns the tested resource(s) "
                          "(real out-of-band knowledge, e.g. 'I created this under Account A') "
                          "-- records a relationship-establishing Observation on a match, "
                          "not just a behavioral one. Omit if ownership isn't actually known.")
    ap.add_argument("--url", action="append", default=[], help="Explicit URL to test (repeatable)")
    ap.add_argument("--auto", action="store_true",
                     help="Also auto-discover object-scoped candidate URLs from --recon-dir")
    ap.add_argument("--max-urls", type=int, default=DEFAULT_MAX_URLS)
    ap.add_argument("--domain", action="append", default=[], required=True,
                     help="In-scope domain pattern (repeatable/comma-separated) — required, "
                          "every request is scope-checked before it fires")
    ap.add_argument("--exclude-domain", action="append", default=[])
    ap.add_argument("--recon-rps", type=float, default=2.0)
    ap.add_argument("--i-understand", action="store_true",
                     help="Actually fire cross-session requests. Without this flag, prints "
                          "a dry-run summary of what would run and exits without any network call.")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    recon_dir = args.recon_dir or os.path.join("recon", args.target)
    urls = list(dict.fromkeys(args.url))
    if args.auto:
        for u in discover_candidate_urls(recon_dir, args.max_urls):
            if u not in urls:
                urls.append(u)
    urls = urls[: args.max_urls]

    if not urls:
        print("ERROR: no URLs to test — pass --url and/or --auto with a populated recon dir", file=sys.stderr)
        return 1

    session_a = AuthSession.from_file(args.session_a_file)
    session_b = AuthSession.from_file(args.session_b_file)
    if session_a.is_empty() or session_b.is_empty():
        print("ERROR: both --session-a-file and --session-b-file must load at least one header", file=sys.stderr)
        return 1
    if session_a.session_id() == session_b.session_id():
        print("ERROR: session A and session B resolve to the identical header set — "
              "this would never detect anything (comparing an identity to itself)", file=sys.stderr)
        return 1

    if not args.i_understand:
        print(f"[DRY-RUN] Would test {len(urls)} URL(s) against {args.target} under two sessions "
              f"(A={session_a.session_id()}, B={session_b.session_id()}).")
        for u in urls:
            print(f"  {u}")
        print("Pass --i-understand to actually run it (only against a program you "
              "have written authorization to test this way).")
        return 0

    domains = _split_patterns(args.domain)
    checker = ScopeChecker(domains, _split_patterns(args.exclude_domain))
    runner = IdorDiffRunner(
        args.target, checker, session_a, session_b,
        owner=args.owner, memory_dir=args.memory_dir, recon_rps=args.recon_rps,
    )

    print(f"idor_diff — {args.target}")
    print(f"Session A: {session_a.describe()}")
    print(f"Session B: {session_b.describe()}")
    print(f"Testing {len(urls)} URL(s)...\n")

    results = runner.run(urls)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print_result(r)
        print(f"\n{'='*60}")
        print(f"  {len(runner.findings)} candidate IDOR finding(s) out of {len(urls)} URL(s) tested")
        print(f"{'='*60}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
