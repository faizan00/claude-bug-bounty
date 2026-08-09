#!/usr/bin/env python3
"""
business_logic_probe.py — mutation-gated producer for memory/object_model.py
Part 2 (rules/logic_patterns.yaml's business-logic taxonomy).

THE GAP THIS CLOSES: memory/object_model.py's detect_logic_pattern_violations()
has been real, tested, and wired to tools/director.py's object_model_leads()
since Phase 6 — same as Part 1's detect_relationship_violations() before
tools/idor_diff.py closed that gap. But every one of the 7 patterns in
rules/logic_patterns.yaml (invite_flow, ownership_transfer, tenant_isolation,
billing, refund, coupon, role_escalation) has a hard GATE: "if the object
model has ZERO observed instances of ANY of the pattern's
required_relationships, the pattern does NOT execute at all." Nothing in
the live pipeline had ever recorded a relationship-establishing Observation
for CAN_INVITE/HAS_MEMBER/OWNS (idor_diff.py's --owner covers OWNS for
Part 1's ownership_violation/tenant_isolation_violation only), so every
one of these 6 patterns has been permanently gated shut since Phase 6.

UNLIKE idor_diff.py (read-only, GET-only by construction), 6 of these 7
patterns key on a genuinely MUTATING action (an invite, a refund, a coupon
redemption, an ownership transfer, a role assignment) — testing them means
actually sending that request. This is real-world impact on a live target,
gated by TWO independent, explicit consent flags: --i-understand (this
tool's own gate, same convention as h1_mutation_idor.py/idor_diff.py) AND
--allow-mutate (tools/browser_recon.py's Fetcher's own pre-existing
mutation gate — passing --i-understand alone still leaves Fetcher's
AutopilotGuard blocking any non-GET method). Every probe fires its
mutating request EXACTLY ONCE per invocation — no retry loop, no
brute-forcing a result.

TWO-STEP WORKFLOW, matching each pattern's real precondition structure
(RELATIONSHIP GRAMMAR is fixed per event type — memory/object_model.py's
module docstring — not itself data-driven, so this tool's per-pattern
field mapping is a hardcoded table, VALIDATED against the loaded YAML at
startup so a future edit to rules/logic_patterns.yaml that changes a
pattern's shape fails loud here rather than silently mis-recording):

  1. --establish: record that a SPECIFIC session genuinely holds the
     required relationship (e.g. "Account A holds CAN_INVITE on org 42")
     — real out-of-band knowledge the hunter asserts, same discipline as
     idor_diff.py's --owner. Without at least one such observation on
     record for the target, the gate never opens and step 2 can only ever
     produce a behavioral fact, never a violation Candidate.
  2. --probe: fire ONE request as a DIFFERENT session (one the hunter
     believes does NOT hold that relationship) against the real mutating
     endpoint, and record the real outcome. If the request succeeds (2xx)
     and the object model's relationship graph shows that actor never
     held the required relationship, detect_logic_pattern_violations()
     fires immediately (checked synchronously at the end of this same
     invocation — the hunter doesn't need a separate director.py call to
     find out).

Usage:
  # Step 1 — assert Account A genuinely holds CAN_INVITE on org "42"
  # (the hunter knows this because they're logged in as a legitimate
  # member with invite rights).
  python3 business_logic_probe.py target.com --pattern invite_flow --establish \\
      --holder-session-file .private/account_a.json --org-ref 42 \\
      --memory-dir hunt-memory

  # Step 2 — probe: does the server let Account B (no CAN_INVITE grant)
  # actually invite someone into org 42?
  python3 business_logic_probe.py target.com --pattern invite_flow --probe \\
      --acting-session-file .private/account_b.json --org-ref 42 \\
      --target-ref newuser@example.com \\
      --method POST --url 'https://target.com/api/orgs/42/invite' \\
      --data '{"email":"newuser@example.com"}' \\
      --domain target.com --i-understand --allow-mutate --memory-dir hunt-memory
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from tools.auth_session import AuthSession  # noqa: E402
from tools.browser_recon import Fetcher  # noqa: E402
from tools.scope_checker import ScopeChecker  # noqa: E402
import tools.lead_board as lead_board  # noqa: E402
from memory.audit_log import AutopilotGuard, RateLimiter  # noqa: E402
from memory.identity import entity_id, object_id  # noqa: E402
from memory.object_model import (  # noqa: E402
    ObservationStore, make_observation, load_logic_patterns,
    detect_logic_pattern_violations, LogicPatternLoadError,
)

import requests  # noqa: E402


@dataclass(frozen=True)
class PatternSpec:
    """Hardcoded, per-pattern field mapping — cross-validated against the
    live rules/logic_patterns.yaml at startup (see _validate_spec_matches_yaml).
    RELATIONSHIP GRAMMAR (memory/object_model.py's module docstring) is
    fixed per event type, so `establish_event` below isn't a guess, it's
    that grammar read literally for each pattern's own
    required_relationships[0]."""
    establish_relationship: str       # what --establish records (CAN_INVITE / HAS_MEMBER / OWNS) --
                                       # this alone determines the RELATIONSHIP GRAMMAR's subject/object
                                       # roles (see establish()), so no separate direction field is needed.
    establish_event: str              # the OBSERVATION_EVENTS value that establishes it
    action_event: str
    action_context: str | None
    performed_by_field: str           # "subject_id" or "metadata.performed_by" -- matched against YAML
    governing_object_field: str       # "subject_id", "object_id", or "metadata.organization_id"
    action_is_mutating: bool          # False only for tenant_isolation (a plain GET)
    object_type: str                  # label for memory.identity.object_id()'s object_type bucket


PATTERN_SPECS: dict[str, PatternSpec] = {
    "invite_flow": PatternSpec(
        establish_relationship="CAN_INVITE", establish_event="invite_capability_granted",
        action_event="membership_granted", action_context=None,
        performed_by_field="metadata.performed_by", governing_object_field="subject_id",
        action_is_mutating=True, object_type="User",
    ),
    "role_escalation": PatternSpec(
        establish_relationship="CAN_INVITE", establish_event="invite_capability_granted",
        action_event="membership_granted", action_context="role_assignment",
        performed_by_field="metadata.performed_by", governing_object_field="subject_id",
        action_is_mutating=True, object_type="User",
    ),
    "ownership_transfer": PatternSpec(
        establish_relationship="OWNS", establish_event="created",
        action_event="ownership_transferred", action_context=None,
        performed_by_field="metadata.performed_by", governing_object_field="object_id",
        action_is_mutating=True, object_type="Resource",
    ),
    "billing": PatternSpec(
        establish_relationship="HAS_MEMBER", establish_event="membership_granted",
        action_event="modified", action_context="billing",
        performed_by_field="subject_id", governing_object_field="metadata.organization_id",
        action_is_mutating=True, object_type="BillingRecord",
    ),
    "refund": PatternSpec(
        establish_relationship="HAS_MEMBER", establish_event="membership_granted",
        action_event="modified", action_context="refund",
        performed_by_field="subject_id", governing_object_field="metadata.organization_id",
        action_is_mutating=True, object_type="Refund",
    ),
    "coupon": PatternSpec(
        establish_relationship="HAS_MEMBER", establish_event="membership_granted",
        action_event="modified", action_context="coupon",
        performed_by_field="subject_id", governing_object_field="metadata.organization_id",
        action_is_mutating=True, object_type="Coupon",
    ),
    "tenant_isolation": PatternSpec(
        establish_relationship="HAS_MEMBER", establish_event="membership_granted",
        action_event="accessed", action_context=None,
        performed_by_field="subject_id", governing_object_field="metadata.organization_id",
        action_is_mutating=False, object_type="http-endpoint",
    ),
}


def _validate_spec_matches_yaml(pattern_id: str, spec: PatternSpec, patterns_path: str | None = None) -> None:
    """Raise loudly if rules/logic_patterns.yaml has drifted from this
    tool's hardcoded understanding of a pattern's shape -- 'never guess'
    applies here too: a silently-wrong field mapping would record an
    Observation detect_logic_pattern_violations() reads incorrectly."""
    patterns = {p.id: p for p in load_logic_patterns(patterns_path)}
    if pattern_id not in patterns:
        raise ValueError(f"pattern {pattern_id!r} not found in rules/logic_patterns.yaml "
                          f"(known: {sorted(PATTERN_SPECS)})")
    p = patterns[pattern_id]
    mismatches = []
    if p.action_event != spec.action_event:
        mismatches.append(f"action_event: yaml={p.action_event!r} tool={spec.action_event!r}")
    if p.action_context != spec.action_context:
        mismatches.append(f"action_context: yaml={p.action_context!r} tool={spec.action_context!r}")
    if p.performed_by != spec.performed_by_field:
        mismatches.append(f"performed_by: yaml={p.performed_by!r} tool={spec.performed_by_field!r}")
    if p.governing_object != spec.governing_object_field:
        mismatches.append(f"governing_object: yaml={p.governing_object!r} tool={spec.governing_object_field!r}")
    if p.requires_active_relationship != spec.establish_relationship:
        mismatches.append(
            f"requires_active_relationship: yaml={p.requires_active_relationship!r} "
            f"tool={spec.establish_relationship!r}"
        )
    if mismatches:
        raise ValueError(
            f"rules/logic_patterns.yaml#{pattern_id} no longer matches this tool's hardcoded "
            f"PATTERN_SPECS -- refusing to record a possibly-wrong Observation. Mismatches: "
            f"{'; '.join(mismatches)}"
        )


def establish(target: str, pattern_id: str, holder_session: AuthSession, org_ref: str,
              memory_dir: str, object_ref: str | None = None) -> dict:
    """Record a real relationship-establishing Observation: `holder_session`
    genuinely holds `spec.establish_relationship` — asserted by the hunter
    from real out-of-band knowledge (they're logged in as this account and
    know it has this grant), never inferred."""
    spec = PATTERN_SPECS[pattern_id]
    _validate_spec_matches_yaml(pattern_id, spec)
    holder_ref = entity_id("User", holder_session.session_id())
    org = entity_id("Organization", org_ref)

    if spec.establish_relationship == "HAS_MEMBER":
        subject_ref, object_ref_full = org, holder_ref
    elif spec.establish_relationship == "CAN_INVITE":
        subject_ref, object_ref_full = holder_ref, org
    else:  # OWNS
        if not object_ref:
            raise ValueError("--object-ref is required to establish OWNS (what does the holder own?)")
        subject_ref, object_ref_full = holder_ref, object_id(spec.object_type, object_ref)

    obs = make_observation(
        subject_id=subject_ref, object_ref=object_ref_full, event=spec.establish_event,
        evidence=[{
            "type": "Human-Input",
            "detail": f"hunter-asserted {spec.establish_relationship} holder via "
                      f"business_logic_probe.py --establish (genuine out-of-band knowledge)",
            "artifact": org_ref,
        }],
        metadata={"target": target, "tool": "business_logic_probe", "pattern_id": pattern_id},
    )
    ObservationStore(Path(memory_dir) / "object_model" / f"{target}.jsonl").record(obs)
    return obs


class ProbeRunner:
    def __init__(self, target: str, scope_checker: ScopeChecker, acting_session: AuthSession,
                 *, memory_dir: str, allow_mutate: bool, recon_rps: float = 2.0,
                 timeout: float = 15.0, max_requests: int = 50):
        self.target = target
        self.memory_dir = memory_dir
        req = requests.Session()
        req.headers.update(acting_session.headers_dict())
        limiter = RateLimiter(recon_rps=recon_rps, test_rps=recon_rps)
        guard = AutopilotGuard(safe_methods_only=not allow_mutate)
        self.fetcher = Fetcher(scope_checker, no_mutate=not allow_mutate, recon_rps=recon_rps,
                                timeout=timeout, max_requests=max_requests, guard=guard,
                                limiter=limiter, session=req)
        self.acting_session = acting_session

    def probe(self, pattern_id: str, method: str, url: str, org_ref: str, target_ref: str,
               data: str | None = None) -> dict:
        spec = PATTERN_SPECS[pattern_id]
        _validate_spec_matches_yaml(pattern_id, spec)
        if spec.action_is_mutating and method.upper() == "GET":
            raise ValueError(f"pattern {pattern_id!r} needs a mutating method (POST/PUT/PATCH/DELETE), got GET")
        if not spec.action_is_mutating and method.upper() != "GET":
            raise ValueError(f"pattern {pattern_id!r} is read-only (tenant_isolation) — method must be GET")

        method_u = method.upper()
        json_body = json.loads(data) if data else None
        result = self._send(method_u, url, json_body)

        actor_ref = entity_id("User", self.acting_session.session_id())
        org = entity_id("Organization", org_ref)
        obj_ref = (
            object_id("http-endpoint", url) if pattern_id == "tenant_isolation"
            else object_id(spec.object_type, target_ref)
        )

        metadata = {"target": self.target, "tool": "business_logic_probe", "pattern_id": pattern_id}
        if spec.action_context:
            metadata["context"] = spec.action_context
        if spec.governing_object_field == "metadata.organization_id":
            metadata["organization_id"] = org
        if spec.performed_by_field == "metadata.performed_by":
            metadata["performed_by"] = actor_ref

        # membership_granted's grammar: subject IS the org (HAS_MEMBER (org, HAS_MEMBER, user));
        # every other action_event here has subject_id = the acting user.
        subject_ref = org if spec.action_event == "membership_granted" else actor_ref

        obs = make_observation(
            subject_id=subject_ref, object_ref=obj_ref, event=spec.action_event,
            evidence=[{
                "type": "Observed-HTTP-Response",
                "detail": f"business_logic_probe.py {method_u} {url} -> {result['status']}",
                "artifact": url,
            }],
            outcome_status=result["status"],
            metadata=metadata,
        )
        store = ObservationStore(Path(self.memory_dir) / "object_model" / f"{self.target}.jsonl")
        store.record(obs)

        all_obs = store.all()
        candidates = detect_logic_pattern_violations(all_obs, target=self.target)
        new_candidates = [c for c in candidates if c["provenance"]["origin_lead_id"] == obs["id"]]
        for c in new_candidates:
            lead_board.add(self.target, spec_skill(pattern_id), url,
                            signal=f"business_logic_probe:{pattern_id}", priority="high")

        return {"status": result["status"], "body": result["body"], "observation": obs,
                "violations": new_candidates}

    def _send(self, method: str, url: str, json_body) -> dict:
        # Fetcher.request() doesn't take a body -- run its preflight/rate-limit/
        # guard checks (the exact same safety gates every other tool in this
        # codebase goes through), then send the real request ourselves so a
        # JSON body can be attached.
        host = self.fetcher.check(method, url)
        try:
            resp = self.fetcher.session.request(method, url, json=json_body, timeout=self.fetcher.timeout)
        except requests.RequestException as exc:
            self.fetcher.guard.record_failure(host)
            raise
        self.fetcher.guard.record_success(host)
        return {"status": resp.status_code, "body": resp.text[:2000]}


def spec_skill(pattern_id: str) -> str:
    # Mirrors rules/logic_patterns.yaml's own `skill` field per pattern —
    # kept here rather than re-parsed from the Candidate, since a match
    # writes the lead-board entry synchronously alongside the Observation.
    return {
        "invite_flow": "hunt-business-logic", "role_escalation": "hunt-auth-bypass",
        "ownership_transfer": "hunt-idor", "billing": "hunt-business-logic",
        "refund": "hunt-business-logic", "coupon": "hunt-business-logic",
        "tenant_isolation": "hunt-idor",
    }[pattern_id]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Mutation-gated producer for memory/object_model.py's business-logic "
                     "pattern detector (rules/logic_patterns.yaml)."
    )
    ap.add_argument("target")
    ap.add_argument("--pattern", required=True, choices=sorted(PATTERN_SPECS))
    ap.add_argument("--memory-dir", default="hunt-memory")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--establish", action="store_true",
                       help="Record that --holder-session-file genuinely holds this pattern's "
                            "required relationship (real out-of-band knowledge, not inferred)")
    mode.add_argument("--probe", action="store_true",
                       help="Fire the real test request as --acting-session-file and record the outcome")
    ap.add_argument("--org-ref", required=True, help="Caller-supplied org identifier (e.g. an org id/slug)")
    ap.add_argument("--object-ref", default=None, help="For --establish --pattern ownership_transfer only: what the holder owns")
    ap.add_argument("--holder-session-file", default=None, help="[--establish] the session that genuinely holds the relationship")
    ap.add_argument("--acting-session-file", default=None, help="[--probe] the session performing the test request")
    ap.add_argument("--target-ref", default=None, help="[--probe] caller-supplied id of the object being acted on")
    ap.add_argument("--method", default="GET")
    ap.add_argument("--url", default=None)
    ap.add_argument("--data", default=None, help="JSON request body for --probe")
    ap.add_argument("--domain", action="append", default=[])
    ap.add_argument("--exclude-domain", action="append", default=[])
    ap.add_argument("--recon-rps", type=float, default=2.0)
    ap.add_argument("--i-understand", action="store_true",
                     help="Actually record --establish, or actually fire the --probe request. "
                          "Without this flag, prints a dry-run summary and exits without any write/network call.")
    ap.add_argument("--allow-mutate", action="store_true",
                     help="[--probe] Required in addition to --i-understand for any non-GET method "
                          "(tools/browser_recon.py Fetcher's own mutation gate — this is a REAL "
                          "state-changing request against a live target, e.g. a real refund/invite/"
                          "transfer, not a read).")
    args = ap.parse_args(argv)

    try:
        spec = PATTERN_SPECS[args.pattern]
        _validate_spec_matches_yaml(args.pattern, spec)
    except (ValueError, LogicPatternLoadError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.establish:
        if not args.holder_session_file:
            print("ERROR: --establish requires --holder-session-file", file=sys.stderr)
            return 1
        holder = AuthSession.from_file(args.holder_session_file)
        if holder.is_empty():
            print("ERROR: --holder-session-file loaded no headers", file=sys.stderr)
            return 1
        if not args.i_understand:
            print(f"[DRY-RUN] Would assert {holder.describe()} holds {spec.establish_relationship} "
                  f"on org {args.org_ref!r} for target {args.target}.")
            print("Pass --i-understand to actually record this (only assert what you genuinely know).")
            return 0
        obs = establish(args.target, args.pattern, holder, args.org_ref, args.memory_dir, args.object_ref)
        print(f"[+] recorded {obs['event']} ({obs['relationship_type']}): {obs['subject_id']} -> {obs['object_id']}")
        return 0

    # --probe
    if not (args.acting_session_file and args.url and args.target_ref):
        print("ERROR: --probe requires --acting-session-file, --url, and --target-ref", file=sys.stderr)
        return 1
    acting = AuthSession.from_file(args.acting_session_file)
    if acting.is_empty():
        print("ERROR: --acting-session-file loaded no headers", file=sys.stderr)
        return 1
    if spec.action_is_mutating and args.method.upper() == "GET":
        print(f"ERROR: pattern {args.pattern!r} needs a mutating --method (POST/PUT/PATCH/DELETE)", file=sys.stderr)
        return 1

    if not args.i_understand:
        print(f"[DRY-RUN] Would send {args.method.upper()} {args.url} as {acting.describe()}"
              + (" -- THIS IS A REAL MUTATING REQUEST with real side effects on the live target"
                 if spec.action_is_mutating else "") + ".")
        print("Pass --i-understand (and --allow-mutate, for a mutating pattern) to actually fire it.")
        return 0
    if spec.action_is_mutating and not args.allow_mutate:
        print("ERROR: this pattern requires a mutating request — pass --allow-mutate as well as "
              "--i-understand (two independent, deliberate confirmations for real state change)", file=sys.stderr)
        return 1

    domains = args.domain or [args.target]
    checker = ScopeChecker(domains, args.exclude_domain)
    runner = ProbeRunner(args.target, checker, acting, memory_dir=args.memory_dir,
                          allow_mutate=args.allow_mutate)
    try:
        result = runner.probe(args.pattern, args.method, args.url, args.org_ref, args.target_ref, args.data)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"Response: HTTP {result['status']}")
    if result["violations"]:
        print(f"\n{'='*60}")
        print(f"  [BUSINESS-LOGIC VIOLATION] {args.pattern}")
        for c in result["violations"]:
            print(f"  {c['rationale']}")
        print(f"  Still a CANDIDATE, not proof — validation_plan describes how to confirm it.")
        print(f"{'='*60}")
    else:
        print("No violation detected (either the request was rejected, or the acting session "
              "does hold the required relationship, or no --establish precondition is on record yet).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
