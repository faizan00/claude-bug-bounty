"""Phase 7, Part B — the Self-Critique Gate.

Takes a memory/candidate.py-shaped Candidate and runs four machine-
evaluable checks, all reusing existing infrastructure (PERMANENT RULE 1:
this module computes no priority/score of its own — memory/vuln_intelligence.py
stays the one formula):

  1. REPRODUCIBILITY   — re-runs validation_plan.steps TWICE through a real
                          tools/browser_recon.py Fetcher (already scope/
                          rate-limit gated). Flaky or non-matching -> BLOCK.
  2. DUPLICATE PROBABILITY — calls memory/vuln_intelligence.py's
                          dedup_probability() unmodified. WARN when sample-
                          backed and elevated; BLOCK the same case if the
                          Candidate's metadata.novel_impact_argument is
                          absent/empty (a structured field, not prose
                          parsed out of rationale).
  3. EVIDENCE COMPLETENESS — a pure structural check against the Candidate
                          schema itself (memory/candidate.py).
  4. BUSINESS-IMPACT CROSS-CHECK — cross-references memory/object_model.py's
                          relationship-violation detectors. WARN only, never
                          BLOCK, and never touches priority_score() (verified
                          by tests/test_self_critique.py's regression test).

Pure library (evaluate_candidate() takes plain data — a Candidate dict, a
Fetcher, report_outcomes/observations lists already loaded by the caller)
+ thin CLI at the bottom, per PERMANENT RULE 5.
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

from memory.candidate import EVIDENCE_TYPES, lead_to_candidate_view  # noqa: E402
from memory.object_model import (  # noqa: E402
    detect_logic_pattern_violations,
    detect_relationship_violations,
)
from memory.vuln_intelligence import (  # noqa: E402
    DEFAULT_DEDUP_PROBABILITY,
    MIN_SAMPLES_FOR_DEDUP_PROBABILITY,
    dedup_probability,
    normalize_endpoint,
)

CHECK_STATUSES = frozenset({"pass", "warn", "block"})

# validation_plan.expected is free-text (e.g. "403 / 401"); this extracts
# any 3-digit HTTP status codes it names. Not a heuristic constant -- a
# fixed, cited protocol fact (HTTP status codes are always 3 digits,
# RFC 9110 section 15).
_STATUS_CODE_RE = re.compile(r"\b([1-5]\d{2})\b")


def _result(name: str, status: str, reason: str, details: dict | None = None) -> dict:
    assert status in CHECK_STATUSES
    return {"name": name, "status": status, "reason": reason, "details": details or {}}


# ─── 1. Reproducibility ──────────────────────────────────────────────────

def _executable_steps(validation_plan: dict) -> list[dict]:
    steps = validation_plan.get("steps") or []
    return [s for s in steps if isinstance(s, dict) and s.get("method") and s.get("url")]


def _expected_statuses(validation_plan: dict) -> set[int]:
    expected = validation_plan.get("expected") or ""
    return {int(m) for m in _STATUS_CODE_RE.findall(expected)}


def check_reproducibility(candidate: dict, fetcher) -> dict:
    """Re-runs the Candidate's validation_plan.steps TWICE via `fetcher`
    (tools/browser_recon.py's Fetcher — scope/cap/circuit-breaker/rate-limit
    already enforced there, not reimplemented here). Both runs must produce
    the same per-step HTTP status, and every observed status must be one
    validation_plan.expected actually names, or this BLOCKS.

    Conservative by construction: a Candidate whose validation_plan carries
    no machine-executable {method,url} step, or whose `expected` names no
    parseable status code, cannot be verified here at all -- that BLOCKS
    too (an unverifiable claim is not evidence of reproducibility, so it
    must not silently pass)."""
    validation_plan = candidate.get("validation_plan") or {}
    steps = _executable_steps(validation_plan)
    if not steps:
        return _result(
            "reproducibility", "block",
            "validation_plan.steps has no machine-executable {method,url} step -- cannot verify reproducibility",
        )

    expected_statuses = _expected_statuses(validation_plan)
    if not expected_statuses:
        return _result(
            "reproducibility", "block",
            "validation_plan.expected has no parseable HTTP status code to verify against",
        )

    runs: list[tuple[int, ...]] = []
    for _ in range(2):
        run_statuses = []
        for step in steps:
            try:
                resp = fetcher.request(step["method"], step["url"])
            except Exception as exc:  # noqa: BLE001 - any fetch failure blocks, never crashes the gate
                return _result("reproducibility", "block", f"request failed while reproducing: {exc}")
            run_statuses.append(resp.status_code)
        runs.append(tuple(run_statuses))

    if runs[0] != runs[1]:
        return _result(
            "reproducibility", "block",
            f"non-reproducible: run 1 = {runs[0]}, run 2 = {runs[1]}",
            details={"runs": runs},
        )

    if not all(status in expected_statuses for status in runs[0]):
        return _result(
            "reproducibility", "block",
            f"observed status {runs[0]} does not match validation_plan.expected ({sorted(expected_statuses)})",
            details={"runs": runs},
        )

    return _result(
        "reproducibility", "pass",
        "reproduced twice, both runs match validation_plan.expected",
        details={"runs": runs},
    )


# ─── 2. Duplicate probability ────────────────────────────────────────────

# Reused, not invented: the same "long enough to carry real signal, not a
# placeholder" length bar tools/secrets_scanner.py's ENTROPY_MIN_LENGTH
# already established for this codebase (itself cited from
# secrets_hunter.sh's existing regex-fallback length bar). Per Rule 4
# ("no heuristic numeric constants unless... existing config... or
# explicitly justified"), reusing this repo's one existing "not just a
# placeholder string" bar is the least-arbitrary choice available, rather
# than inventing a second number that means the same thing.
MIN_NOVEL_IMPACT_ARGUMENT_LENGTH = 20


def _novel_impact_argument_reused_verbatim(
    candidate: dict, novel_impact_argument: str, prior_candidates: list[dict] | None,
) -> bool:
    """True if `novel_impact_argument` (already stripped) is the EXACT same
    text as another Candidate's novel_impact_argument on the SAME target.
    `prior_candidates` is caller-supplied (no candidate persistence exists
    in this repo to read from directly -- see FIX #4 note in self_critique()
    below); a copy-pasted justification reused verbatim across findings is
    a strong signal it was never genuinely novel each time, worth flagging
    even though it never blocks on its own."""
    if not novel_impact_argument or not prior_candidates:
        return False
    target = (candidate.get("metadata") or {}).get("target")
    this_id = candidate.get("id")
    for prior in prior_candidates:
        if prior.get("id") == this_id:
            continue
        prior_metadata = prior.get("metadata") or {}
        if prior_metadata.get("target") != target:
            continue
        if (prior_metadata.get("novel_impact_argument") or "").strip() == novel_impact_argument:
            return True
    return False


def check_duplicate_probability(
    candidate: dict,
    report_outcomes: list[dict] | None = None,
    prior_candidates: list[dict] | None = None,
) -> dict:
    """Calls vuln_intelligence.dedup_probability() with the Candidate's
    type/target/program/tech_stack -- no new formula, same function
    priority_score() itself consumes. WARN when the sample-backed
    probability is elevated (above DEFAULT_DEDUP_PROBABILITY, the same 0.5
    cold-start baseline dedup_probability() already treats as neutral) and
    candidate.metadata["novel_impact_argument"] is a real, non-placeholder
    string (at least MIN_NOVEL_IMPACT_ARGUMENT_LENGTH characters); BLOCK the
    identical case when it's absent/empty/too short to carry real signal.

    A structured metadata field, not a marker phrase parsed out of
    `rationale` -- PERMANENT RULE 4 only requires this be a structural
    presence check, not a heuristic score, and a required field a caller
    either did or didn't set is less error-prone than a hunter having to
    remember an exact magic phrase in free text.

    `prior_candidates` (optional, caller-supplied -- e.g. every Candidate
    already evaluated this session/target): when the SAME novel_impact_argument
    text is reused verbatim across Candidates for the same target, that's
    surfaced in `details["novel_impact_argument_reused_verbatim"]` and noted
    in the reason -- flagged, never blocked, since a legitimately reused
    short justification ("same auth-bypass root cause, different endpoint")
    can be genuine; only a HUMAN or a stricter downstream policy should
    decide that's disqualifying, this check only ever surfaces the signal."""
    metadata = candidate.get("metadata") or {}
    vuln_class = candidate.get("type", "")
    endpoint = metadata.get("endpoint")
    result = dedup_probability(
        vuln_class=vuln_class,
        endpoint_shape=normalize_endpoint(endpoint) if endpoint else None,
        program=metadata.get("program"),
        tech_stack=metadata.get("tech_stack"),
        report_outcomes=report_outcomes,
    )

    sample_backed = result["sample_size"] >= MIN_SAMPLES_FOR_DEDUP_PROBABILITY
    elevated = sample_backed and result["probability"] > DEFAULT_DEDUP_PROBABILITY
    novel_impact_argument = (metadata.get("novel_impact_argument") or "").strip()
    has_novel_impact_argument = len(novel_impact_argument) >= MIN_NOVEL_IMPACT_ARGUMENT_LENGTH
    reused_verbatim = _novel_impact_argument_reused_verbatim(candidate, novel_impact_argument, prior_candidates)
    reuse_note = (
        " -- NOTE: this exact novel_impact_argument text was already used for another "
        "Candidate on this target; a copy-pasted justification is a strong signal it is "
        "not genuinely novel each time"
        if reused_verbatim else ""
    )
    details = {"dedup_probability": result, "novel_impact_argument_reused_verbatim": reused_verbatim}

    if elevated and not has_novel_impact_argument:
        return _result(
            "duplicate_probability", "block",
            f"sample-backed duplicate probability {result['probability']} ({result['basis']}) "
            f"with no metadata.novel_impact_argument (must be a real justification, "
            f"at least {MIN_NOVEL_IMPACT_ARGUMENT_LENGTH} characters, not a placeholder)",
            details=details,
        )
    if elevated:
        return _result(
            "duplicate_probability", "warn",
            f"sample-backed duplicate probability {result['probability']} ({result['basis']}) "
            f"-- allowed through on metadata.novel_impact_argument{reuse_note}",
            details=details,
        )
    if reused_verbatim:
        return _result(
            "duplicate_probability", "warn",
            f"duplicate probability {result['probability']} not sample-backed elevated ({result['basis']})"
            f"{reuse_note}",
            details=details,
        )
    return _result(
        "duplicate_probability", "pass",
        f"duplicate probability {result['probability']} not sample-backed elevated ({result['basis']})",
        details=details,
    )


# ─── 3. Evidence completeness ────────────────────────────────────────────

def check_evidence_completeness(candidate: dict) -> dict:
    """Pure structural check against memory/candidate.py's schema: evidence[]
    non-empty with real Evidence Typing labels, validation_plan carrying all
    three fields, rationale non-empty. BLOCKS on any missing/empty field."""
    missing: list[str] = []

    evidence = candidate.get("evidence")
    if not evidence:
        missing.append("evidence")
    else:
        for i, entry in enumerate(evidence):
            if entry.get("type") not in EVIDENCE_TYPES:
                missing.append(f"evidence[{i}].type")

    validation_plan = candidate.get("validation_plan") or {}
    for field in ("steps", "expected", "stop_condition"):
        if not validation_plan.get(field):
            missing.append(f"validation_plan.{field}")

    if not candidate.get("rationale"):
        missing.append("rationale")

    if missing:
        return _result(
            "evidence_completeness", "block",
            f"missing/empty required field(s): {', '.join(missing)}",
            details={"missing": missing},
        )
    return _result("evidence_completeness", "pass", "all required Candidate fields present")


# ─── 4. Business-impact cross-check ──────────────────────────────────────

def _violation_refs(violation: dict) -> tuple:
    """Relationship-violation Candidates carry the (subject, object) pair
    under different metadata keys depending on which object_model.py
    detector produced them (detect_relationship_violations() uses
    subject_id/object_id; detect_logic_pattern_violations() uses
    performed_by/governing_object) -- read either, never guess a third."""
    md = violation.get("metadata") or {}
    subject = md.get("subject_id") or md.get("performed_by")
    obj = md.get("object_id") or md.get("governing_object")
    return (subject, obj)


def check_business_impact(candidate: dict, observations: list[dict] | None = None) -> dict:
    """WARN-only, never BLOCK, never imports/calls priority_score() (see
    tests/test_self_critique.py's regression test). If the Candidate
    already originates from object_model.py's own violation detectors,
    it IS a confirmed relationship violation by construction. Otherwise,
    cross-reference the Candidate's own subject_id/object_id (if its
    metadata carries them) against what those same detectors currently
    find in `observations` -- an empty/cold-start Object Model just means
    nothing to cross-reference, never a crash."""
    if candidate.get("source") == "object-model":
        return _result(
            "business_impact", "warn",
            "Candidate originates from object-model relationship-violation detection -- "
            "business-impact confirmed, upgrade report language accordingly",
            details={"upgraded_impact": True},
        )

    observations = observations or []
    metadata = candidate.get("metadata") or {}
    subject_id = metadata.get("subject_id")
    object_ref = metadata.get("object_id")
    if not subject_id or not object_ref or not observations:
        return _result(
            "business_impact", "pass",
            "no object-model relationship data to cross-reference",
            details={"upgraded_impact": False},
        )

    target = metadata.get("target")
    violations = (
        detect_relationship_violations(observations, target=target)
        + detect_logic_pattern_violations(observations, target=target)
    )
    matched = any(_violation_refs(v) == (subject_id, object_ref) for v in violations)

    if matched:
        return _result(
            "business_impact", "warn",
            "confirming this Candidate corresponds to an observed relationship-graph violation -- "
            "upgrade report language accordingly",
            details={"upgraded_impact": True},
        )
    return _result(
        "business_impact", "pass",
        "no matching relationship violation found in the current object model",
        details={"upgraded_impact": False},
    )


# ─── Combined gate ────────────────────────────────────────────────────────

def self_critique(
    candidate: dict,
    fetcher=None,
    report_outcomes: list[dict] | None = None,
    observations: list[dict] | None = None,
    prior_candidates: list[dict] | None = None,
) -> dict:
    """Run all four checks. `fetcher` is optional at the API level so
    non-HTTP-reproducible checks (2-4) can still run standalone in tests --
    omitting it makes the reproducibility check BLOCK (no fetcher means no
    verification), never silently skips it.

    `prior_candidates` (optional): other Candidates already evaluated for
    this target, passed straight through to check_duplicate_probability()'s
    verbatim-reuse flag (see its docstring) -- this module still has no
    candidate-persistence store of its own, and doesn't need one to surface
    the signal when a caller already has the list."""
    if fetcher is not None:
        checks = [check_reproducibility(candidate, fetcher)]
    else:
        checks = [_result("reproducibility", "block", "no fetcher supplied -- cannot verify reproducibility")]

    checks.append(check_duplicate_probability(candidate, report_outcomes, prior_candidates))
    checks.append(check_evidence_completeness(candidate))
    checks.append(check_business_impact(candidate, observations))

    if any(c["status"] == "block" for c in checks):
        overall = "block"
    elif any(c["status"] == "warn" for c in checks):
        overall = "warn"
    else:
        overall = "pass"

    return {
        "candidate_id": candidate.get("id"),
        "checks": checks,
        "overall": overall,
        "details": {c["name"]: c for c in checks},
    }


# ─── CLI ──────────────────────────────────────────────────────────────────

def _load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _load_jsonl(path: str | None) -> list[dict]:
    if not path or not os.path.exists(path):
        return []
    entries = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def main() -> int:
    ap = argparse.ArgumentParser(description="Phase 7 Self-Critique Gate for a memory/candidate.py Candidate")
    ap.add_argument("--candidate", default=None, help="Path to a Candidate JSON file")
    ap.add_argument(
        "--from-lead-board", nargs=2, metavar=("TARGET", "LEAD_ID"), default=None,
        help="Alternative to --candidate: load an existing lead_board.py ledger entry "
             "(memory/leads/<TARGET>.jsonl, matched by LEAD_ID) and convert it via "
             "memory.candidate.lead_to_candidate_view() instead of hand-transcribing a "
             "Candidate JSON file. Closes the gap where a confirmed finding whose evidence "
             "originated as a plain lead-board lead (not memory/object_model.py, which "
             "already produces native Candidates) had no path into this gate short of "
             "manually authoring one.",
    )
    ap.add_argument("--report-outcomes", default=None, help="Path to hunt-memory/report_outcomes.jsonl")
    ap.add_argument("--observations", default=None, help="Path to memory/object_model.py's observations.jsonl")
    ap.add_argument(
        "--prior-candidates", default=None,
        help="Path to a JSONL file of prior Candidates already evaluated this session/target "
             "(one Candidate JSON object per line) -- enables the verbatim novel_impact_argument "
             "reuse flag in the duplicate_probability check. Optional; omitting it just means "
             "reuse-across-Candidates can't be checked yet, same cold-start convention as "
             "--report-outcomes/--observations.",
    )
    ap.add_argument("--allowed-domain", action="append", default=[], help="Scope allowlist for the reproducibility Fetcher (repeatable)")
    ap.add_argument("--no-fetch", action="store_true", help="Skip live reproduction — reproducibility check BLOCKs (no fetcher)")
    ap.add_argument("--recon-rps", type=float, default=None)
    ap.add_argument("--max-requests", type=int, default=None)
    ap.add_argument(
        "--output", default=None,
        help="Persist the report as canonical JSON at this path and print its sha256 hex "
             "digest on the last stdout line -- the (path, hash) pair "
             "memory/finding_state.py's REPORT_READY transition requires as evidence "
             "(self_critique_report_path / self_critique_report_hash). Uses the same "
             "memory.finding_state.write_report_artifact() the transition check verifies "
             "against, so there is exactly one place that decides what 'the same bytes' means.",
    )
    args = ap.parse_args()

    if bool(args.candidate) == bool(args.from_lead_board):
        ap.error("exactly one of --candidate or --from-lead-board is required")

    if args.candidate:
        candidate = _load_json(args.candidate)
    else:
        import tools.lead_board as lead_board

        target, lead_id = args.from_lead_board
        lead = next((ld for ld in lead_board.load_ledger(target) if ld.get("id") == lead_id), None)
        if lead is None:
            print(f"ERROR: no lead {lead_id!r} in memory/leads/{target}.jsonl", file=sys.stderr)
            return 1
        candidate = lead_to_candidate_view(lead)

    report_outcomes = _load_jsonl(args.report_outcomes)
    observations = _load_jsonl(args.observations)
    prior_candidates = _load_jsonl(args.prior_candidates)

    fetcher = None
    if not args.no_fetch and args.allowed_domain:
        from tools.browser_recon import Fetcher
        from tools.scope_checker import ScopeChecker

        checker = ScopeChecker(args.allowed_domain, [])
        kwargs = {}
        if args.recon_rps is not None:
            kwargs["recon_rps"] = args.recon_rps
        if args.max_requests is not None:
            kwargs["max_requests"] = args.max_requests
        fetcher = Fetcher(checker, **kwargs)

    report = self_critique(
        candidate, fetcher=fetcher, report_outcomes=report_outcomes,
        observations=observations, prior_candidates=prior_candidates,
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.output:
        from memory.finding_state import write_report_artifact

        report_hash = write_report_artifact(report, args.output)
        print(f"self_critique_report_path={args.output}")
        print(f"self_critique_report_hash={report_hash}")
    return 0 if report["overall"] != "block" else 1


if __name__ == "__main__":
    raise SystemExit(main())
