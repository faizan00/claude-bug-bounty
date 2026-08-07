"""
Canonical Candidate schema — Phase 6 (Logic-Bug Agent), Part 0.

{
  "id": "cand-<hex>",
  "source": "...",
  "type": "...",
  "evidence": [{"type": "<Evidence Typing vocabulary>", "detail": "...", "artifact": "..."}],
  "rationale": "...",
  "validation_plan": {"steps": [...], "expected": "...", "stop_condition": "..."},
  "provenance": {"origin_lead_id": "...", "origin_source": "..."},
  "state": "new|validated|rejected|...",
  "metadata": {},
}

Two directions, both pure/read-only — neither mutates its input, neither
computes a priority or score (that stays tools/director.py's and memory/
vuln_intelligence.py's job, unchanged):

  lead_to_candidate_view(lead)         existing lead-board-shaped dict
                                        (tools/director.py's
                                        browser_intel_leads() / attack_graph
                                        top_paths() / *_leads() tool
                                        adapters, or a raw lead_board.py
                                        ledger entry) -> Candidate VIEW.
                                        Retrofit only — tools/director.py's
                                        build_plan()/_score_lead() keep
                                        scoring the ORIGINAL lead dicts,
                                        completely untouched by this.

  candidate_to_lead_view(candidate,    a NATIVELY-Candidate-shaped source
                          skill,       (memory/object_model.py, and future
                          priority)    Phase 6 callers) -> lead-board-shaped
                                       dict, so it can enter
                                       tools/director.py's existing
                                       all_leads/_score_lead() pipeline
                                       exactly the way every other source
                                       already does (see
                                       tools/director.py's
                                       object_model_leads() adapter). This
                                       function does not choose skill/
                                       priority itself — mirrors
                                       tools/director.py's existing
                                       category->(skill, priority) routing
                                       tables (_SECRET_FINDING_ROUTE,
                                       _GRAPHQL_AUDIT_SIGNALS): the CALLER
                                       decides the tier from the
                                       candidate's `type`, exactly like
                                       every other adapter already does.
                                       Candidate producers (object_model.py)
                                       never see or choose a priority tier.

EVIDENCE TYPING vocabulary (PERMANENT RULE 3, this repo's existing
convention — see tools/secrets_scanner.py's module docstring, the first
place it was actually enumerated): Observed-Runtime, Observed-HTTP-
Response, Browser-Artifact, Static-JS, Fingerprint, Historical-Memory,
Human-Input, Validation-Confirmed. Centralized here as EVIDENCE_TYPES so
this is the one place a new Candidate is checked against it
(validate_candidate() raises on an evidence entry with a type outside this
set) — existing modules that already hardcode their own subset of these
exact strings (tools/secrets_scanner.py's EVIDENCE_TYPE_STATIC_JS etc.)
are NOT changed to import from here; this is additive centralization for
NEW Phase 6 code, not a retrofit of Phase 5 modules that already work.
"""

from __future__ import annotations

import secrets

EVIDENCE_TYPES: frozenset[str] = frozenset({
    "Observed-Runtime",
    "Observed-HTTP-Response",
    "Browser-Artifact",
    "Static-JS",
    "Fingerprint",
    "Historical-Memory",
    "Human-Input",
    "Validation-Confirmed",
})

CANDIDATE_STATES: frozenset[str] = frozenset({"new", "validated", "rejected"})


def new_candidate_id() -> str:
    return "cand-" + secrets.token_hex(4)


def make_candidate(
    source: str,
    type_: str,
    evidence: list[dict],
    rationale: str,
    validation_plan: dict | None = None,
    provenance: dict | None = None,
    state: str = "new",
    metadata: dict | None = None,
) -> dict:
    """Build one Candidate. Raises ValueError if any evidence entry's `type`
    is outside EVIDENCE_TYPES — the one hard guarantee this schema enforces
    at construction time (mirrors memory/attack_graph.py's Node/Edge
    __post_init__ validating node/edge type against NODE_TYPES/EDGE_TYPES).
    Does not validate `state` against CANDIDATE_STATES — callers
    (validation/Phase 7 self-critique) are expected to move a Candidate
    through states this module has no opinion on beyond the schema's
    literal "new|validated|rejected|..." (the "..." is deliberate — this
    schema does not close off future states)."""
    for entry in evidence:
        et = entry.get("type")
        if et not in EVIDENCE_TYPES:
            raise ValueError(
                f"evidence entry has type {et!r}, not in EVIDENCE_TYPES vocabulary: {sorted(EVIDENCE_TYPES)}"
            )
    return {
        "id": new_candidate_id(),
        "source": source,
        "type": type_,
        "evidence": list(evidence),
        "rationale": rationale,
        "validation_plan": validation_plan or {"steps": [], "expected": "", "stop_condition": ""},
        "provenance": provenance or {"origin_lead_id": None, "origin_source": source},
        "state": state,
        "metadata": dict(metadata or {}),
    }


# ─── Retrofit: existing lead dict -> Candidate VIEW (read-only) ────────────

# Best-effort provenance label per lead-board `source` value, for leads that
# predate Phase 6 and were never built with evidence typing in mind. Chosen
# from what each source genuinely IS (see call sites in tools/director.py /
# tools/lead_board.py / memory/attack_graph.py), not fabricated to look more
# precise than it is — e.g. "chain"/"hypothesis" leads are lead_board.py
# correlating already-ingested, already-persisted ledger entries, which is
# exactly what Historical-Memory means elsewhere in this repo; a live
# scanner hit (takeover/cloud/graphql tool output) is a real HTTP/DNS round
# trip, so Observed-HTTP-Response.
_LEAD_SOURCE_EVIDENCE_TYPE: dict[str, str] = {
    "browser-intel": "Browser-Artifact",
    "attack-graph": "Historical-Memory",
    "chain": "Historical-Memory",
    "hypothesis": "Historical-Memory",
    "takeover-scan": "Observed-HTTP-Response",
    "cloud-recon": "Observed-HTTP-Response",
    "graphql-audit": "Observed-HTTP-Response",
    "manual": "Human-Input",
}
# secret_scan_leads() already tags its own evidence_type inline in `why`
# (f"{category} finding ({method}, evidence_type={evidence_type})") — read
# that back rather than re-guessing; Static-JS is the fallback only if the
# tag is somehow missing.
_SECRET_SCAN_DEFAULT_EVIDENCE_TYPE = "Static-JS"

# Any lead_board-ingested `source` this table doesn't recognize (the raw
# recon-observation routing sources: "url", "nuclei", "graphql", ...) is
# read from the persisted ledger (memory/leads/<target>.jsonl) the same way
# "chain"/"hypothesis" are — Historical-Memory, not a fabricated more-
# specific label.
_DEFAULT_RETROFIT_EVIDENCE_TYPE = "Historical-Memory"


def _evidence_type_for_lead(lead: dict) -> str:
    source = lead.get("source", "")
    if source == "secret-scan":
        why = lead.get("why", "") or ""
        for token in why.split():
            if token.startswith("evidence_type="):
                candidate_type = token[len("evidence_type="):].rstrip(")")
                if candidate_type in EVIDENCE_TYPES:
                    return candidate_type
        return _SECRET_SCAN_DEFAULT_EVIDENCE_TYPE
    return _LEAD_SOURCE_EVIDENCE_TYPE.get(source, _DEFAULT_RETROFIT_EVIDENCE_TYPE)


def lead_to_candidate_view(lead: dict) -> dict:
    """Pure, read-only: an existing lead-board-shaped dict -> a Candidate
    VIEW. Never mutates `lead`, never touches tools/director.py's scoring
    (that reads the original lead dicts directly, unaware this view
    exists). Safe to call on ANY dict already carrying id/skill/priority/
    signal/why/evidence/source — the exact shape every *_leads() function
    in tools/director.py, memory/attack_graph.py's top_paths(), and
    tools/lead_board.py's ledger entries already produce."""
    evidence_type = _evidence_type_for_lead(lead)
    return {
        "id": "cand-" + lead.get("id", new_candidate_id()),
        "source": lead.get("source", "unknown"),
        "type": lead.get("skill", lead.get("signal", "unknown")),
        "evidence": [{
            "type": evidence_type,
            "detail": lead.get("why", ""),
            "artifact": lead.get("evidence", ""),
        }],
        "rationale": lead.get("why", ""),
        "validation_plan": {"steps": [], "expected": "", "stop_condition": ""},
        "provenance": {"origin_lead_id": lead.get("id"), "origin_source": lead.get("source", "unknown")},
        "state": "validated" if lead.get("status") in ("investigating", "reported") else (
            "rejected" if lead.get("status") == "killed" else "new"
        ),
        "metadata": {"priority": lead.get("priority"), "target": lead.get("target")},
    }


def leads_to_candidates(leads: list[dict]) -> list[dict]:
    """Batch form of lead_to_candidate_view() — the whole point of this
    function existing is that it changes NOTHING about how `leads` itself
    gets scored; it is a parallel, additive read path."""
    return [lead_to_candidate_view(lead) for lead in leads]


# ─── Native direction: Candidate -> lead-board-shaped dict ─────────────────

def candidate_to_lead_view(candidate: dict, skill: str, priority: str, id_prefix: str = "cand") -> dict:
    """A NATIVELY-Candidate-shaped source (memory/object_model.py) ->
    lead-board-shaped dict, so it can be concatenated into
    tools/director.py's `all_leads` and scored by the existing
    `_score_lead()` completely unmodified — the SAME wrapper pattern
    browser_intel_leads()/attack_graph_leads()/secret_scan_leads() already
    use, just entering from a Candidate instead of a tool's native output.

    `skill`/`priority` are supplied by the CALLER (tools/director.py's
    adapter, via its own type->(skill, priority) routing table) — this
    function does not choose them, so memory/object_model.py never touches
    priority at all, directly or indirectly.
    """
    import tools.lead_board as lead_board  # local import: memory/ -> tools/ only inside this function,
    # matching memory/attack_graph.py's existing precedent of memory/ importing tools/lead_board module-level;
    # kept function-local here since most callers of candidate_to_lead_view() (tests) don't need lead_board's
    # own dependencies loaded just to build a dict.

    now = lead_board.now_iso()
    detail = "; ".join(e.get("detail", "") for e in candidate.get("evidence", []) if e.get("detail"))
    artifact = "; ".join(e.get("artifact", "") for e in candidate.get("evidence", []) if e.get("artifact"))
    return {
        "id": f"{id_prefix}-{candidate['id']}",
        "target": candidate.get("metadata", {}).get("target", ""),
        "skill": skill,
        "priority": priority,
        "signal": candidate.get("type", ""),
        "why": candidate.get("rationale", ""),
        "evidence": lead_board.norm_evidence(artifact or detail),
        "source": candidate.get("source", "object-model"),
        "candidate_id": candidate["id"],
        "status": "new",
        "note": "",
        "created": now,
        "last_seen": now,
        "seen_count": 1,
    }
