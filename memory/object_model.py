"""
Application Object Model — Phase 6 (Logic-Bug Agent), Part 1.

Problem this solves: memory/attack_graph.py (Phase 4) answers "how can I
attack?" — it chains TECHNICAL signals (leads, endpoints, capabilities)
into a path. This module answers a different question: "what
relationships should exist between actors and objects, and is observed
behavior consistent with them?" Most serious IDOR / privilege-escalation /
multi-tenant bugs are relationship bugs (actor A did something only
actor B's relationship to an object should permit), not endpoint bugs —
nothing else in this repo models that.

ARCHITECTURAL PRINCIPLE (non-negotiable, do not merge these):
  - This module is SEPARATE from memory/attack_graph.py.
  - This module produces Candidate objects (memory/candidate.py's schema).
  - tools/director.py's object_model_leads() adapter consumes those
    Candidates EXACTLY the way it consumes every other lead source
    (browser_intel_leads/attack_graph_leads/secret_scan_leads/...) — via a
    routing table it owns (type -> skill/priority), concatenated into
    all_leads, scored by the existing, unmodified _score_lead(). Director
    never reaches into this module's Entity/Relationship/Observation
    internals, and this module never imports priority_score()/
    expected_value_per_hour() or any P_HIGH/P_MED/P_LOW constant — it has
    no notion of priority at all.
  - This module never computes relationships from anything director.py
    (or attack_graph.py) already knows how to compute — chains, paths,
    tech-fingerprint weights stay exactly where they are.

OBJECT MODEL DISCIPLINE (non-negotiable): this is an OBSERVATIONAL model,
not a semantic one. It records only relationships supported by real
evidence, and relationship lifecycle inferred from observed EVENTS —
never from endpoint names, URL paths, parameter names, naming conventions,
or assumptions. A field literally named `owner_id` in a response body is
NOT evidence of an OWNS relationship here — that would be exactly the
naming-based inference this discipline forbids. The only thing that
establishes a relationship is an explicitly-typed Observation event
(`created`, `ownership_transferred`, `membership_granted`, ...) carrying
at least one Evidence Typing entry, recorded by a caller who has genuine
out-of-band knowledge of what the request meant (a human, an agent, or a
Part 3 stateful-session workflow driver stepping through a real business
flow) — never auto-parsed from recon/<target>/browser/api-calls.json's
request_body_shape/response_shape (checked before writing this: those
fields carry only field NAMES + type labels, e.g. {"owner_id": "number"},
by tools/browser_recon.py's shape_of() design — treating a shape's key
name as a relationship claim would be the textbook naming-convention
inference this discipline exists to prevent). No automatic recon-artifact
adapter is built in this phase for exactly that reason — see the Phase 6
report's OUT OF SCOPE section.

A relationship-violation Candidate means:
    "Observed behavior appears inconsistent with the currently observed
    relationship graph."
It does NOT mean:
    "This is a vulnerability." Determining that is validation's job
    (Phase 6 validation plan) and Phase 7 Self-Critique — never this
    module's.

RELATIONSHIP GRAMMAR (subject, TYPE, object) reads as "subject TYPE
object" — the convention every event below follows:
    OWNS         (user,  OWNS,        object)   "user owns object"
    BELONGS_TO   (object, BELONGS_TO, org)       "object belongs to org"
    CONTAINS     (org,   CONTAINS,    object)    "org contains object"
    HAS_MEMBER   (org,   HAS_MEMBER,  user)      "org has member user"
    CAN_INVITE   (user,  CAN_INVITE,  org)       "user can invite into org"

RELATIONSHIP TIMELINE: relationships are not immutable. compute_relationships()
recomputes CURRENT state from the full append-only observation history on
every call — nothing is mutated in place, nothing is ever deleted. A
`created` observation's OWNS edge is superseded (not overwritten) by a
later `ownership_transferred` naming the same object; superseded/revoked/
archived/deleted edges stay in `history` for audit. detect_relationship_
violations() only ever looks at the CURRENT (status="active") edge for a
given (subject, type, object) — so historical ownership can never trigger
a false positive, and a legitimate transfer is exactly the observation
that stops the old edge from being active.

APPEND-ONLY OBSERVATION STORE: ObservationStore.record() only ever
appends (same fcntl-locked-append + size-based rotation convention as
memory/vuln_intelligence.py's _JsonlDB) — no update, no delete, no dedup
(the same actor legitimately accessing the same object twice is two real
observations, not a duplicate to collapse).
"""

from __future__ import annotations

import fcntl
import json
import os
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

from memory.candidate import EVIDENCE_TYPES, make_candidate
from memory.rotation import DEFAULT_KEEP, DEFAULT_MAX_BYTES, rotate_if_needed

# ─── Vocabulary ─────────────────────────────────────────────────────────────

# Actor-shaped entities (memory.identity.entity_id(type, ref)). "Object-type"
# (Part 1's fourth entity) is deliberately NOT a closed enum here — real
# applications have arbitrary resource types (documents, orders, projects,
# ...) and memory.identity.object_id(object_type, ref) already accepts any
# caller-supplied type label; closing it to a fixed list would be exactly
# the kind of unrequested, over-specific enum PERMANENT RULE 4 warns against.
ENTITY_TYPES = frozenset({"User", "Role", "Organization"})

RELATIONSHIP_TYPES = frozenset({"OWNS", "BELONGS_TO", "CONTAINS", "HAS_MEMBER", "CAN_INVITE"})
RELATIONSHIP_STATUSES = frozenset({"active", "superseded", "revoked", "archived", "deleted"})

# Observation event vocabulary. An event either ESTABLISHES/ENDS a specific
# relationship_type (see _ESTABLISHING_EVENTS/_ENDING_EVENTS) or is a pure
# behavioral fact (accessed/modified) that detect_relationship_violations()
# checks against the CURRENT relationship graph — it never itself asserts
# a relationship.
OBSERVATION_EVENTS = frozenset({
    "created", "accessed", "modified", "ownership_transferred",
    "membership_granted", "membership_revoked",
    "invite_capability_granted", "invite_capability_revoked",
    "archived", "deleted",
})

_ESTABLISHING_EVENTS: dict[str, str] = {
    "created": "OWNS",
    "ownership_transferred": "OWNS",
    "membership_granted": "HAS_MEMBER",
    "invite_capability_granted": "CAN_INVITE",
}
_ENDING_EVENTS: dict[str, str] = {
    "membership_revoked": "HAS_MEMBER",
    "invite_capability_revoked": "CAN_INVITE",
}
# archived/deleted end EVERY relationship edge touching the object (either
# side), not one relationship_type — handled separately in
# compute_relationships(), not via _ESTABLISHING_EVENTS/_ENDING_EVENTS.
_OBJECT_LIFECYCLE_EVENTS = frozenset({"archived", "deleted"})

# A successful (2xx) access/modify/delete is the only kind of behavioral
# observation that can contradict a relationship — a 401/403 is the
# boundary holding, not a violation. Reused by detect_relationship_
# violations() below.
_SUCCESS_STATUS_LOW, _SUCCESS_STATUS_HIGH = 200, 300


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_observation_id() -> str:
    return "obs-" + secrets.token_hex(4)


# ─── Observation ────────────────────────────────────────────────────────────

def make_observation(
    subject_id: str,
    object_ref: str,
    event: str,
    evidence: list[dict],
    relationship_type: str | None = None,
    outcome_status: int | None = None,
    ts: str | None = None,
    metadata: dict | None = None,
) -> dict:
    """Build one Observation. RUNTIME-DERIVED ONLY (module docstring):
    every Observation MUST carry at least one Evidence Typing entry — an
    event with none raises, it is never silently downgraded to "no
    relationship" (that would let a caller believe a violation candidate
    could later reference evidence that never existed). A relationship-
    establishing/ending event's relationship_type is checked against what
    that event is actually allowed to assert (a `created` observation
    cannot be labeled HAS_MEMBER); if the caller doesn't pass one, the
    correct one is filled in automatically since the event already
    determines it unambiguously.

    subject_id/object_ref are caller-supplied identity strings (see
    memory/identity.py's entity_id()/object_id()) — this function makes no
    claim about how the caller derived them and never parses a URL/field
    name to invent one itself.
    """
    if event not in OBSERVATION_EVENTS:
        raise ValueError(f"unknown observation event {event!r}, expected one of {sorted(OBSERVATION_EVENTS)}")
    if not evidence:
        raise ValueError(
            "Observation requires at least one Evidence Typing entry — "
            "OBJECT MODEL DISCIPLINE: no evidence means no relationship"
        )
    for entry in evidence:
        if entry.get("type") not in EVIDENCE_TYPES:
            raise ValueError(
                f"evidence entry has type {entry.get('type')!r}, not in EVIDENCE_TYPES vocabulary: "
                f"{sorted(EVIDENCE_TYPES)}"
            )

    expected_rel = _ESTABLISHING_EVENTS.get(event) or _ENDING_EVENTS.get(event)
    if expected_rel is not None:
        if relationship_type is None:
            relationship_type = expected_rel
        elif relationship_type != expected_rel:
            raise ValueError(f"event {event!r} establishes/ends {expected_rel!r}, not {relationship_type!r}")
    elif relationship_type is not None and relationship_type not in RELATIONSHIP_TYPES:
        raise ValueError(f"unknown relationship_type {relationship_type!r}, expected one of {sorted(RELATIONSHIP_TYPES)}")

    return {
        "id": new_observation_id(),
        "ts": ts or _now_iso(),
        "subject_id": subject_id,
        "object_id": object_ref,
        "event": event,
        "relationship_type": relationship_type,
        "outcome_status": outcome_status,
        "evidence": list(evidence),
        "metadata": dict(metadata or {}),
    }


class ObservationStore:
    """Append-only JSONL store for Observations. Same fcntl-locked-append +
    size-based rotation convention as memory/vuln_intelligence.py's
    _JsonlDB (kept self-contained rather than imported, for the same
    reason that class documents: nothing here should be able to regress
    an unrelated store). No dedup — this store's whole contract is that
    every valid observation is kept, in order, forever (until rotated)."""

    def __init__(self, path: str | Path, max_bytes: int = DEFAULT_MAX_BYTES, keep_backups: int = DEFAULT_KEEP):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes
        self.keep_backups = keep_backups

    def record(self, observation: dict) -> dict:
        """Append one already-built Observation (see make_observation()).
        Never overwrites, never deletes, never mutates `observation`."""
        line = json.dumps(observation, separators=(",", ":")) + "\n"
        encoded = line.encode("utf-8")

        rotate_if_needed(self.path, max_bytes=self.max_bytes, keep=self.keep_backups)

        fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                written = os.write(fd, encoded)
                if written != len(encoded):
                    raise OSError(f"Partial write: {written}/{len(encoded)} bytes")
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
        return observation

    def all(self) -> list[dict]:
        """Best-effort read: a corrupted line is skipped (warned to
        stderr), never raised — same convention as _JsonlDB.read_all()."""
        if not self.path.exists():
            return []
        entries = []
        with open(self.path, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(f"WARNING: {self.path.name} line {lineno} corrupted (skipping): {e}", file=sys.stderr)
        return entries


# ─── Relationship computation (pure — recomputed from observations every call) ─

def compute_relationships(observations: list[dict]) -> dict[tuple[str, str, str], dict]:
    """Recompute the CURRENT relationship graph from the full observation
    history. Pure — never mutates `observations`. Key:
    (subject_id, relationship_type, object_id). Value: {"status",
    "created_at", "last_confirmed_at", "evidence", "history"} — `history`
    keeps every prior status this exact edge held, for audit; only
    `status` (the latest) is ever used by lookups, which is what makes a
    legitimate ownership transfer or membership revocation stop being a
    violation source instead of a false positive."""
    ordered = sorted(observations, key=lambda o: o.get("ts", ""))
    state: dict[tuple[str, str, str], dict] = {}

    def _upsert(subject: str, rel: str, obj: str, status: str, obs: dict) -> None:
        key = (subject, rel, obj)
        entry = state.get(key)
        if entry is None:
            state[key] = {
                "subject_id": subject, "relationship_type": rel, "object_id": obj,
                "status": status, "created_at": obs["ts"], "last_confirmed_at": obs["ts"],
                "evidence": list(obs["evidence"]), "history": [],
            }
            return
        entry["history"].append({"status": entry["status"], "at": entry["last_confirmed_at"]})
        entry["status"] = status
        entry["last_confirmed_at"] = obs["ts"]
        entry["evidence"] = entry["evidence"] + list(obs["evidence"])

    def _end(key: tuple[str, str, str], status: str, obs: dict) -> None:
        entry = state.get(key)
        if entry is not None and entry["status"] == "active":
            entry["history"].append({"status": entry["status"], "at": entry["last_confirmed_at"]})
            entry["status"] = status
            entry["last_confirmed_at"] = obs["ts"]

    for obs in ordered:
        event = obs["event"]
        subject, obj = obs["subject_id"], obs["object_id"]

        if event == "created":
            _upsert(subject, "OWNS", obj, "active", obs)
            org = obs.get("metadata", {}).get("organization_id")
            if org:
                _upsert(obj, "BELONGS_TO", org, "active", obs)
                _upsert(org, "CONTAINS", obj, "active", obs)
        elif event == "ownership_transferred":
            old_subject = obs.get("metadata", {}).get("transferred_from")
            if old_subject:
                _end((old_subject, "OWNS", obj), "superseded", obs)
            _upsert(subject, "OWNS", obj, "active", obs)
        elif event == "membership_granted":
            _upsert(subject, "HAS_MEMBER", obj, "active", obs)
        elif event == "membership_revoked":
            _end((subject, "HAS_MEMBER", obj), "revoked", obs)
        elif event == "invite_capability_granted":
            _upsert(subject, "CAN_INVITE", obj, "active", obs)
        elif event == "invite_capability_revoked":
            _end((subject, "CAN_INVITE", obj), "revoked", obs)
        elif event in _OBJECT_LIFECYCLE_EVENTS:
            new_status = "archived" if event == "archived" else "deleted"
            for key, entry in state.items():
                if obj in (key[0], key[2]) and entry["status"] == "active":
                    entry["history"].append({"status": entry["status"], "at": entry["last_confirmed_at"]})
                    entry["status"] = new_status
                    entry["last_confirmed_at"] = obs["ts"]
        # "accessed"/"modified": pure behavioral facts, never alter state —
        # see detect_relationship_violations() below.

    return state


def _active(state: dict, predicate) -> list[dict]:
    return [e for k, e in state.items() if e["status"] == "active" and predicate(k, e)]


# ─── Violation detection -> Candidates ──────────────────────────────────────

def detect_relationship_violations(observations: list[dict], target: str | None = None) -> list[dict]:
    """Observed behavior vs. the CURRENT relationship graph. A candidate
    here means "inconsistent with the currently observed relationship
    graph" — NOT "this is a vulnerability" (module docstring). Only a
    successful (2xx) accessed/modified/deleted observation is checked — a
    401/403 is the boundary holding, not evidence of anything wrong, and
    an object with no established OWNS edge at all has no relationship to
    contradict (no evidence means no relationship, so no violation can be
    raised against it either)."""
    state = compute_relationships(observations)
    candidates: list[dict] = []

    for obs in sorted(observations, key=lambda o: o.get("ts", "")):
        if obs["event"] not in ("accessed", "modified", "deleted"):
            continue
        status = obs.get("outcome_status")
        if status is None or not (_SUCCESS_STATUS_LOW <= status < _SUCCESS_STATUS_HIGH):
            continue

        subject, obj = obs["subject_id"], obs["object_id"]
        owners = _active(state, lambda k, e, obj=obj: k[1] == "OWNS" and k[2] == obj)
        if not owners:
            continue  # nothing established for this object -- no relationship to contradict
        owner_id = owners[0]["subject_id"]
        if owner_id == subject:
            continue  # the owner accessing their own object

        belongs_to = _active(state, lambda k, e, obj=obj: k[0] == obj and k[1] == "BELONGS_TO")
        subject_orgs = {k[0] for k, e in state.items()
                         if e["status"] == "active" and k[1] == "HAS_MEMBER" and k[2] == subject}
        permitted = any(e["object_id"] in subject_orgs for e in belongs_to)
        if permitted:
            continue

        vtype = "tenant_isolation_violation" if belongs_to else "ownership_violation"
        candidates.append(make_candidate(
            source="object-model",
            type_=vtype,
            evidence=list(owners[0]["evidence"]) + list(obs["evidence"]),
            rationale=(
                f"actor {subject} performed {obs['event']} (status {status}) on {obj}; the "
                f"current relationship graph's only active OWNS holder is {owner_id} and no "
                f"active HAS_MEMBER/BELONGS_TO path grants {subject} access. Observed behavior "
                f"appears inconsistent with the currently observed relationship graph."
            ),
            validation_plan={
                "steps": ["retry modifying request as non-owner"],
                "expected": "403 / 401",
                "stop_condition": "retry fails -> not reproducible",
            },
            provenance={"origin_lead_id": obs["id"], "origin_source": "object-model"},
            metadata={"target": target, "subject_id": subject, "object_id": obj, "owner_id": owner_id},
        ))

    return candidates
