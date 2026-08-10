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
from dataclasses import dataclass
from pathlib import Path

import yaml

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from memory.candidate import EVIDENCE_TYPES, make_candidate  # noqa: E402
from memory.rotation import DEFAULT_KEEP, DEFAULT_MAX_BYTES, rotate_if_needed  # noqa: E402
from memory.atomic_write import atomic_write_text  # noqa: E402
from tools.auth_session import AuthSession  # noqa: E402

DEFAULT_LOGIC_PATTERNS_PATH = os.path.join(_REPO, "rules", "logic_patterns.yaml")

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


# ─── Part 2: business logic taxonomy — rules/logic_patterns.yaml ───────────
#
# Data, not per-pattern Python (rules/logic_patterns.yaml's own header
# comment has the full schema) — the same "rules as data" convention
# rules/chain_rules.yaml established for memory/attack_graph.py. ONE
# generic executor (detect_logic_pattern_violations() below) interprets
# every pattern; adding a new business-logic pattern is a YAML addition,
# never a new Python branch.


class LogicPatternLoadError(Exception):
    """rules/logic_patterns.yaml failed to parse or validate. Raised
    loudly — never silently skipped or defaulted, same discipline as
    memory/attack_graph.py's RuleLoadError."""


@dataclass(frozen=True)
class LogicPattern:
    id: str
    description: str
    enabled: bool
    required_relationships: tuple[str, ...]
    action_event: str
    performed_by: str
    requires_active_relationship: str
    governing_object: str
    skill: str
    vuln_type: str
    violation: str
    validation_plan: dict
    action_context: str | None = None
    relationship_direction: str = "performed_by_to_governing"


_RELATIONSHIP_DIRECTIONS = frozenset({"performed_by_to_governing", "governing_to_performed_by"})
_FIELD_REFS = frozenset({"subject_id", "object_id"})


def _valid_field_ref(value: str) -> bool:
    return value in _FIELD_REFS or value.startswith("metadata.")


def load_logic_patterns(path: str | None = None) -> list[LogicPattern]:
    """Load + validate rules/logic_patterns.yaml. Raises LogicPatternLoadError
    (or lets yaml.YAMLError propagate) on any malformed input — a typo can
    never quietly disable/misdefine a pattern without being noticed, same
    discipline as memory/attack_graph.py's load_chain_rules()."""
    path = path or DEFAULT_LOGIC_PATTERNS_PATH
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except OSError as exc:
        raise LogicPatternLoadError(f"cannot read {path}: {exc}") from exc

    if not isinstance(raw, list):
        raise LogicPatternLoadError(f"{path}: top-level content must be a YAML list of patterns, got {type(raw).__name__}")

    patterns: list[LogicPattern] = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            raise LogicPatternLoadError(f"{path}: pattern #{i} is not a mapping")

        pid = item.get("id")
        if not isinstance(pid, str) or not pid.strip():
            raise LogicPatternLoadError(f"{path}: pattern #{i} missing required non-empty 'id'")

        description = item.get("description")
        if not isinstance(description, str) or not description.strip():
            raise LogicPatternLoadError(f"pattern {pid!r}: missing required non-empty 'description'")

        enabled = item.get("enabled", True)
        if not isinstance(enabled, bool):
            raise LogicPatternLoadError(f"pattern {pid!r}: 'enabled' must be a bool, got {enabled!r}")

        required = item.get("required_relationships")
        if not isinstance(required, list) or not required or any(r not in RELATIONSHIP_TYPES for r in required):
            raise LogicPatternLoadError(
                f"pattern {pid!r}: 'required_relationships' must be a non-empty list drawn from "
                f"{sorted(RELATIONSHIP_TYPES)}, got {required!r}"
            )

        action_event = item.get("action_event")
        if action_event not in OBSERVATION_EVENTS:
            raise LogicPatternLoadError(
                f"pattern {pid!r}: 'action_event' {action_event!r} not in {sorted(OBSERVATION_EVENTS)}"
            )

        action_context = item.get("action_context")
        if action_context is not None and not isinstance(action_context, str):
            raise LogicPatternLoadError(f"pattern {pid!r}: 'action_context' must be a string if present")

        performed_by = item.get("performed_by")
        if not isinstance(performed_by, str) or not _valid_field_ref(performed_by):
            raise LogicPatternLoadError(
                f"pattern {pid!r}: 'performed_by' must be 'subject_id', 'object_id', or 'metadata.<key>', "
                f"got {performed_by!r}"
            )

        governing_object = item.get("governing_object")
        if not isinstance(governing_object, str) or not _valid_field_ref(governing_object):
            raise LogicPatternLoadError(
                f"pattern {pid!r}: 'governing_object' must be 'subject_id', 'object_id', or 'metadata.<key>', "
                f"got {governing_object!r}"
            )

        requires_active_relationship = item.get("requires_active_relationship")
        if requires_active_relationship not in RELATIONSHIP_TYPES:
            raise LogicPatternLoadError(
                f"pattern {pid!r}: 'requires_active_relationship' {requires_active_relationship!r} "
                f"not in {sorted(RELATIONSHIP_TYPES)}"
            )

        relationship_direction = item.get("relationship_direction", "performed_by_to_governing")
        if relationship_direction not in _RELATIONSHIP_DIRECTIONS:
            raise LogicPatternLoadError(
                f"pattern {pid!r}: 'relationship_direction' must be one of {sorted(_RELATIONSHIP_DIRECTIONS)}, "
                f"got {relationship_direction!r}"
            )

        skill = item.get("skill")
        if not isinstance(skill, str) or not skill.startswith("hunt-"):
            raise LogicPatternLoadError(f"pattern {pid!r}: 'skill' must be a 'hunt-*' string, got {skill!r}")

        vuln_type = item.get("vuln_type")
        if not isinstance(vuln_type, str) or not vuln_type.strip():
            raise LogicPatternLoadError(f"pattern {pid!r}: missing required non-empty 'vuln_type'")

        violation = item.get("violation")
        if not isinstance(violation, str) or not violation.strip():
            raise LogicPatternLoadError(f"pattern {pid!r}: missing required non-empty 'violation'")

        vp = item.get("validation_plan")
        if (not isinstance(vp, dict) or "steps" not in vp or "expected" not in vp
                or "stop_condition" not in vp):
            raise LogicPatternLoadError(
                f"pattern {pid!r}: 'validation_plan' must be a mapping with steps/expected/stop_condition"
            )

        patterns.append(LogicPattern(
            id=pid, description=description, enabled=enabled,
            required_relationships=tuple(required), action_event=action_event,
            performed_by=performed_by, requires_active_relationship=requires_active_relationship,
            governing_object=governing_object, skill=skill, vuln_type=vuln_type,
            violation=violation, validation_plan=vp, action_context=action_context,
            relationship_direction=relationship_direction,
        ))

    return patterns


def _resolve_field(obs: dict, ref: str):
    if ref == "subject_id":
        return obs.get("subject_id")
    if ref == "object_id":
        return obs.get("object_id")
    if ref.startswith("metadata."):
        return (obs.get("metadata") or {}).get(ref[len("metadata."):])
    return None


def _relationship_active_before(observations: list[dict], ts: str, subject: str, rel: str, obj: str) -> bool:
    """Point-in-time check: was (subject, rel, obj) active in the
    relationship graph as it stood strictly BEFORE `ts`? Used instead of
    the final/current state so a pattern's own action (e.g. an ownership
    transfer) is never evaluated against the state it just changed."""
    prior = [o for o in observations if o.get("ts", "") < ts]
    state = compute_relationships(prior)
    entry = state.get((subject, rel, obj))
    return entry is not None and entry["status"] == "active"


def detect_logic_pattern_violations(
    observations: list[dict],
    patterns: list[LogicPattern] | None = None,
    target: str | None = None,
) -> list[dict]:
    """The Part 2 generic executor. For each enabled pattern: GATE first —
    if the object model has no observed instance (any status) of every one
    of the pattern's required_relationships, the pattern does NOT execute
    (Part 2, non-negotiable: "Missing relationship evidence means: Pattern
    does NOT execute. Never guess."). Otherwise, scan observations matching
    action_event (+ action_context, if the pattern declares one) and flag
    any where `performed_by` did NOT hold `requires_active_relationship`
    against `governing_object` immediately beforehand. Emits Candidates —
    same "inconsistent with the observed graph, not asserted as a
    vulnerability" discipline as detect_relationship_violations()."""
    patterns = load_logic_patterns() if patterns is None else patterns
    present_types = {k[1] for k in compute_relationships(observations)}
    candidates: list[dict] = []

    for pattern in patterns:
        if not pattern.enabled:
            continue
        if not set(pattern.required_relationships).issubset(present_types):
            continue

        for obs in sorted(observations, key=lambda o: o.get("ts", "")):
            if obs["event"] != pattern.action_event:
                continue
            if pattern.action_context is not None and (obs.get("metadata") or {}).get("context") != pattern.action_context:
                continue
            status = obs.get("outcome_status")
            if status is not None and not (_SUCCESS_STATUS_LOW <= status < _SUCCESS_STATUS_HIGH):
                continue

            performed_by = _resolve_field(obs, pattern.performed_by)
            governing_object = _resolve_field(obs, pattern.governing_object)
            if not performed_by or not governing_object:
                continue  # can't evaluate without both — never guess

            if pattern.relationship_direction == "governing_to_performed_by":
                rel_subject, rel_object = governing_object, performed_by
            else:
                rel_subject, rel_object = performed_by, governing_object
            if _relationship_active_before(observations, obs["ts"], rel_subject,
                                            pattern.requires_active_relationship, rel_object):
                continue

            rationale = pattern.violation.format(
                object_id=obs["object_id"], performed_by=performed_by, governing_object=governing_object,
            ).strip()
            candidates.append(make_candidate(
                source="object-model",
                type_=pattern.vuln_type,
                evidence=list(obs["evidence"]),
                rationale=rationale,
                validation_plan=dict(pattern.validation_plan),
                provenance={"origin_lead_id": obs["id"], "origin_source": f"logic_patterns.yaml#{pattern.id}"},
                metadata={
                    "target": target, "pattern_id": pattern.id,
                    "performed_by": performed_by, "governing_object": governing_object,
                },
            ))

    return candidates


# ─── Part 3: stateful session checkpoint ────────────────────────────────────
#
# Reuses tools/auth_session.py's AuthSession — no reinvention. Same JSON
# sidecar convention as tools/director.py's save_plan()/load_plan()
# (plain json.dumps(..., indent=2, sort_keys=True), plain json.loads()).
#
# NEVER PERSISTED: cookies, bearer tokens, passwords, session IDs (the raw
# values). AuthSession.session_id() is already a one-way sha256 hash of the
# canonical header set (tools/auth_session.py's own docstring: "Secrets
# never appear in logs or repr/str. The session_id is the only piece
# written to hunt-memory") — that hash, never AuthSession.headers_dict()/
# headers_list()/curl_args(), is the only thing this checkpoint ever
# touches. reachable_objects/reachable_capabilities are validated to be
# memory/identity.py-shaped reference strings (entity:/object:/endpoint:/
# capability:), not arbitrary values, so a caller can't accidentally smuggle
# a raw secret into either list.

CHECKPOINT_VERSION = 1
_IDENTITY_PREFIXES = ("entity:", "object:", "endpoint:", "capability:")


def _is_identity_ref(value) -> bool:
    return isinstance(value, str) and value.startswith(_IDENTITY_PREFIXES)


def make_checkpoint(
    workflow_state: dict,
    reachable_objects: list[str],
    reachable_capabilities: list[str],
    auth_session: AuthSession | None = None,
    metadata: dict | None = None,
) -> dict:
    """Build a workflow checkpoint. Raises ValueError if reachable_objects/
    reachable_capabilities contain anything that isn't a memory/identity.py
    -shaped reference string — the one guard against a raw value (a cookie,
    a token, a literal user-supplied string) ending up somewhere this
    checkpoint will later be written to disk."""
    for label, refs in (("reachable_objects", reachable_objects), ("reachable_capabilities", reachable_capabilities)):
        for ref in refs:
            if not _is_identity_ref(ref):
                raise ValueError(
                    f"{label} entry {ref!r} is not an identity reference "
                    f"(memory/identity.py — expected one of {_IDENTITY_PREFIXES})"
                )

    fingerprint = None
    if auth_session is not None and not auth_session.is_empty():
        fingerprint = auth_session.session_id()

    return {
        "version": CHECKPOINT_VERSION,
        "workflow_state": dict(workflow_state),
        "reachable_objects": list(reachable_objects),
        "reachable_capabilities": list(reachable_capabilities),
        "fingerprinted_session_reference": fingerprint,
        "metadata": dict(metadata or {}),
    }


def save_session(checkpoint: dict, path: str | Path) -> str:
    """JSON sidecar for cross-process workflow resume — same convention as
    tools/director.py's save_plan(), including its atomic write (memory/
    atomic_write.py): a crash mid-write to a business-logic checkpoint
    that's been accumulating real --establish/--probe workflow_state
    across a multi-step test would otherwise corrupt or empty it, taking
    /pickup's "where you left off" resume with it."""
    out_path = Path(path)
    atomic_write_text(out_path, json.dumps(checkpoint, indent=2, sort_keys=True) + "\n")
    return str(out_path)


def load_session(path: str | Path) -> dict:
    """Inverse of save_session() — same convention as tools/director.py's
    load_plan(). Raises ValueError if the file's `version` doesn't match
    CHECKPOINT_VERSION this module knows how to read (fail loud on a
    future format change, rather than silently misinterpreting one)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("version") != CHECKPOINT_VERSION:
        raise ValueError(f"unsupported checkpoint version {data.get('version')!r}, expected {CHECKPOINT_VERSION}")
    return data
