"""Phase 7, Part A — the smallest safe producer that turns Phase 1's already-
collected recon/<target>/browser/api-calls.json into real memory/object_model.py
Observations, closing the "functionally dormant" half of Phase 6's disclosed
gap (nothing in the pipeline called ObservationStore.record() with real data).

WHY THIS IS A SEPARATE MODULE, NOT memory/object_model.py ITSELF: that
module's own docstring already explains, in detail, why no automatic
recon-artifact adapter was built in Phase 6 — tools/browser_recon.py's
shape_of()/shape_of_body() (confirmed by reading the actual implementation
before writing this) replace every leaf value in a request/response body
with its TYPE NAME ONLY (`{"id": 7}` -> `{"id": "number"}`). No concrete
field value survives into api-calls.json's request_body_shape/response_shape
— ever. That rules out the literal "same numeric ID in two response bodies"
scenario a naive adapter might attempt; there is no ID left to compare by
the time it reaches this file.

WHAT IS ACTUALLY AVAILABLE (the only two concrete, non-shaped values
api-calls.json persists):
  1. The full request URL, stored verbatim (ApiCallRecorder.on_request()'s
     `entry["url"] = request.url` — never shaped).
  2. request_headers_auth_fingerprint: a truncated sha256 of each auth
     header's raw value (tools/browser_recon.py's _value_fingerprint()) —
     already the exact mechanism memory/attack_graph.py's cross-host chain
     detection uses to recognize "the same actual secret value on two
     different hosts" without ever storing the raw value.

THE CORRELATION THIS MODULE BUILDS: two entries sharing the exact same
(method, url) string, produced under two DIFFERENT auth-fingerprint-derived
actors, both with a 2xx response, is genuine observed evidence that two
distinct authenticated identities interacted with the same concrete request
target — not a naming guess. Rule 11 forbids inferring relationships from
"endpoint paths, field names, URL segments" — the URL is deliberately never
parsed or split here; it is compared only as one opaque whole string, the
same "treat as an opaque comparable blob" pattern this repo already applies
to AuthSession fingerprints. No segment of it is ever assumed to "be" an
object id.

WHAT THIS MODULE DELIBERATELY DOES NOT DO: it never emits a relationship-
ESTABLISHING event (created/ownership_transferred/membership_granted/...).
Knowing that a specific request created or transferred an object requires
genuine out-of-band knowledge of what the request meant (memory/object_model.py's
own OBJECT MODEL DISCIPLINE) — an HTTP method/status code alone doesn't
supply that safely. This adapter only ever emits "accessed" behavioral
facts (evidence_type Observed-HTTP-Response). Those facts are real and
useful (they are exactly what detect_relationship_violations() needs on
the behavioral side), but by themselves they cannot yet produce a
relationship-violation Candidate — an establishing observation must still
come from a human, an agent, or a Part 3 stateful-session workflow, exactly
as Phase 6 intended. Conservative by construction: when in doubt (missing
fingerprint, single actor, non-2xx), this module produces NO observation.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from memory.identity import entity_id, object_id  # noqa: E402
from memory.object_model import ObservationStore, make_observation  # noqa: E402

_SUCCESS_STATUS_LOW, _SUCCESS_STATUS_HIGH = 200, 300


def _actor_key(entry: dict) -> str | None:
    """A stable, one-way identity for "whoever made this request", derived
    only from the already-hashed auth-header fingerprints api-calls.json
    stores (never a raw secret, never a header/field NAME treated as
    meaningful — the header names are sorted only to make the key order-
    independent, not interpreted). None when an entry carries no auth
    fingerprint at all — such an entry can never prove "a DIFFERENT
    authenticated context" against anything, so it is excluded rather than
    treated as some implicit "anonymous" actor that could falsely collide
    with another anonymous entry."""
    fp = entry.get("request_headers_auth_fingerprint") or {}
    if not fp:
        return None
    canonical = "|".join(f"{h}:{fp[h]}" for h in sorted(fp))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def _load_api_calls(target: str, recon_dir: str | Path) -> list[dict]:
    """Best-effort read of recon/<target>/browser/api-calls.json — same
    path convention tools/browser_recon.py's own writer uses. Never raises:
    missing file, unreadable file, or malformed JSON all just mean there is
    nothing to observe yet."""
    path = Path(recon_dir) / target / "browser" / "api-calls.json"
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        calls = data.get("calls")
    else:
        calls = data
    if not isinstance(calls, list):
        return []
    return [c for c in calls if isinstance(c, dict)]


def observe_from_api_calls(target: str, recon_dir: str | Path, store: ObservationStore) -> list[dict]:
    """Read api-calls.json, find (method, url) pairs hit by 2+ distinct
    authenticated actors with a 2xx response each, and record one "accessed"
    Observation per qualifying (actor, entry). Returns the list of
    Observations actually recorded (empty list on no correlation found, or
    on missing/malformed input — never raises for either).
    """
    calls = _load_api_calls(target, recon_dir)

    groups: dict[tuple[str, str], list[tuple[str, dict]]] = {}
    for entry in calls:
        method = entry.get("method")
        url = entry.get("url")
        status = entry.get("response_status")
        if not method or not url or status is None:
            continue
        if not (_SUCCESS_STATUS_LOW <= status < _SUCCESS_STATUS_HIGH):
            continue
        actor = _actor_key(entry)
        if actor is None:
            continue
        groups.setdefault((method, url), []).append((actor, entry))

    recorded: list[dict] = []
    for (method, url), hits in groups.items():
        distinct_actors = {actor for actor, _ in hits}
        if len(distinct_actors) < 2:
            continue  # only one authenticated context ever touched this exact request target -- no correlation

        object_ref = object_id("http-endpoint", url)
        for actor, entry in hits:
            obs = make_observation(
                subject_id=entity_id("User", actor),
                object_ref=object_ref,
                event="accessed",
                evidence=[{
                    "type": "Observed-HTTP-Response",
                    "detail": (
                        f"{method} {url} -> {entry['response_status']}; same request target observed "
                        f"across {len(distinct_actors)} distinct authenticated actors"
                    ),
                    "artifact": url,
                }],
                outcome_status=entry["response_status"],
                metadata={"target": target, "trigger": entry.get("trigger")},
            )
            recorded.append(store.record(obs))

    return recorded
