"""
Shared identity scheme — Phase 6 (Logic-Bug Agent), Part 0.

Canonical reference-id convention shared by memory/object_model.py,
memory/candidate.py, and (for the two prefixes that already existed)
memory/attack_graph.py:

    entity:<type>:<id>       a real-world actor node — User/Role/Organization
    object:<type>:<id>       an application object node — a document, an
                              order, a project, ... (Object-type entity)
    endpoint:<path>          an HTTP endpoint
    capability:<name>        a named capability/permission

Every id is a flat "<prefix>:<value>" string, matching the convention
memory/attack_graph.py's Node/Edge ids already use (asset:<target>,
lead:<id>, endpoint:<url>, capability:<name>, boundary:<route>,
credential:xhost:<fp>, impact:<rule.id>) — no competing format is
introduced here.

attack_graph.py's Asset/Lead/Boundary/Credential/Impact node ids predate
this module and are OUTSIDE this scheme's four prefixes (entity:/object:/
endpoint:/capability:) — they are NOT renamed here. Doing so would break
byte-identical Node/Edge ids relied on throughout tests/test_attack_graph.py
(PERMANENT RULE 2: additive only, byte-identical behavior). Its existing
endpoint:/capability: node-id construction IS refactored (same Part 0
batch) to call endpoint_id()/capability_id() below instead of an inline
f-string — same output, every character — which is the concrete form
"align attack_graph.py with this convention" takes without changing
anything it computes.
"""

from __future__ import annotations


def entity_id(entity_type: str, ref: str) -> str:
    """A real-world actor node id — User/Role/Organization. `ref` is
    caller-supplied (e.g. an AuthSession fingerprint, an explicit human-
    provided user id) — this module makes no claim about where it came
    from."""
    return f"entity:{entity_type}:{ref}"


def object_id(object_type: str, ref: str) -> str:
    """An application-object node id — Object-type entity instances (a
    document, an order, ...). `object_type` is a caller-supplied bucket
    label, never derived here from a URL path or field name."""
    return f"object:{object_type}:{ref}"


def endpoint_id(path: str) -> str:
    """Matches memory/attack_graph.py's pre-existing endpoint:<url> node id
    exactly — same prefix, same value, zero behavior change."""
    return f"endpoint:{path}"


def capability_id(name: str) -> str:
    """Matches memory/attack_graph.py's pre-existing capability:<name> node
    id exactly — same prefix, same value, zero behavior change."""
    return f"capability:{name}"
