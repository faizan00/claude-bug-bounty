#!/usr/bin/env python3
"""
Target Profile — read-only composition of everything currently known about
a target, built from the stores that already exist (architecture audit,
Milestone 1).

This is NOT a new memory system, NOT a cache, NOT a graph engine. It never
writes anything and it is not persisted — every call re-reads the live
stores below and returns a fresh dict. Safe to call repeatedly; calling it
twice with no state change returns equivalent data.

Sources composed (all reused as-is, none reimplemented):
  tech_stack          tools.director.load_tech_stack()
  assets              memory.attack_graph.build_capability_graph() —
                       Asset/Endpoint nodes only (the existing lead-derived
                       graph; no second graph representation)
  relationships        memory.object_model.compute_relationships(), fed by
                       memory.object_model.ObservationStore — returned
                       exactly as that function produces it (tuple-keyed
                       dict), never reshaped, so it cannot silently drift
                       from what detect_relationship_violations() itself
                       sees
  leads_summary /
  active_hypotheses    tools.lead_board.load_ledger()
  confirmed_findings   memory.finding_state.FindingStateDB — the most
                       recent transition per (vuln_class, endpoint) for
                       this target, kept only where that latest state is
                       exactly "CONFIRMED" (not SELF_CRITIQUED/REPORT_READY
                       — see build_target_profile()'s docstring for why
                       this is a deliberate, narrow reading)
  failed_techniques    memory.vuln_intelligence.FailedPatternDB, filtered
                       to this target

Cold start: every source that has no on-disk file yet for this target
contributes its empty/default value — never raises, never fabricates data.
Each underlying *Store/*DB class's own __init__() creates its parent
directory as a side effect (pre-existing behavior in every one of these
classes, not something introduced here) — so every source below is gated
behind checking the target-specific file's own existence BEFORE
constructing the class that would read it, keeping a true cold-start call
free of any filesystem mutation, not just free of data writes.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from tools import director  # noqa: E402
from tools import lead_board  # noqa: E402
from memory import attack_graph  # noqa: E402
from memory import object_model  # noqa: E402
from memory import finding_state  # noqa: E402
from memory import vuln_intelligence  # noqa: E402

_ASSET_NODE_TYPES = ("Asset", "Endpoint")
_LEAD_STATUS_KEYS = ("new", "investigating", "killed", "reported")


def _leads_summary(leads: list[dict]) -> dict[str, int]:
    summary = {k: 0 for k in _LEAD_STATUS_KEYS}
    for lead in leads:
        status = lead.get("status")
        if status in summary:
            summary[status] += 1
    return summary


def _active_hypotheses(leads: list[dict]) -> list[dict]:
    return [
        lead for lead in leads
        if lead.get("source") == "hypothesis" and lead.get("status") == "new"
    ]


def _assets_from_graph(graph: attack_graph.Graph) -> dict:
    """Asset/Endpoint nodes only — the two node types that represent the
    target's actual inventory, as opposed to Credential/Capability/Boundary
    nodes (leaks, auth-model artifacts) which aren't "assets" in that
    sense. Every field the real Node dataclass carries is preserved,
    including its own provenance/confidence_source, so a caller never sees
    a stripped-down view."""
    return {
        "nodes": [
            {
                "id": node.id,
                "type": node.type,
                "label": node.label,
                "origin_lead_id": node.origin_lead_id,
                "origin_source": node.origin_source,
                "confidence_source": node.confidence_source,
                "vuln_class": node.vuln_class,
                "impact_severity": node.impact_severity,
            }
            for node in graph.nodes.values()
            if node.type in _ASSET_NODE_TYPES
        ],
    }


def _relationships(target: str, memory_dir: str) -> dict:
    om_path = director.object_model_observations_path(target, memory_dir)
    if not om_path.exists():
        return object_model.compute_relationships([])
    observations = object_model.ObservationStore(om_path).all()
    return object_model.compute_relationships(observations)


def _confirmed_findings(target: str, memory_dir: str) -> list[dict]:
    """The most recent finding_state.py transition per (vuln_class, endpoint)
    for this target, kept only where the CURRENT state is exactly
    "CONFIRMED". A finding that has since advanced to SELF_CRITIQUED or
    REPORT_READY is deliberately excluded here — the milestone spec asks
    for "only CONFIRMED findings", read literally rather than "CONFIRMED or
    anything downstream of it", since broadening that reading is a policy
    call this milestone doesn't need to make. Narrowing this later (e.g. to
    "CONFIRMED and beyond") is a one-line change if a future consumer needs
    it."""
    path = Path(memory_dir) / "finding_states.jsonl"
    if not path.exists():
        return []
    db = finding_state.FindingStateDB(path)
    entries = [e for e in db.read_all() if e.get("target") == target]
    entries.sort(key=lambda e: e.get("ts", ""))

    latest_by_key: dict[tuple[str, str], dict] = {}
    for entry in entries:
        key = (entry.get("vuln_class"), entry.get("endpoint"))
        latest_by_key[key] = entry

    return [entry for entry in latest_by_key.values() if entry.get("state") == "CONFIRMED"]


def _failed_techniques(target: str, memory_dir: str) -> list[dict]:
    path = Path(memory_dir) / "failed_patterns.jsonl"
    if not path.exists():
        return []
    db = vuln_intelligence.FailedPatternDB(path)
    return [entry for entry in db.read_all() if entry.get("target") == target]


def build_target_profile(target: str, memory_dir: str = "hunt-memory",
                          recon_dir: str | None = None) -> dict:
    """One live, read-only view of everything currently known about
    `target`, composed from the stores that already exist. Never writes
    anything; not persisted; safe to call repeatedly. See module docstring
    for exactly which function backs each field.

    Cold start: any source with no on-disk data for this target yet
    contributes its own empty/default value (tools.director.load_tech_stack()
    already does this for tech_stack; tools.lead_board.load_ledger() already
    does this for leads; the object_model/finding_state/failed_patterns
    sources are gated the same way here, before any *Store/*DB class is
    constructed, since those classes' own __init__() creates their parent
    directory as a side effect otherwise)."""
    recon_dir = recon_dir if recon_dir is not None else os.path.join("recon", target)

    leads = lead_board.load_ledger(target)
    graph = attack_graph.build_capability_graph(target, recon_dir=recon_dir, leads=leads)

    return {
        "target": target,
        "tech_stack": director.load_tech_stack(target, memory_dir),
        "assets": _assets_from_graph(graph),
        "relationships": _relationships(target, memory_dir),
        "leads_summary": _leads_summary(leads),
        "confirmed_findings": _confirmed_findings(target, memory_dir),
        "failed_techniques": _failed_techniques(target, memory_dir),
        "active_hypotheses": _active_hypotheses(leads),
    }


def main() -> int:
    import argparse
    import json

    ap = argparse.ArgumentParser(description="Read-only composed target profile")
    ap.add_argument("target")
    ap.add_argument("--memory-dir", default="hunt-memory")
    ap.add_argument("--recon-dir", default=None)
    args = ap.parse_args()

    profile = build_target_profile(args.target, memory_dir=args.memory_dir, recon_dir=args.recon_dir)
    # relationships is keyed by tuples (compute_relationships()'s native
    # shape, preserved as-is) — not directly JSON-serializable, so the CLI
    # renders it with string keys for display only; build_target_profile()
    # itself always returns the real tuple-keyed dict.
    printable = dict(profile)
    printable["relationships"] = {" | ".join(k): v for k, v in profile["relationships"].items()}
    print(json.dumps(printable, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
