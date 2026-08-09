---
description: Pick up a previous hunt on a target — shows hunt history, untested endpoints, and memory-informed suggestions. Usage: /pickup target.com
---

# /pickup

Pick up where you left off on a target.

> **Renamed from `/resume`** — `/resume` is a reserved Claude Code command. Use `/pickup` to continue a previous hunt.

## What This Does

1. Reads the target profile from `hunt-memory/targets/<target>.json`
2. Shows hunt history (sessions, findings, payouts)
3. **If `recon/<target>/hunt-plan.json` exists, this is the authoritative resume
   point** — it's `director.py`'s own queue state, more precise than re-deriving
   "what's untested" from recon output alone, because it already reflects every
   `replan()` call (including one fired the moment an attack started testing, not
   just when it finished — see `agents/autopilot.md` Step 6) from the interrupted
   session:
   ```bash
   python3 -c "
   import json
   plan = json.load(open('recon/<target>/hunt-plan.json'))
   for a in plan['attacks']:
       if a['state'] in ('IN_PROGRESS', 'READY'):
           print(f\"[{a['state']:11}] {a['id']}  {a['vuln_class']:20} {a['evidence'][:1] or a['skill']}\")
   "
   ```
   An `IN_PROGRESS` attack here means the last session was killed mid-test on it —
   resume there first, not from the top of `READY`. Then continue the queue with
   `tools/director.py replan` exactly as Step 6 of `/autopilot` does; do **not**
   re-run `build-plan`, which would discard this state and re-derive a fresh queue.
   If `hunt-plan.json` doesn't exist (no `/autopilot` session ran, or recon was the
   only thing done last time), fall through to step 4 below.
4. **If `hunt-memory/object_model/checkpoints/<target>__*.json` files exist, show
   each one's `workflow_state`** — these are `tools/business_logic_probe.py`'s Part 3
   checkpoints, written automatically after every real `--establish`/`--probe` call
   (never opt-in). One file per pattern under test:
   ```bash
   python3 -c "
   import glob, json
   for f in sorted(glob.glob('hunt-memory/object_model/checkpoints/<target>__*.json')):
       cp = json.load(open(f))
       ws = cp['workflow_state']
       print(f\"[{ws.get('pattern')}] last_action={ws.get('last_action')} \"
             f\"org_ref={ws.get('org_ref')} violation_detected={ws.get('violation_detected')}\")
   "
   ```
   A checkpoint showing `last_action=establish` with no matching `--probe` run yet
   means the relationship precondition is on record but the actual test was never
   fired — resume by running `--probe` for that pattern, not `--establish` again
   (re-establishing is harmless but redundant; the precondition already holds).
   `violation_detected=True` on a `probe` checkpoint means a candidate is already
   sitting in the lead board from before the interruption — check there first
   rather than re-probing.
5. Otherwise, lists untested endpoints from last recon
6. Suggests techniques based on tech stack + pattern DB, and flags any technique already in `hunt-memory/failed_patterns.jsonl` for this target as a don't-retry
7. Asks: continue hunting or re-run recon?

## Usage

```
/pickup target.com
```

## Output

```
PICKUP: target.com
═══════════════════════════════════════

Hunt History:
  Sessions:    3
  Last hunt:   2026-03-24
  Total time:  2h 00m
  Findings:    1 confirmed (IDOR, $1500 paid)

Resumable Plan (recon/target.com/hunt-plan.json):
  [IN_PROGRESS] atk-a1b2c3  idor  /api/v2/users/{id}/export   <- killed mid-test, resume here first
  [READY]       atk-d4e5f6  ssrf  /api/v2/webhooks/register
  [READY]       atk-a7b8c9  idor  /api/v2/users/{id}/share

Business-Logic Checkpoints (hunt-memory/object_model/checkpoints/):
  [invite_flow] last_action=establish org_ref=42   <- precondition on record, --probe not run yet
  [refund]      last_action=probe org_ref=17 violation_detected=True   <- check lead board first

Untested Surface (no hunt-plan.json — shown only when the above is empty):
  3 endpoints from last recon:
  1. /api/v2/users/{id}/export
  2. /api/v2/users/{id}/share
  3. /api/v2/users/{id}/history

Memory Suggestions:
  Tech stack [Next.js, GraphQL, PostgreSQL] matches 2 targets
  where you found auth bypass. Try introspection → mutation pattern.

Don't Retry:
  ssrf/webhook_url_param — rejected 2026-03-01: "egress filtered"

Actions:
  [r] Continue hunting untested endpoints
  [n] Re-run recon first (surface may have changed)
  [s] Show full hunt journal for this target
```

## If No Previous Hunt

```
No previous hunt data for target.com.
Run /recon target.com first, then /hunt target.com.
```
