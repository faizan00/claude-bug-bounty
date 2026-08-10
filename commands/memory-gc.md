---
description: Inspect or rotate every hunt-memory JSONL file (audit.jsonl, patterns.jsonl, journal.jsonl, failed_patterns.jsonl, chains.jsonl, report_outcomes.jsonl, hypotheses.jsonl, experiments.jsonl, finding_states.jsonl, object_model/<target>.jsonl). Caps file size and keeps N rotated backups so memory does not grow unbounded.
---

# /memory-gc

Garbage-collect the hunt-memory directory. Reports current sizes, rotates oversized files past a configurable cap, or purges old backups.

## Why This Exists

Append-only logs grow without bound. On active hunters:
- `audit.jsonl` can reach 100 MB+ in months (every outbound request)
- `patterns.jsonl`, `journal.jsonl`, `chains.jsonl`, `hypotheses.jsonl`, `report_outcomes.jsonl`, `failed_patterns.jsonl`, `experiments.jsonl`, `finding_states.jsonl`, and `object_model/<target>.jsonl` all accumulate forever too

This command surfaces that growth and gives you a one-shot fix.

## Usage

```
/memory-gc                       # report only
/memory-gc --rotate              # rotate files above 10 MB (default cap)
/memory-gc --rotate --max-mb 5   # custom cap
/memory-gc --purge-backups       # delete all .1/.2/.3 backups
/memory-gc --dir <path>          # scan a non-default hunt-memory dir
```

## What It Does

1. Walks the hunt-memory directory recursively.
2. Finds every file matching `tools/memory_gc.py`'s `ROTATABLE` list at any depth: `audit.jsonl`, `patterns.jsonl`, `journal.jsonl`, `failed_patterns.jsonl`, `chains.jsonl`, `report_outcomes.jsonl`, `hypotheses.jsonl`, `experiments.jsonl`, `finding_states.jsonl`, and `object_model/*.jsonl` (one file per target — `memory/object_model.py`'s per-target observation log, unlike every other entry here which is a single shared file).
3. Prints a per-file table: live size, total (live + backups), backup count, status.
4. With `--rotate`: renames oversize files to `<file>.1`, shifting older backups up to `<file>.{keep}`. The oldest is dropped.
5. With `--purge-backups`: removes every `.1`/`.2`/`.3` backup, keeping only live files.

`memory/leads/<target>.jsonl` (the lead board, `tools/lead_board.py`) is
deliberately **not** covered — it lives outside `hunt-memory/` entirely and
is a stateful keyed ledger (read-modify-write on every `ingest`/`touch`/`add`
call), not a pure append-only log. Byte-cap rotation is only safe for
append-only files; applying it here would silently drop killed/reported
lead history, violating Critical Rule 6 ("never lose a lead"). If that
ledger ever needs size management, it needs its own compaction design, not
this tool.

## Implementation

The agent shells out to:

```bash
python -m tools.memory_gc [args]
```

from the repo root.

## Defaults

- **Rotation cap:** 10 MB per file
- **Backups kept:** 3 (so `<file>.1` newest → `<file>.3` oldest)
- **Scope:** `hunt-memory/` and any nested target dirs

Auto-rotation fires automatically in two places:

1. **On every write** — every one of the 10 classes above (`AuditLog`, `PatternDB`, `FailedPatternDB`, `ChainDB`, `ReportOutcomeDB`, `HypothesisDB`, `ExperimentDB`, `FindingStateDB`, `ObservationStore`, plus the journal writer) calls `memory.rotation.rotate_if_needed()` inside its own `.save()`/`.record()`/`.log()` before appending — this is what actually protects every one of these files from unbounded growth. It doesn't depend on this command ever being run.
2. **On session end** — a `Stop` hook in `.claude/settings.json` runs `python3 -m tools.memory_gc --rotate`, catching anything that crossed the cap but hasn't been written to again since (the on-write trigger above only fires on the *next* write to that specific file).

This command's job is reporting/visibility and manual cleanup — the files stay protected from unbounded growth whether or not you ever run it.

So this slash command is mainly for ad-hoc reporting (`/memory-gc` with no args) and manual cleanup of accumulated backups (`/memory-gc --purge-backups`).
