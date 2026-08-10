#!/usr/bin/env python3
"""
Memory GC — inspect and rotate hunt-memory JSONL files.

Scans the hunt-memory directory for every append-only log this repo's
memory/*.py *DB/*Store classes already protect with a per-write
memory.rotation.rotate_if_needed() call (see ROTATABLE below) and reports
per-file size + backup usage. Optionally rotates oversize files or purges
existing backups.

Before this list covered only 3 of the (now) 10 files that already have
real on-write rotation protection — chains.jsonl/hypotheses.jsonl/
report_outcomes.jsonl/failed_patterns.jsonl/experiments.jsonl/
finding_states.jsonl/object_model/<target>.jsonl were all invisible here,
so `--dir hunt-memory` (no args) undersold actual disk usage, and the
session-end Stop-hook's blind `--rotate` call (.claude/settings.json)
missed them too. Not a silent-unbounded-growth risk on its own (the
per-write trigger inside each class's own .save()/.record() already
rotates on the very next write regardless of whether this tool ever
looked at the file) — purely a reporting/manual-rotation blind spot,
closed here for consistency with what CLAUDE.md's `memory/rotation.py`
bullet already claims applies repo-wide.

memory/leads/<target>.jsonl (the lead board, tools/lead_board.py) is
DELIBERATELY not covered here even though it's also a hunt-memory-
adjacent JSONL file: it's a stateful KEYED ledger (read-modify-write via
save_ledger()'s full-rewrite, not append-only) living outside the
hunt-memory/ tree entirely. Byte-cap rotation is safe only for pure
append-only logs (chop old bytes into a numbered backup, keep writing to
a fresh file) — applying it to a ledger where every entry's CURRENT
status/dedup-key membership must stay live-readable would silently drop
killed/reported lead history, violating "Critical Rule 6: never lose a
lead." A safe fix there needs its own compaction design (e.g. archiving
terminal-status leads while keeping their dedup keys indexed elsewhere),
not a blind reuse of this file's rotate-by-size logic.

Usage:
    python -m tools.memory_gc                       # report only
    python -m tools.memory_gc --dir hunt-memory     # report on a custom dir
    python -m tools.memory_gc --rotate              # force-rotate live files
    python -m tools.memory_gc --rotate --max-mb 5   # rotate above 5 MB
    python -m tools.memory_gc --purge-backups       # delete all .1/.2/.3 files
"""

import argparse
import os
import sys
from pathlib import Path

# Make memory/ importable when running as a script from repo root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.banner import print_banner  # noqa: E402
from memory.rotation import (  # noqa: E402
    DEFAULT_KEEP,
    DEFAULT_MAX_BYTES,
    list_backups,
    purge_backups,
    rotate_if_needed,
    total_bytes,
)

# Files/patterns we consider rotatable, matched via Path.rglob() (works
# identically for a bare filename or a glob pattern with wildcards -- see
# _find_targets()). Anything else in the directory is left alone.
#
# "object_model/*.jsonl" is the one entry that needs a wildcard:
# memory.object_model.ObservationStore writes one <target>.jsonl file per
# target under hunt-memory/object_model/ (see
# tools/director.py::object_model_observations_path()), unlike every
# other entry here, which is a single fixed filename shared across all
# targets in one hunt-memory dir.
ROTATABLE = (
    "audit.jsonl",
    "patterns.jsonl",
    "journal.jsonl",
    "failed_patterns.jsonl",
    "chains.jsonl",
    "report_outcomes.jsonl",
    "hypotheses.jsonl",
    "experiments.jsonl",
    "finding_states.jsonl",
    "object_model/*.jsonl",
)


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def _find_targets(root: Path) -> list[Path]:
    """Return all rotatable JSONL "live" paths at any depth under root.

    Also includes paths whose live file is gone but rotated backups exist —
    so ``--purge-backups`` can still clean them up.
    """
    if not root.exists():
        return []
    found: set[Path] = set()
    for pattern in ROTATABLE:
        found.update(root.rglob(pattern))
        # Match orphaned backups (audit.jsonl.1, object_model/acme.jsonl.2,
        # ...) and surface their live path as a target even if the live
        # file is gone. Path.match() (not a bare name==name comparison)
        # so this stays precise for the "object_model/*.jsonl" wildcard
        # entry too -- a coincidental "object_model/x.jsonl.bak.1" strips
        # to "object_model/x.jsonl.bak", which correctly does NOT match
        # "object_model/*.jsonl" and is left alone.
        for bp in root.rglob(pattern + ".*"):
            stem = bp.with_suffix("")  # strip the .N suffix
            if stem.match(pattern):
                found.add(stem)
    return sorted(found)


def report(root: Path, max_bytes: int, keep: int) -> int:
    """Print per-file size report. Returns the number of files over cap."""
    targets = _find_targets(root)
    if not targets:
        print(f"No rotatable files under {root}")
        return 0

    print(f"Scanning {root} (cap: {_human_size(max_bytes)}, keep: {keep})")
    print()
    print(f"{'FILE':<60} {'LIVE':>10} {'TOTAL':>10} {'BACKUPS':>8}  STATUS")
    print("-" * 100)

    over = 0
    for path in targets:
        live = path.stat().st_size if path.exists() else 0
        total = total_bytes(path, keep=keep)
        backups = len(list_backups(path, keep=keep))
        status = "OVER CAP" if live >= max_bytes else "ok"
        if live >= max_bytes:
            over += 1
        rel = path.relative_to(root) if path.is_relative_to(root) else path
        print(
            f"{str(rel):<60} {_human_size(live):>10} "
            f"{_human_size(total):>10} {backups:>8}  {status}"
        )
    return over


def do_rotate(root: Path, max_bytes: int, keep: int) -> int:
    """Rotate every oversize file. Returns the count rotated."""
    rotated = 0
    for path in _find_targets(root):
        if rotate_if_needed(path, max_bytes=max_bytes, keep=keep):
            rotated += 1
            print(f"rotated: {path}")
    return rotated


def do_purge(root: Path, keep: int) -> int:
    """Purge all existing backups. Returns the count removed."""
    removed = 0
    for path in _find_targets(root):
        n = purge_backups(path, keep=keep)
        if n:
            removed += n
            print(f"purged {n} backup(s): {path}")
    return removed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument(
        "--dir", default="hunt-memory",
        help="Hunt memory directory to scan (default: hunt-memory)",
    )
    parser.add_argument(
        "--max-mb", type=float, default=DEFAULT_MAX_BYTES / (1024 * 1024),
        help="Rotate files above this size in megabytes (default: 10)",
    )
    parser.add_argument(
        "--keep", type=int, default=DEFAULT_KEEP,
        help=f"Backups to retain (default: {DEFAULT_KEEP})",
    )
    parser.add_argument("--rotate", action="store_true", help="Rotate oversize files")
    parser.add_argument("--purge-backups", action="store_true", help="Delete all backups")
    args = parser.parse_args(argv)

    root = Path(args.dir).resolve()
    max_bytes = int(args.max_mb * 1024 * 1024)

    print_banner(
        "Memory GC · Hunt-memory JSONL rotation",
        target=str(root),
        steps=[
            ("Inspect", f"scan {root.name}/ for files over the cap"),
            ("Rotate",  f"keep {args.keep} backups, cap {args.max_mb:.0f} MB"),
            ("Purge",   "drop old backups when --purge-backups is set"),
        ],
    )

    over = report(root, max_bytes, args.keep)
    print()

    if args.purge_backups:
        removed = do_purge(root, args.keep)
        print(f"\nPurged {removed} backup file(s).")

    if args.rotate:
        rotated = do_rotate(root, max_bytes, args.keep)
        print(f"\nRotated {rotated} file(s).")
    elif over and not args.purge_backups:
        print(f"{over} file(s) over cap. Re-run with --rotate to rotate them.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
