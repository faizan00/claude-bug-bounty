"""
Atomic whole-file JSON/text writes for state that must survive a crash.

Distinct concern from memory/rotation.py (which bounds an APPEND-ONLY
log's SIZE via backup rotation): this module is about making a single
REPLACE-the-whole-file write crash-safe, regardless of size.

tools/lead_board.py's save_ledger() established this exact discipline
(fixed in this repo's PR #20) after a real bug: a plain path.write_text()
truncates the destination before writing a single byte of the
replacement -- a crash (SIGKILL, OOM-kill, power loss) mid-write loses
whatever was there before, not just the in-flight change. That fix was
never extracted into a shared helper, so it protected ONLY the lead
board -- every other JSON state file this codebase read-modify-writes
across multiple runs (tools/director.py's hunt-plan.json,
memory/object_model.py's business-logic checkpoints,
tools/fingerprint.py's per-target profile and CVE cache,
tools/browser_recon.py's cross-account api-calls.json) used a plain,
non-atomic write instead, until this module existed to fix that in one
place.
"""

import contextlib
import os
import tempfile
from pathlib import Path


def atomic_write_text(path: str | Path, content: str, encoding: str = "utf-8") -> None:
    """Write ``content`` to ``path`` atomically: build the full content in
    a same-directory temp file, fsync it, then os.replace() into place.
    os.replace() is atomic on POSIX -- a concurrent reader (including a
    process that crashed and is being resumed by another) always sees
    either the complete old file or the complete new one, never a
    truncated/partial one.

    Creates parent directories if needed, same convention every caller
    of this function already had inline before switching to it.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}-", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding=encoding) as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, str(path))
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise
