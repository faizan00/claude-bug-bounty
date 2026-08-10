"""Regression guard: every literal ``tools/<name>.py|sh`` path referenced in
agent/command/skill docs must actually exist on disk.

Found via a fresh audit: ``install_tools.sh`` lives at the REPO ROOT, not
under ``tools/`` -- but ``tools/hunt.py``, ``commands/hunt.md``, and
``commands/recon.md`` all told the reader to run ``bash tools/install_tools.sh``
(wrong path, fails with "No such file or directory"). This test makes that
whole class of bug mechanically impossible to reintroduce silently: scans
every doc/prose file this repo actually reads at runtime for a
``tools/name.py``/``tools/name.sh`` reference and fails if the referenced
file doesn't exist.
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

_TOOL_PATH_RE = re.compile(r"tools/[a-zA-Z0-9_]+\.(?:py|sh)")

# Same scope this bug was actually found in -- prose files an agent or
# hunter reads and might literally copy-paste a command from.
_SCAN_GLOBS = (
    "agents/*.md",
    "commands/*.md",
    "skills/**/*.md",
    "CLAUDE.md",
    "AGENTS.md",
    "OPENCODE.md",
    "README.md",
)


def _referenced_tool_paths() -> dict[str, list[str]]:
    """Map each unique referenced tools/*.py|sh path -> files that reference it."""
    refs: dict[str, list[str]] = {}
    for pattern in _SCAN_GLOBS:
        for path in REPO_ROOT.glob(pattern):
            text = path.read_text(encoding="utf-8", errors="replace")
            for match in _TOOL_PATH_RE.findall(text):
                refs.setdefault(match, []).append(str(path.relative_to(REPO_ROOT)))
    return refs


def test_every_referenced_tool_path_exists_on_disk():
    refs = _referenced_tool_paths()
    missing = {
        tool_path: files
        for tool_path, files in refs.items()
        if not (REPO_ROOT / tool_path).is_file()
    }
    assert not missing, (
        "Doc(s) reference a tools/*.py|sh path that doesn't exist on disk "
        "-- copy-pasting the documented command would fail with "
        f"'No such file or directory': {missing}"
    )


def test_scan_actually_finds_references():
    # Guards the guard: if the globs ever stop matching anything (e.g. a
    # directory rename), the test above would trivially pass on an empty
    # set and silently stop checking anything.
    refs = _referenced_tool_paths()
    assert len(refs) > 20, (
        f"Expected 20+ distinct tools/*.py|sh references across the repo's docs, "
        f"found {len(refs)} -- the scan glob may no longer be matching real files"
    )
