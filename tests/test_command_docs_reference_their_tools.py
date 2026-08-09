"""Regression guard: commands/scan-cves.md, cloud-recon.md, secrets-hunt.md,
and intel.md described their underlying tools/*.sh|py script only in prose
("the script", "learn.py" with no path) without ever stating the literal
file path or a runnable invocation -- unlike commands/param-discover.md/
takeover.md, which correctly name the tool explicitly. An LLM reading the
command doc had to infer the exact script name rather than being told
directly. This just checks the fix stays in place: each doc must contain
its tool's literal path string somewhere.
"""

from pathlib import Path

import pytest

COMMANDS_DIR = Path(__file__).resolve().parents[1] / "commands"

_EXPECTED_TOOL_REFS = {
    "scan-cves.md": "tools/cve_scan.sh",
    "cloud-recon.md": "tools/cloud_recon.sh",
    "secrets-hunt.md": "tools/secrets_hunter.sh",
    "intel.md": "tools/intel_engine.py",
}


@pytest.mark.parametrize("command_file,tool_ref", sorted(_EXPECTED_TOOL_REFS.items()))
def test_command_doc_names_its_tool_explicitly(command_file, tool_ref):
    text = (COMMANDS_DIR / command_file).read_text()
    assert tool_ref in text, (
        f"{command_file} never states {tool_ref} -- an agent reading this doc "
        f"has to guess the underlying script's exact path/name"
    )
