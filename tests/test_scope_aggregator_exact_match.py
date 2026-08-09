"""
Regression test for tools/scope_aggregator.sh's program-handle matching.

Guards a scope-bypass found during the post-Phase-7 hardening audit:
_extract_dump() matched programs via unanchored Python substring
containment (`program not in handle and program not in url`), so asking
for program "acme" would also match a completely different program named
"acme-labs" or "notacme-corp" and merge ITS scope into the output file.
That file then feeds tools/recon_engine.sh in list-mode, which treats it
as pre-vetted and skips scope_checker.py entirely -- no safety net against
actively probing the wrong org.

No network calls: a bounty-targets-data cache file is pre-seeded locally
so _fetch_dump() finds it fresh and never invokes curl.
"""

import json
import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCOPE_AGGREGATOR = REPO_ROOT / "tools" / "scope_aggregator.sh"

FIXTURE_DUMP = [
    {
        "handle": "acme",
        "url": "https://hackerone.com/acme",
        "targets": {"in_scope": [{"asset_identifier": "*.acme.com", "asset_type": "wildcard"}]},
    },
    {
        "handle": "acme-labs",
        "url": "https://hackerone.com/acme-labs",
        "targets": {"in_scope": [{"asset_identifier": "*.acme-labs-unrelated.com", "asset_type": "wildcard"}]},
    },
    {
        "handle": "notacme-corp",
        "url": "https://hackerone.com/notacme-corp",
        "targets": {"in_scope": [{"asset_identifier": "*.totally-different-company.com", "asset_type": "wildcard"}]},
    },
]


def _run(program, cache_dir, out_file, env_extra=None):
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / "hackerone.json").write_text(json.dumps(FIXTURE_DUMP))

    env = dict(os.environ)
    # No bbscope on PATH in this sandbox already; force the dump fallback
    # path explicitly and keep curl unreachable as belt-and-suspenders.
    env["HTTP_PROXY"] = "http://127.0.0.1:1"
    env["HTTPS_PROXY"] = "http://127.0.0.1:1"
    env["BBHUNT_CACHE_DIR"] = str(cache_dir)
    if env_extra:
        env.update(env_extra)

    return subprocess.run(
        ["bash", str(SCOPE_AGGREGATOR), program, "--platform", "h1", "--out", str(out_file)],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=30, env=env,
    )


def test_exact_handle_match_only_pulls_that_programs_scope(tmp_path):
    out_file = tmp_path / "acme.scope.txt"
    proc = _run("acme", tmp_path / "cache", out_file)
    assert proc.returncode == 0, f"stdout={proc.stdout}\nstderr={proc.stderr}"

    scope = out_file.read_text()
    assert "acme.com" in scope
    assert "acme-labs-unrelated.com" not in scope, (
        "matching 'acme' against handle 'acme-labs' via substring containment "
        "would incorrectly merge a different program's scope in"
    )
    assert "totally-different-company.com" not in scope


def test_substring_of_another_handle_does_not_match(tmp_path):
    # "acme-lab" is a substring of "acme-labs" but is not itself a real
    # handle in the fixture -- exact match must reject it entirely rather
    # than fuzzy-matching to the closest handle.
    out_file = tmp_path / "notfound.scope.txt"
    proc = _run("acme-lab", tmp_path / "cache", out_file)
    assert proc.returncode != 0
    assert not out_file.exists() or out_file.read_text().strip() == ""
