---
description: Discover hidden HTTP parameters on a URL or list of URLs using Arjun (or x8 fallback). Hidden params are gold for IDOR, SSRF, LFI, redirect, and authorization bypass — often missed by automated scanners. Usage: /param-discover <url> | /param-discover -l <urls-file>
---

# /param-discover

Find HTTP parameters the application accepts but doesn't link from any visible
endpoint. Useful when an endpoint looks unreachable or returns a generic
response — often a hidden `id`, `user`, `redirect`, `file`, or `debug` param
unlocks the real surface.

## Usage

```
/param-discover https://api.target.com/v2/user
/param-discover -l recon/target.com/live/urls.txt
```

## Scope

Requires `BB_SCOPE_DOMAINS` (e.g. `export BB_SCOPE_DOMAINS='*.target.com,target.com'`)
before running — the script refuses to probe with no declared scope. Run
`/scope <asset>` first if you haven't already.

## Tools

`tools/param_discovery.sh` prefers `arjun` (richer JSON output, ML-driven diffing) and
falls back to `x8` (Rust, faster on huge wordlists). Install hint:

```
pipx install arjun
# or
cargo install x8
```

## Why it pays

- Hidden `redirect=` / `next=` → open redirect, SSRF, OAuth code theft chain.
- Hidden `id=` / `user_id=` → IDOR.
- Hidden `file=` / `path=` / `template=` → LFI, SSTI, RFI.
- Hidden `debug=` / `admin=` → privilege escalation toggles.
- Hidden `callback=` / `jsonp=` → reflected XSS via JSONP.

After discovery, feed the URL+param into `/hunt --vuln-class <best-fit>` for
targeted testing.

## Output

`findings/params/<timestamp>/`:
- `arjun.json` / `arjun_summary.txt` — endpoint → discovered params
- `x8.txt` — diff-based hits when arjun is unavailable

## Feeding the Lead Board / Decision Engine

A raw `findings/params/<timestamp>/` directory isn't picked up by anything
automatically — same convention as `/takeover`, `/cloud-recon`, `/graphql-audit`
(all standalone, timestamped output). Point `director.py build-plan` at it:

```bash
python3 tools/director.py build-plan target.com --hours 4 \
  --param-findings-dir findings/params/<timestamp> --write
```

Each diff-confirmed param name routes through `lead_board.py`'s `"param"`
ROUTES source (bare-name match — `user_id`→`hunt-idor`, `callback`→`hunt-ssrf`,
`is_admin`→`hunt-auth-bypass`, etc.) into a real, scored lead, and composes
with existing chain/hypothesis detection (e.g. a leaked secret + a hidden
IDOR param on the same host still trips the `secret_plus_api` chain).
