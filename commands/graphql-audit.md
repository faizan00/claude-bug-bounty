---
description: Full GraphQL security audit — introspection dump, graphw00f engine fingerprint, clairvoyance field-suggestion enumeration, batching DoS, alias bombing, gqlmap injection scan, graphql-cop checklist, depth-limit probe. Usage: /graphql-audit <endpoint-url>
---

# /graphql-audit

Run the full 8-phase GraphQL audit against a discovered `/graphql`,
`/api/graphql`, or GQL-over-HTTP endpoint.

## Usage

```
/graphql-audit https://target.com/graphql
/graphql-audit https://target.com/api/graphql --cookie "session=abc123"
/graphql-audit https://target.com/graphql --header "Authorization: Bearer TOKEN"
/graphql-audit https://target.com/graphql --proxy http://127.0.0.1:8080
```

## Scope

Requires `BB_SCOPE_DOMAINS` (e.g. `export BB_SCOPE_DOMAINS='*.target.com,target.com'`)
before running — the script refuses to probe with no declared scope. Run
`/scope <asset>` first if you haven't already.

## How it works

`tools/graphql_audit.sh` runs each phase in turn, falling back to built-in
curl probes when an optional tool isn't installed:

1. **Introspection** — full `__schema` dump when enabled.
2. **Fingerprint** (graphw00f) — engine identification; different engines
   carry different CVEs.
3. **Field discovery** (clairvoyance) — recovers schema via field-suggestion
   errors even when introspection is disabled.
4. **Batching DoS** — response-time delta for 1 vs. 100 queries in one POST.
5. **Alias bombing** — deeply aliased single-query amplification.
6. **Injection scan** (gqlmap) — SQLi/NoSQLi via string arguments.
7. **graphql-cop checklist** — standard auth-bypass/misconfig sweep.
8. **Depth-limit probe** — a depth-15 nested query; HTTP 200 with no depth/complexity rejection means the endpoint has no query-depth limiting (built-in, no external tool needed).

For the full manual methodology (IDOR-via-aliasing, field-level auth checks,
subscription abuse) beyond what the automated sweep covers, see
`skills/graphql-audit/SKILL.md` — load it explicitly for the deep-dive
checklist and bypass tables this command's automated pass doesn't replace.

## Output

`findings/<target>/graphql/<timestamp>/`:
- `introspection.json` — full schema dump (if enabled), or the raw disabled-response otherwise
- `fingerprint.txt` — engine type (graphw00f)
- `field_suggestions.json` — clairvoyance's own field-recovery output (a DIFFERENT signal from the `field_suggestions:` line in `summary.txt`, which is Phase 1's built-in "did you mean" hint check — no dedicated file of its own)
- `interesting_fields.txt` — introspected type/field names matching admin/internal/secret/token/password/role/debug/legacy/private/key/flag
- `batching_dos.txt` — response time delta for 1 vs 100 queries
- `alias_bomb.txt` — alias depth test results
- `gqlmap.txt` — injection scan results (or a built-in SQLi quick-probe result if gqlmap isn't installed)
- `cop_report.txt` — graphql-cop attack checklist results
- `depth_bomb.txt` — depth-15 query response + HTTP status/timing
- `summary.txt` — the one place every phase writes a clean ENABLED/DISABLED/HIT verdict — `director.py`'s `graphql_audit_leads()` reads THIS to decide what becomes a lead, not the raw per-phase files above (which are always non-empty regardless of outcome — curl always writes a response body)

## Before submitting

Route every hit through `/validate` — batching DoS and alias-bomb signals in
particular are frequently on programs' never-submit lists unless you can show
concrete resource-exhaustion impact, not just a response-time delta.
