# Claude Bug Bounty — Plugin Guide

This repo is a Claude Code plugin for professional bug bounty hunting across HackerOne, Bugcrowd, Intigriti, and Immunefi.

## What's Here

### Skills (13 domains — load with `/bug-bounty`, `/web2-recon`, `/token-scan`, etc.)

| Skill | Domain |
|---|---|
| `skills/bug-bounty/` | Master workflow — recon to report, all vuln classes, LLM testing, chains |
| `skills/bb-methodology/` | **Hunting mindset + 5-phase non-linear workflow + tool routing + session discipline** |
| `skills/web2-recon/` | Subdomain enum, live host discovery, URL crawling, nuclei |
| `skills/web2-vuln-classes/` | 21 bug classes with bypass tables (SSRF, open redirect, file upload, Agentic AI) |
| `skills/security-arsenal/` | Payloads, bypass tables, gf patterns, always-rejected list |
| `skills/web3-audit/` | 10 smart contract bug classes, Foundry PoC template, pre-dive kill signals |
| `skills/meme-coin-audit/` | Meme coin rug pull detection, token authority checks, bonding curve exploits, LP attacks |
| `skills/report-writing/` | H1/Bugcrowd/Intigriti/Immunefi report templates, CVSS 3.1, human tone |
| `skills/triage-validation/` | 7-Question Gate, 4 gates, never-submit list, conditionally valid table |
| `skills/credential-attack/` | Password spray methodology — when/why, 4-stage pipeline, mode selection, lockout tactics, legal guardrails, pitfalls learned from live tests |
| `skills/mobile-pentest/` | Android/iOS app pentest — runtime-first proxy workflow, APK/IPA decompile for hidden endpoints + secrets, deeplink/exported-activity injection, WebView bridge, SSL pinning bypass |
| `skills/cicd-security/` | CI/CD pipeline hunting — GitHub Actions injection, secret exfil, self-hosted runner poisoning, OIDC abuse, supply chain attacks |
| `skills/graphql-audit/` | GraphQL hunting — introspection, field suggestions (clairvoyance), batching DoS, IDOR via aliasing, injection, auth bypass, depth bombs |

### Commands (28 slash commands)

> **Note:** All commands are prefixed to avoid conflicts with Claude Code's built-in commands.
> `/resume` is a reserved Claude Code command — use `/pickup` to continue a previous hunt.

| Command | Usage |
|---|---|
| `/recon` | `/recon target.com` — full recon pipeline |
| `/hunt` | `/hunt target.com` — start hunting |
| `/validate` | `/validate` — run 7-Question Gate on current finding |
| `/report` | `/report` — write submission-ready report |
| `/chain` | `/chain` — build A→B→C exploit chain |
| `/scope` | `/scope <asset>` — verify asset is in scope |
| `/scope-aggregate` | `/scope-aggregate <program>` — pull every in-scope asset across H1/Bugcrowd/Intigriti/YWH/Immunefi |
| `/triage` | `/triage` — quick 7-Question Gate |
| `/web3-audit` | `/web3-audit <contract.sol>` — smart contract audit |
| `/autopilot` | `/autopilot target.com --normal` — autonomous hunt loop |
| `/surface` | `/surface target.com` — ranked attack surface |
| `/pickup` | `/pickup target.com` — pick up previous hunt (was `/resume`) |
| `/remember` | `/remember` — log finding to hunt memory |
| `/intel` | `/intel target.com` — fetch CVE + disclosure intel |
| `/token-scan` | `/token-scan <contract>` — meme coin/token rug pull scanner |
| `/memory-gc` | `/memory-gc [--rotate|--purge-backups]` — inspect/rotate hunt-memory JSONL files (10MB cap, 3 backups) |
| `/secrets-hunt` | `/secrets-hunt --js-bundle <recon-dir>` — leaked-credential scan (trufflehog/noseyparker/gitleaks) |
| `/takeover` | `/takeover --recon <recon-dir>` — subdomain takeover candidates (dnsReaper/subjack) |
| `/cloud-recon` | `/cloud-recon --keyword <name>` — public S3/Azure/GCP + CloudFlare-bypass origin IPs |
| `/param-discover` | `/param-discover <url>` — find hidden HTTP parameters (Arjun/x8) |
| `/bypass-403` | `/bypass-403 <url>` — try header/method/encoding tricks against a 403/401 |
| `/arsenal` | `/arsenal [tool]` — list installed external tools or get an install hint |
| `/scan-cves` | `/scan-cves <host>` — focused nuclei CVE sweep (high/critical) + optional log4j-scan |
| `/wordlist-gen` | `/wordlist-gen <target>` — company-specific password wordlist (cewler + hashcat); requires `--with-credential-attack` |
| `/osint-employees` | `/osint-employees <target>` — employee names + emails (theHarvester + username-anarchy, opt-in LinkedIn); requires `--with-credential-attack` |
| `/breach-check` | `/breach-check <wordlist>` — HIBP k-anonymity rank wordlist by real-world breach count |
| `/spray` | `/spray <url> --mode http-form\|oauth\|o365\|okta --users <f> --passes <f>` — password spray with hard guards (typed-host confirm, lockout warn, audit log) |
| `/graphql-audit` | `/graphql-audit <url>` — full GraphQL audit: introspection, batching DoS, IDOR, injection, alias bomb, graphw00f fingerprint |

### Agents (14 specialized agents)

- `recon-agent` — subdomain enum + live host discovery
- `js-intelligence` — mines JS bundles/source maps for hidden endpoints, feature flags, debug routes, leaked config, auth flows
- `vulnerability-intelligence` — builds the memory-driven intelligence briefing (tech→vuln affinity, known chains, don't-retry list) before ranking; writes learned failed-patterns/chains back after a hunt
- `hypothesis-engine` — synthesizes recon + JS intel + memory + the attack graph into ranked, evidence-backed vulnerability hypotheses before any testing starts
- `report-writer` — generates H1/Bugcrowd/Immunefi reports; validates exploitability/impact/evidence first and checks report-outcome acceptance history
- `validation-engine` — technical proof gate before `validator`: reproducibility, proven impact, authorization boundary crossed, clean PoC, duplicate/noise against hunt memory
- `validator` — 4-gate checklist on a finding
- `web3-auditor` — smart contract bug class analysis
- `chain-builder` — builds A→B→C exploit chains, memory-first (chains.jsonl + lead-board graph before the static table), saves every chain it confirms
- `autopilot` — autonomous hunt loop (scope→recon→rank→hunt→validate→report), decision-engine-driven priority scoring, experiment-tracked stop/pivot decisions
- `research-director` — wraps `tools/director.py`'s dependency-aware, falsifier-generating, time-boxed planner; drives `/autopilot`'s Decision (Step 5) and Experiment Selection (Step 6) via `build_plan()`/`replan()` instead of ad hoc re-scoring
- `recon-ranker` — scored, confidence-rated attack surface ranking from recon output + hypotheses + the intelligence briefing + lead-board chains, plus Expected Value per Hour per candidate
- `token-auditor` — fast meme coin/token rug pull and security analysis
- `credential-hunter` — orchestrates wordlist-gen + osint-employees + breach-check; HARD STOPS at spray for human go/no-go

### Rules (always active)

- `rules/hunting.md` — 17 critical hunting rules
- `rules/reporting.md` — report quality rules

### Tools (Python/shell — in `tools/`)

- `tools/hunt.py` — master orchestrator
- `tools/recon_engine.sh` — subdomain + URL discovery (now with optional `nuclei` phase); `BB_BROWSER_RECON=1` opts into Phase 2.5, which runs `browser_recon.py` (source maps, framework routes, client-side auth model, hidden endpoints) against Phase 2's live hosts — off by default since it drives a real headless browser. `browser_recon.py --api-capture` now also feeds `memory/api_call_observer.py`, so running it once per test account (`--bearer`/`--cookie`) accumulates cross-account API calls in `browser/api-calls.json` and records real Object Model observations for `director.py`'s authorization-violation detector — previously built and tested but never wired to any producer. Phase 2.6 always runs `fingerprint.py` (local-file analysis only, no new network calls) — see below. Phase 5.5 always runs `incremental_recon.py` — see below — closing the "discover a new host mid-run, actually probe it before this run ends" gap the other 10 phases never had (a linear one-shot pipeline until this).
- `tools/fingerprint.py` — framework/infra/API-style/SPA detection + CVE matching against `tools/tech_attack_matrix.json`, writing `recon/<target>/fingerprint.json` and syncing `tech_stack` into `hunt-memory/targets/<target>.json` (the one place `director.py`'s `load_tech_stack()` reads). Now called automatically by `recon_engine.sh`'s Phase 2.6 — previously had zero callers anywhere, so `director.py`'s tech-stack-aware scoring and CVE matching (`load_fingerprint_tech_attack_matrix()`, gated on `fingerprint.json`'s presence) silently got nothing on every real hunt. `--live-cve-lookup` (real network call to GitHub Advisory DB/NVD via `learn.py`) stays opt-in, off by default. Each `cves[]` hit now also carries `vuln_class`/`citation` (previously computed then dropped) so `director.py`'s `fingerprint_cve_leads()` can turn a version-CONFIRMED CVE match (a real `version_in_range()` comparison against the target's actual fingerprinted version, not a heuristic) directly into a scored `hunt-*` lead — the framework-aware signal that used to dead-end at a version-blind `technology_match` score nudge and nothing else.
- `tools/incremental_recon.py` — the "DISCOVER NEW INFORMATION -> RECON AGAIN" step `recon_engine.sh`'s 10 phases never had (they're strictly linear/one-shot; a host first referenced by Phase 4's URL collection or Phase 2.5's real captured browser API calls never got probed by anything). Finds hosts newly referenced in `urls/all.txt` (real crawled/historical URLs) or `browser/api-calls.json` (real browser-observed requests, when Phase 2.5 ran) that aren't already in `subdomains/all.txt`, probes each *exact observed* scheme+host+port once (never assumes default ports — a discovery on `:8443` re-probed on the assumed-default `:443` would silently miss it), and merges the live ones back into `subdomains/all.txt` + `live/urls.txt` — so a host discovered mid-run becomes a first-class citizen of every later phase in the SAME run (verified end-to-end: a newly merged host gets picked up by Phase 6's directory fuzzing before the pipeline finishes). Now called automatically by `recon_engine.sh`'s Phase 5.5, same fail-closed scope gate as Phase 2.5.
- `tools/vuln_scanner.sh` — XSS/SQLi/SSTI/MFA/SAML probe pipeline
- `tools/idor_diff.py` — generic cross-session IDOR/BOLA diff tester for arbitrary targets (GET-only, scope-gated via `browser_recon.py`'s `Fetcher` — the same shared choke point `business_logic_probe.py`/`incremental_recon.py` reuse, now with a real, code-enforced `max_wall_clock_seconds` budget (600s default) in addition to its existing `max_requests` cap; a slow/hanging target burning the full per-request timeout on every request could previously run indefinitely since `max_requests` alone bounds request COUNT, not elapsed TIME); requires two `AuthSession` files (Account A/B) and `--i-understand`; `--auto` pulls object-scoped candidate URLs from recon output; a genuine match feeds a `hunt-idor` lead and, with `--owner a|b` (a real hunter-asserted ownership fact, never inferred), a `memory/object_model.py` relationship-establishing Observation — the first live producer its `detect_relationship_violations()` detector has ever had. See `skills/web2-vuln-classes/SKILL.md` §1.
- `tools/business_logic_probe.py` — mutation-gated producer for `memory/object_model.py`'s business-logic pattern detector (`rules/logic_patterns.yaml`: invite_flow/ownership_transfer/tenant_isolation/billing/refund/coupon/role_escalation). Two-step: `--establish` records a real hunter-asserted relationship fact (e.g. "this session holds CAN_INVITE on org 42"), `--probe` fires ONE real request (GET for tenant_isolation, mutating otherwise) as the session being tested and checks the result synchronously against the real `detect_logic_pattern_violations()` — the first live producer any of these 7 patterns has had since Phase 6, since every one is gated shut with zero relationship evidence otherwise. Mutating patterns require both `--i-understand` and `browser_recon.py` Fetcher's own `--allow-mutate`. Every `--establish`/`--probe` call also automatically writes a `memory/object_model.py` Phase 6 Part 3 stateful-session checkpoint (`hunt-memory/object_model/checkpoints/<target>__<pattern>.json`) — the first live producer that mechanism has had either; `/pickup` reads it back to show where an interrupted multi-step business-logic test left off. See `skills/web2-vuln-classes/SKILL.md` §5.
- `tools/validate.py` — 4-gate finding validator
- `tools/learn.py` — CVE + disclosure intel; `fetch_and_cache_cve()` (Phase 5) populates `tools/tech_attack_matrix_live_cache.json` with real fetched CVEs, called only via `fingerprint.py`'s opt-in `--live-cve-lookup` flag (new network call, default OFF)
- `tools/intel_engine.py` — on-demand intel with memory context. `--program <handle>` now also pulls `mcp/hackerone-mcp/server.py`'s `get_program_policy()` (structured scope + per-asset bounty eligibility, straight from HackerOne's public GraphQL API) — real, tested, but never actually called from anywhere until now, despite `commands/intel.md`'s own docs already claiming "Program stats, policy" was available. Surfaced in its own `PROGRAM:` output section, not buried in the generic info-count `get_program_stats()`'s entry was previously invisible inside.
- `tools/scope_checker.py` — deterministic scope safety checker
- `tools/scope_aggregator.sh` — multi-platform scope pull (bbscope + bounty-targets-data)
- `tools/secrets_hunter.sh` — trufflehog/noseyparker/gitleaks wrapper for FS/git/JS/GH-org; `--recon-sources` mode runs `secrets_scanner.py` against Phase 1's recovered sources + cicd_scanner.sh output, no network I/O
- `tools/secrets_scanner.py` — pattern + Shannon-entropy + JS-signal (internal API URLs, feature flags, GraphQL fragments, exposed sourcemaps) secret scanner over `recon/<target>/browser/sources/` and `recon/<target>/cicd/`
- `tools/takeover_scanner.sh` — dnsReaper/subjack subdomain-takeover scanner. `director.py`'s `takeover_leads()` parses subjack's REAL output format (verified against its upstream Go source) — it logs `"[Not Vulnerable] <url>"` for every scanned-but-clean host, not just hits, so treating any non-empty line as a takeover lead (the previous behavior) fabricated a P_HIGH lead for every clean host. dnsReaper's own CONFIRMED/POTENTIAL/UNLIKELY confidence field now maps to priority instead of flattening every hit to P_HIGH.
- `tools/cloud_recon.sh` — S3Scanner + cloud_enum + CloudFail wrapper. `director.py`'s `cloud_recon_leads()` now checks each tool's REAL output format (verified against upstream source) instead of a loose substring match: s3scanner's own text output says "exists" for any existing bucket regardless of public/private (the real signal is a non-empty `AllUsers:[...]`/`AuthUsers:[...]` permission grant), cloud_enum logs "Protected"/"Auth-Only"/"Disabled" results too (not just public ones), and CloudFail's actual markers (`[FOUND:HOST]` etc.) never matched the previous regex at all — a false NEGATIVE that silently sent zero leads to the board on every run.
- `tools/param_discovery.sh` — Arjun/x8 hidden-parameter discovery, writing `findings/params/<timestamp>/{arjun.json,x8.txt}`. `director.py`'s `param_discovery_leads()` (opt-in `--param-findings-dir`, same "standalone tool, timestamped external findings dir" convention as takeover/cloud/graphql below) routes each diff-confirmed param NAME through `lead_board.py`'s new `"param"` ROUTES source — previously a dead end nothing downstream ever read.
- `tools/bypass_403.sh` — byp4xx + built-in 403/401 bypass matrix
- `tools/cve_scan.sh` — focused nuclei CVE-tag sweep + optional log4j-scan
- `tools/external_arsenal.sh` — installed-tool registry (~50 tools); other scripts source this for `_have <tool>`
- `tools/cicd_scanner.sh` — GitHub Actions workflow scanner (sisakulint wrapper, remote scan)
- `tools/token_scanner.py` — automated token red flag scanner (EVM + Solana)
- `tools/wordlist_engine.sh` — company-specific password wordlist generator (cewler + hashcat rules); requires `--with-credential-attack`
- `tools/osint_employees.sh` — employee names + email patterns for spray prep (theHarvester + username-anarchy, opt-in CrossLinked); requires `--with-credential-attack`
- `tools/breach_checker.py` — HIBP k-anonymity wordlist enrichment; ranks passwords by breach count (no API key, free)
- `tools/spray_orchestrator.sh` — password spray with typed-hostname guard + lockout warning + audit log; modes: http-form / oauth / o365 / okta (TREVOR); requires `--with-credential-attack` for TREVOR modes
- `tools/graphql_audit.sh` — 8-phase GraphQL audit: introspection + schema dump, graphw00f fingerprint, clairvoyance field discovery, batching DoS, alias bomb, gqlmap injection, graphql-cop checklist, depth-limit probe. `director.py`'s `graphql_audit_leads()` now reads the script's own `summary.txt` ENABLED/DISABLED/HIT verdicts instead of "is the raw per-phase file non-empty" — verified by reading the script line by line that curl always writes an HTTP response body (and a not-installed placeholder is also non-empty text) regardless of outcome, so the old check had been fabricating P_HIGH "confirmed" leads (batching DoS, alias bomb, introspection enabled, ...) on essentially every successful run. Also newly wired: the depth-limit probe (previously had zero lead-board coverage under any name) and the `field_suggestions:` "did you mean" hint check (previously conflated with the differently-named `field_suggestions.json`, which is actually clairvoyance's own, unrelated output file).
- `tools/lead_board.py` — persistent per-target lead ledger that routes every recon observation to the right `hunt-*` skill and tracks its status so no lead is forgotten (`memory/leads/<target>.jsonl`). `ingest` parses recon output and routes 30+ signal types (IDOR/SSRF/GraphQL/OAuth/SAML/LLM/source-leak/tech-stack/nuclei) to skills, then runs 2-signal chain detection and 3-signal same-host hypothesis detection (`account_takeover_via_leaked_secret`, etc.) automatically; `show` lists untouched-first, surfaces detected chains/hypotheses, and flags stale high-priority leads; `next` returns the single top lead; `touch` marks a lead investigating/killed/reported (re-ingest preserves status; `--status reported` warns to stderr if the target has no `memory/finding_state.py` transition on record that ever reached CONFIRMED/SELF_CRITIQUED/REPORT_READY — advisory, not a hard block, since a lead and a finding aren't keyed the same way); `graph` renders the Asset→Endpoint→Technology→Vulnerability Hypothesis→Impact attack surface graph. See **Critical Rule 6**.

### External tool references

- `wordlists/REFERENCES.md` — pointers to SecLists / OneListForAll / fuzz4bounty / PayloadsAllTheThings
- `skills/security-arsenal/REFERENCES.md` — methodology, writeup archives, dorks, key-verification, AI-security skill repos
- `skills/security-arsenal/METHODOLOGY_CHEATSHEET.md` — per-vuln quick-check tables distilled from HowToHunt + HolyTips + AllAboutBugBounty + KingOfBugBountyTips

### MCP Integrations (in `mcp/`)

- `mcp/burp-mcp-client/` — Burp Suite proxy integration
- `mcp/hackerone-mcp/` — HackerOne public API (Hacktivity, program stats, policy)

### Hunt Memory (in `memory/`)

- `memory/pattern_db.py` — cross-target pattern learning
- `memory/vuln_intelligence.py` — failed-pattern + confirmed-chain + report-outcome + hypothesis memory, tech→vuln affinity, endpoint-shape scoring (`normalize_endpoint()`/`endpoint_shape_stats()` — cross-target win/loss history for a URL's *shape*, e.g. `/api/v2/users/{id}/orders`), the `priority_score()` decision-engine formula (self-learning: its `impact_potential` prior bounded-blends toward observed `report_outcomes.jsonl` acceptance rate once 5+ samples exist per vuln_class; also applies `endpoint_shape_stats()`'s losing-track-record penalty when called with `endpoint=`/`--endpoint`, so `director.py build-plan` — which always passes a lead's evidence as `endpoint` — gets this signal automatically, not just the `recon-ranker` agent's hand-applied version), `expected_value_per_hour()` (score × payout probability × time cost), `duplicate_or_noise_check()`, and `hypothesis_calibration()` (does stated confidence match actual outcomes) (CLI: `python3 -m memory.vuln_intelligence <cmd>`)
- `memory/experiment_memory.py` — granular per-payload-attempt log (`experiments.jsonl`) beneath patterns/failed_patterns; `payload_category_affinity()`, `should_stop()` (5-min-rule + diminishing-returns), `suggest_pivot()` (CLI: `python3 -m memory.experiment_memory <cmd>`)
- `memory/audit_log.py` — request audit log, rate limiter, circuit breaker
- `memory/rotation.py` — size-based JSONL rotation (10MB cap, keep 3 backups), auto-fired on append
- `memory/schemas.py` — schema validation for all data

## Start Here

```bash
claude
# /recon target.com
# /hunt target.com
# /validate   (after finding something)
# /report     (after validation passes)
```

## Install Skills

```bash
chmod +x install.sh && ./install.sh
```

## Critical Rules (Always Active)

1. READ FULL SCOPE before touching any asset
2. NEVER hunt theoretical bugs — "Can attacker do this RIGHT NOW?"
3. Run 7-Question Gate BEFORE writing any report
4. KILL weak findings fast — N/A hurts your validity ratio
5. 5-minute rule — nothing after 5 min = move on
6. **LEAD BOARD — never lose a lead.** After recon, run `lead_board.py ingest <target>` + `show`, and route each finding to its `hunt-*` skill in plain language ("GraphQL endpoint → hunt-graphql"). When starting/killing/reporting a lead, `touch` its status. The hunter focuses on one lead at a time; the board remembers the rest so none is forgotten. Surface stale high-priority leads unprompted.
