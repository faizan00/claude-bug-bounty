#!/usr/bin/env python3
"""
Secrets Scanner — Phase 5 Part C: pattern + entropy + JS-signal secret
detection over already-recovered source, no network I/O.

Problem this solves: tools/secrets_hunter.sh's --js-bundle mode only
scans a re-fetched copy of the raw minified bundle (a live network call)
with one fixed regex fallback. It never looks at Phase 1's
recon/<target>/browser/sources/ — browser_recon.py's already-recovered,
UNMINIFIED original TypeScript/JSX (see recover_source_maps_for_target()) —
which is far higher-signal (real variable names, real comments, real
internal URLs) than a minified bundle ever is.

This module adds three things, all pure/offline/deterministic:

  1. Vendor-specific PATTERN_SIGNATURES (AWS/GitHub/Slack/Stripe/Google/
     JWT/private-key/generic secret assignment) — the same kind of regex
     secrets_hunter.sh's fallback already uses, just organized so every hit
     is machine-labeled with a category.
  2. Shannon-entropy detection (find_high_entropy_strings()) for
     secret-shaped strings that match NO known vendor pattern — genuinely
     new capability, nothing in this repo computes entropy today (see
     "Entropy threshold rationale" below). A random high-entropy token is
     not proof of a secret, and this WILL false-positive on things like
     hashes, minified identifiers, and cache-busting query strings —
     labeled with method="entropy" precisely so a downstream consumer can
     tell it apart from a matched vendor pattern.
  3. JS-specific structural signals: internal/private API base URLs,
     feature-flag-shaped identifiers, GraphQL schema fragments, and —
     via directory-existence rather than a fragile text regex — confirmed
     exposed production source maps (see find_exposed_sourcemap_signal()).

EVIDENCE TYPING (not numeric confidence): every finding here carries an
`evidence_type` — a fixed provenance label from the shared vocabulary
(Observed-Runtime, Observed-HTTP-Response, Browser-Artifact, Static-JS,
Fingerprint, Historical-Memory, Human-Input, Validation-Confirmed), plus a
`method` field describing the detection mechanism (pattern/entropy/
heuristic/directory_evidence). Neither field is a number, and neither is
translated into a lead priority or score inside this module OR inside
tools/director.py's secret_scan_leads() adapter — priority_score() /
memory/attack_graph.py remain the only places a type/signal is ever turned
into a number. Every scan_* function here reads already-recovered static
JS source (recon/<target>/browser/sources/, Phase 1's output) or static
cicd_scanner.sh text output, so evidence_type="Static-JS" for every regex/
entropy-based finding; find_exposed_sourcemap_signal() is derived from
browser_recon.py's own recovered-bundle directory structure rather than a
text match, so it gets evidence_type="Browser-Artifact" instead.

Entropy threshold rationale (documented per Part C spec, not fabricated —
citation, not just prose): this follows the same two-charset convention
truffleHog's original high-entropy-string detector popularized (see
github.com/trufflesecurity/truffleHog's HEX_CHARS/BASE64_CHARS entropy
check) — a candidate token's charset determines which bound applies,
because a purely-hex string maxes out at 4 bits/char (16 symbols) while a
base64-ish string maxes out at 6 bits/char (64+ symbols):
  - hex-only candidates:            entropy >= HEX_ENTROPY_THRESHOLD (3.0)
  - broader alnum/symbol candidates: entropy >= B64_ENTROPY_THRESHOLD (4.5)
Candidates are also length-gated (>=20 chars, matching secrets_hunter.sh's
existing regex-fallback length bar) since short strings don't carry enough
signal for entropy to mean anything.

Pure library + thin CLI, JSON in/out, no input()/prompts, no network calls
anywhere in this file — every scan_* function reads files already on disk.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path

# ─── Evidence typing (not numeric confidence) ────────────────────────────
# Shared provenance vocabulary — see module docstring's EVIDENCE TYPING
# section. A fixed label describing WHERE/HOW evidence was observed, never
# a score; priority_score()/memory/attack_graph.py are the only places a
# type is ever turned into a number.
EVIDENCE_TYPE_STATIC_JS = "Static-JS"
EVIDENCE_TYPE_BROWSER_ARTIFACT = "Browser-Artifact"

# ─── Shannon entropy ─────────────────────────────────────────────────────


def shannon_entropy(s: str) -> float:
    """Bits of entropy per character. Empty string -> 0.0."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


HEX_ENTROPY_THRESHOLD = 3.0
B64_ENTROPY_THRESHOLD = 4.5
ENTROPY_MIN_LENGTH = 20
ENTROPY_MAX_LENGTH = 80
_HEX_CHARS = set("0123456789abcdefABCDEF")
# Candidate token shape: base64/hex/URL-safe-ish alphabets, the same rough
# shape secrets_hunter.sh's own regex fallback already targets.
_ENTROPY_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/_\-]{%d,%d}" % (ENTROPY_MIN_LENGTH, ENTROPY_MAX_LENGTH))


def find_high_entropy_strings(text: str) -> list[dict]:
    """Secret-shaped tokens with no vendor-pattern match, ranked by entropy.
    evidence_type=Static-JS, method="entropy" (see module docstring's
    EVIDENCE TYPING section for why this is a type label, not a confidence
    score). Never overlaps with a PATTERN_SIGNATURES hit on the same span
    (those are reported once, as method="pattern", not double-counted
    here)."""
    pattern_spans = [m.span() for _name, rx, _cat in PATTERN_SIGNATURES for m in rx.finditer(text)]

    def _overlaps_pattern(span: tuple[int, int]) -> bool:
        return any(span[0] < p[1] and span[1] > p[0] for p in pattern_spans)

    findings = []
    seen = set()
    for m in _ENTROPY_CANDIDATE_RE.finditer(text):
        token = m.group(0)
        if token in seen or _overlaps_pattern(m.span()):
            continue
        is_hex = all(c in _HEX_CHARS for c in token)
        threshold = HEX_ENTROPY_THRESHOLD if is_hex else B64_ENTROPY_THRESHOLD
        entropy = shannon_entropy(token)
        if entropy < threshold:
            continue
        seen.add(token)
        findings.append({
            "category": "high_entropy_string",
            "method": "entropy",
            "evidence_type": EVIDENCE_TYPE_STATIC_JS,
            "entropy": round(entropy, 2),
            "match": token,
        })
    return findings


# ─── Vendor-specific pattern signatures ─────────────────────────────────
# (name, compiled regex, category) — every hit here is evidence_type=
# Static-JS, method="pattern": these are specific enough that a match is
# real evidence, not a statistical guess (contrast with method="entropy").
# The last entry (generic_secret_assignment) is secrets_hunter.sh's own
# existing regex fallback, promoted here so it's covered by the same
# category/evidence-type labeling as everything else.

PATTERN_SIGNATURES: tuple[tuple[str, re.Pattern, str], ...] = (
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "cloud_credential"),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "vcs_credential"),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "chat_credential"),
    ("stripe_key", re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b"), "payment_credential"),
    ("google_api_key", re.compile(r"\bAIza[A-Za-z0-9_\-]{35}\b"), "cloud_credential"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "auth_token"),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----"), "private_key"),
    ("generic_secret_assignment",
     re.compile(r"(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|"
                r"client[_-]?secret|private[_-]?key|bearer)[\"'\s:=]+[a-zA-Z0-9_\-]{20,}", re.I),
     "generic_secret"),
)


def find_pattern_matches(text: str) -> list[dict]:
    findings = []
    for name, rx, category in PATTERN_SIGNATURES:
        for m in rx.finditer(text):
            findings.append({
                "category": category,
                "signature": name,
                "method": "pattern",
                "evidence_type": EVIDENCE_TYPE_STATIC_JS,
                "match": m.group(0)[:120],
            })
    return findings


# ─── JS-specific structural signals ─────────────────────────────────────

_PRIVATE_HOST_RE = re.compile(
    r"https?://(?:"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"localhost|127\.0\.0\.1|"
    r"[a-zA-Z0-9.\-]*\.(?:internal|corp|local|intranet|lan|svc\.cluster\.local)|"
    r"(?:internal|admin|staging|dev|private|backend)-api[.\-][a-zA-Z0-9.\-]+"
    r")\b[^\s\"'<>]*",
    re.I,
)


def find_internal_api_urls(text: str, target: str | None = None) -> list[dict]:
    """Private/internal-looking hostnames — RFC1918 IPs, .internal/.corp/
    .local/.svc.cluster.local suffixes, or an internal-api/admin-api/
    staging-api naming convention. `target` (the public domain being
    hunted) is excluded ONLY in the degenerate case where the matched host
    IS the bare public domain (or www.<domain>) — every regex branch here
    already requires an explicit internal marker to match at all, so an
    internal subdomain of the public target (e.g. admin-api.internal.
    target.com) is correctly still flagged, not swallowed by a broad
    substring exclusion."""
    findings = []
    for m in _PRIVATE_HOST_RE.finditer(text):
        url = m.group(0)
        host = re.sub(r"^https?://", "", url, flags=re.I).split("/")[0].lower()
        if target and host in (target.lower(), f"www.{target.lower()}"):
            continue
        findings.append({
            "category": "internal_api_url", "method": "heuristic",
            "evidence_type": EVIDENCE_TYPE_STATIC_JS, "match": url[:200],
        })
    return findings


_FEATURE_FLAG_RE = re.compile(
    r"(?:"
    r"[\"'](?:feature[_-]?flag|ff)[_-][a-zA-Z0-9_]+[\"']|"
    r"\bflags?\.[a-zA-Z_][a-zA-Z0-9_]*|"
    r"\.variation\(\s*[\"'][a-zA-Z0-9_\-]+[\"']|"
    r"\bisFeatureEnabled\(\s*[\"'][a-zA-Z0-9_\-]+[\"']|"
    r"\bunleash\.[a-zA-Z_][a-zA-Z0-9_]*"
    r")",
    re.I,
)


def find_feature_flags(text: str) -> list[dict]:
    """Client-side feature-flag identifiers (LaunchDarkly/Unleash-style
    .variation()/isFeatureEnabled() calls, flags.X references, literal
    feature-flag-shaped string keys) — an unlaunched or gated feature named
    here may be reachable by forcing the flag client-side."""
    return [
        {"category": "feature_flag", "method": "heuristic",
         "evidence_type": EVIDENCE_TYPE_STATIC_JS, "match": m.group(0)[:120]}
        for m in _FEATURE_FLAG_RE.finditer(text)
    ]


_GRAPHQL_FRAGMENT_RE = re.compile(
    r"(?:"
    r"\bfragment\s+\w+\s+on\s+\w+\s*\{|"
    r"\b(?:type|input|enum)\s+\w+\s*\{|"
    r"\b__typename\b|"
    r"\bmutation\s+\w+\s*\(|"
    r"\bquery\s+\w+\s*\("
    r")"
)


def find_graphql_fragments(text: str) -> list[dict]:
    """Inline GraphQL schema/query/mutation/fragment syntax embedded in a
    client bundle — confirms a GraphQL API and exposes real field/type
    names to test for IDOR/over-fetching, without needing introspection."""
    return [
        {"category": "graphql_fragment", "method": "heuristic",
         "evidence_type": EVIDENCE_TYPE_STATIC_JS, "match": m.group(0)[:120]}
        for m in _GRAPHQL_FRAGMENT_RE.finditer(text)
    ]


_RECOVERED_SOURCE_SUFFIXES = {".js", ".ts", ".jsx", ".tsx", ".mjs"}


def find_exposed_sourcemap_signal(sources_dir: Path) -> list[dict]:
    """Confirmed (not guessed) exposed-production-sourcemap signal: each
    top-level bundle subdirectory under recon/<target>/browser/sources/ is
    proof recover_source_maps_for_target() (Phase 1) successfully found AND
    fetched a live sourceMappingURL for that bundle — recovery cannot
    happen otherwise. Real ground truth, not a regex guess at bundle text
    this module never sees (the minified bundle itself isn't stored here,
    only its recovered originals) -> evidence_type="Browser-Artifact"
    (derived from browser_recon.py's own artifact directory structure, a
    categorically different provenance than a text-pattern match)."""
    if not sources_dir.is_dir():
        return []
    findings = []
    for bundle_dir in sorted(p for p in sources_dir.iterdir() if p.is_dir()):
        findings.append({
            "category": "exposed_sourcemap", "method": "directory_evidence",
            "evidence_type": EVIDENCE_TYPE_BROWSER_ARTIFACT,
            "match": f"production source map recovered for bundle '{bundle_dir.name}'",
            "bundle": bundle_dir.name,
            "file": str(bundle_dir),
        })
    return findings


# ─── Per-text / per-file / per-directory scanning ───────────────────────


def scan_text(text: str, file: str = "", target: str | None = None) -> list[dict]:
    """Runs every pattern/entropy/JS-signal detector over one blob of text.
    Every finding gets `file` attached; never raises on any input."""
    findings = (
        find_pattern_matches(text)
        + find_high_entropy_strings(text)
        + find_internal_api_urls(text, target=target)
        + find_feature_flags(text)
        + find_graphql_fragments(text)
    )
    for f in findings:
        f["file"] = file
    return findings


def _read_text_best_effort(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def scan_path(path: str, target: str | None = None,
              suffixes: set[str] | None = None) -> list[dict]:
    """Walk a single file or directory (recursively) and scan every file
    whose suffix is in `suffixes` (default: JS/TS source extensions, the
    exact set browser_recon.py's own sources/ walkers already use). Never
    raises — a single unreadable file is skipped, not fatal."""
    suffixes = suffixes or _RECOVERED_SOURCE_SUFFIXES
    p = Path(path)
    if not p.exists():
        return []

    files = [p] if p.is_file() else [f for f in p.rglob("*") if f.is_file() and f.suffix.lower() in suffixes]

    findings = []
    for f in files:
        text = _read_text_best_effort(f)
        if text is None:
            continue
        findings += scan_text(text, file=str(f), target=target)
    return findings


def scan_recon_sources(recon_dir: str, target: str | None = None) -> list[dict]:
    """Scan recon/<target>/browser/sources/ — Phase 1's recovered,
    unminified original source — the primary Part C data source."""
    sources_dir = Path(recon_dir) / "browser" / "sources"
    findings = scan_path(str(sources_dir), target=target)
    findings += find_exposed_sourcemap_signal(sources_dir)
    return findings


def scan_cicd_findings(recon_dir: str) -> list[dict]:
    """Scan recon/<target>/cicd/<org>/{scan_results.txt,summary.txt} —
    cicd_scanner.sh's sisakulint output — through the SAME pattern/entropy
    engine, not a second scanner. Closes the Part B gap: cicd_scanner.sh
    findings feed this pipeline instead of a separate lead type."""
    cicd_dir = Path(recon_dir) / "cicd"
    if not cicd_dir.is_dir():
        return []
    return scan_path(str(cicd_dir), suffixes={".txt"})


def scan_all(recon_dir: str, target: str | None = None) -> list[dict]:
    return scan_recon_sources(recon_dir, target=target) + scan_cicd_findings(recon_dir)


# ─── CLI ──────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Pattern + entropy + JS-signal secret scan over already-recovered recon output (no network I/O)"
    )
    parser.add_argument("--recon-dir", required=True, help="recon/<target> directory")
    parser.add_argument("--target", default=None, help="public domain, excluded from internal-URL findings")
    parser.add_argument("--skip-cicd", action="store_true", help="only scan browser/sources/, not cicd/ output")
    args = parser.parse_args(argv)

    findings = scan_recon_sources(args.recon_dir, target=args.target)
    if not args.skip_cicd:
        findings += scan_cicd_findings(args.recon_dir)

    print(json.dumps({"recon_dir": args.recon_dir, "count": len(findings), "findings": findings}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
