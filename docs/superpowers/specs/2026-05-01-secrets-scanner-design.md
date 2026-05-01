# Secrets Scanner Design

## Overview

A Rust-powered, non-LLM secrets scanner that crawls the codebase and git history to detect sensitive data before it ships. Runs as a first-class scanner in the zentra scan pipeline (integrated into the TUI dashboard) and as a standalone tool (`zentra scan --only secrets`). LLM scanners can also invoke it as a tool (`scan_secrets`) to leverage its findings without re-implementing detection logic.

**Goal:** Give developers and the LLM a fast, deterministic eye for hardcoded secrets — using pattern matching, entropy analysis, and context-aware validation to minimize false positives.

---

## Architecture

### Module Layout

```
src/scanners/secrets/
├── mod.rs          ← pub struct SecretScanner, pub fn new(), pub async fn run()
├── engine.rs       ← orchestrates file + git crawl, deduplicates, produces Vec<SecretsMatch>
├── patterns.rs     ← ~50 compiled Regex patterns grouped by provider/type
├── entropy.rs      ← Shannon entropy scoring for base64, hex, alphanumeric strings
├── git_history.rs  ← git log -p streaming, scans added (+) lines only
├── validator.rs    ← ContextValidator: 6 suppression rules, false-positive reduction
├── allowlist.rs    ← .zentra/secrets-allowlist.toml loader, fingerprint/glob matching
└── report.rs       ← writes .zentra/secrets-report.md (scanner mode) or JSON (tool mode)
```

### Integration Points

| Location | Change |
|---|---|
| `src/agent/mod.rs` | Add `ScannerType::SecretsScan` variant |
| `src/agent/orchestrator.rs` | Special-case dispatch: call `SecretScanner::new(...).run()` instead of `ScannerAgent` |
| `src/tools/mod.rs` | Register `scan_secrets` tool returning capped JSON for LLM callers |
| `src/cli/mod.rs` | Add `--depth <N>` flag to `zentra scan` subcommand |
| `src/scanners/mod.rs` | Re-export `secrets` module |

---

## Core Data Types

```rust
pub struct SecretsMatch {
    pub file: String,
    pub line: u32,
    pub commit: Option<String>,   // None for working-tree hits
    pub detector: String,         // e.g. "aws_access_key", "high_entropy_base64"
    pub entropy: Option<f64>,
    pub redacted: String,         // e.g. "AKIA...XXXX" (last 4 visible)
    pub suppressed: bool,         // true if allowlist/annotation suppressed it
    pub suppression_reason: Option<String>,
}

pub enum HistoryDepth {
    Last(usize),   // --depth 50 (default)
    All,           // --depth all
}
```

---

## Detection

### Pattern Matching

~50 compiled Regex patterns organized by provider/category, loaded once at startup via `patterns.rs`. Coverage targets:

| Category | Examples |
|---|---|
| AWS | access key (`AKIA...`), secret key, session token |
| GitHub | classic PAT, fine-grained PAT, app token, OAuth token |
| GitLab | personal, project, group, deploy tokens |
| Stripe | live/test secret and publishable keys |
| Twilio | account SID + auth token |
| Slack | bot token, webhook URL |
| JWT | `eyJ...` three-part structure |
| Private keys | RSA/EC/DSA PEM headers, OpenSSH private key |
| `.env` literals | `PASSWORD=`, `SECRET=`, `API_KEY=`, `TOKEN=` with non-placeholder values |
| Connection strings | `postgres://user:pass@`, `mongodb+srv://`, JDBC strings with credentials |
| GCP | service account JSON key, API key |
| Azure | storage account key, SAS token, client secret |
| Generic high-risk | `PRIVATE_KEY`, `SECRET_KEY`, `AUTH_TOKEN`, `ACCESS_TOKEN` with values |

Each pattern captures the full match plus a named group `secret` for the sensitive portion (used for redaction).

### Entropy Analysis (`entropy.rs`)

Shannon entropy computed on candidate token extracted from each pattern match. Three token classes:

| Class | Alphabet | Min Length | Entropy Threshold |
|---|---|---|---|
| base64 | `A-Za-z0-9+/=` | 20 chars | > 4.5 bits |
| hex | `0-9a-fA-F` | 32 chars | > 3.0 bits |
| alphanumeric | `A-Za-z0-9` | 20 chars | > 3.5 bits |

High-entropy strings matching no named pattern are emitted as `high_entropy_<class>` detector hits. Entropy score is stored on `SecretsMatch` for all hits.

---

## Git History Crawler (`git_history.rs`)

Streams `git log -p --max-count=<N>` (or without `--max-count` for `HistoryDepth::All`) via `tokio::process::Command` with stdout piped. Processes line-by-line:

- Track current commit SHA from `commit <sha>` header lines.
- Track current file from `+++ b/<path>` diff header lines.
- Scan only `+` lines (additions) — deletions are not flagged.
- Apply the same pattern + entropy pipeline as the filesystem crawler.

Each hit gets `commit: Some(sha)` and the file path from the diff header.

**Default depth:** `--depth 50` (last 50 commits). Override with `--depth all` for full history. This guards against exhausting LLM API budget when used in the full scan pipeline.

---

## Context-Aware Validation (`validator.rs`)

`ContextValidator` applies 6 suppression rules in order. A match is suppressed if any rule fires:

1. **Test directory** — file path contains `/test`, `/tests`, `/spec`, `/mock`, or `__test__`.
2. **Placeholder value** — redacted value matches common placeholders: `your_`, `<`, `>`, `example`, `placeholder`, `xxx`, `yyy`, `dummy`, `fake`, `todo`, `changeme`, all repeated chars (e.g. `aaaa`).
3. **Inline annotation** — line or the preceding line contains `# zentra:ignore` or `// zentra:ignore`.
4. **Variable name only** — pattern matched but the extracted `secret` group is a variable name reference rather than a literal value (e.g. `token = my_token_var`).
5. **Allowlist fingerprint** — SHA-256 of `<file>:<line>:<redacted>` matches an entry in `.zentra/secrets-allowlist.toml`.
6. **Allowlist path glob** — file path matches a glob pattern from the allowlist.

Suppressed matches are still recorded in `SecretsMatch` with `suppressed: true` and the matching rule as `suppression_reason`. They appear in the report greyed out (not as active findings).

---

## Allowlist (`allowlist.rs`)

File: `.zentra/secrets-allowlist.toml`

```toml
[allowlist]
paths = [
    "tests/**",
    "fixtures/**",
]
fingerprints = [
    "a3f8c2...",    # sha256 of file:line:redacted
]

[[allowlist.entries]]
detector = "high_entropy_base64"
path = "src/test_vectors.rs"
```

Loaded once at scanner startup. Missing file is not an error (empty allowlist). Users add entries by running `zentra secrets allow <fingerprint>` (future command) or hand-editing.

---

## `.zentraignore` (Stub — Separate Plan)

A `.zentraignore` file at the repo root will be parsed to exclude paths from the full zentra scan pipeline (all scanners), similar to `.gitignore`. The secrets scanner will respect it when it exists, but its implementation is a separate, independent plan. The secrets scanner reads it via a shared `ignore_matcher` that returns early if a path matches.

---

## Dual-Mode Output

### Scanner Mode (standalone / pipeline)

Writes two artifacts to `.zentra/`:

**`secrets-report.md`** — human-readable findings:
```markdown
# Secrets Scan Report

## Active Findings (3)
| File | Line | Commit | Detector | Entropy | Redacted |
|------|------|--------|----------|---------|----------|
| src/config.rs | 42 | a3f8c2d | aws_access_key | 4.8 | AKIA...XXXX |
...

## Suppressed (12)
...
```

**`secrets-findings.json`** — structured findings array for machine consumption.

### Tool Mode (LLM invocation via `scan_secrets`)

Returns a JSON object capped at 50 active findings (never raw values):
```json
{
  "total_active": 3,
  "total_suppressed": 12,
  "findings": [
    { "file": "src/config.rs", "line": 42, "detector": "aws_access_key", "entropy": 4.8, "redacted": "AKIA...XXXX" }
  ]
}
```

Raw secret values are never returned to the LLM. Redacted form shows first 4 + `...` + last 4 chars of the sensitive group.

---

## CLI Integration

`zentra scan` gains a `--depth` flag:
```
--depth <N|all>    Git history depth for secrets scan [default: 50]
```

Used as `HistoryDepth::Last(N)` or `HistoryDepth::All`.

Standalone: `zentra scan --only secrets` runs the scanner and exits.
Pipeline: `SecretsScan` runs in the parallel phase (alongside SAST, SCA, API, IaC).

---

## TUI Integration

`SecretsScan` appears in the scan dashboard like other scanners. Since it is non-LLM, it emits `ScanEvent::ScannerStarted`, `ScanEvent::FindingEmitted` (per batch or per chunk), and `ScanEvent::ScannerCompleted` directly — no tool-call loop.

---

## Error Handling

- Git not available: skip history crawl, log warning, continue with filesystem scan.
- `.zentra/secrets-allowlist.toml` missing: treat as empty allowlist (not an error).
- Pattern compilation failure: panic at startup (not runtime) — patterns are static.
- IO errors reading files: skip file, emit warning to stderr.
- `git log` non-zero exit: skip history crawl, log warning.

---

## Testing Strategy

Unit tests per module:
- `patterns.rs` — each pattern matches known-good examples and rejects non-secrets.
- `entropy.rs` — known high/low entropy strings produce correct scores.
- `validator.rs` — each of the 6 suppression rules fires correctly in isolation.
- `allowlist.rs` — TOML parse, fingerprint match, glob match.
- `git_history.rs` — mock `git log -p` output produces correct `SecretsMatch` entries.
- `report.rs` — MD and JSON output format correctness.

Integration test: a temp git repo with planted secrets in working tree and history; `SecretScanner::new(...).run()` detects them with correct metadata.

---

## Out of Scope (This Plan)

- `zentra secrets allow <fingerprint>` command (CLI allowlist management)
- `.zentraignore` implementation (separate plan)
- LLM-augmented triage or remediation suggestions
- Secrets rotation or revocation integrations
