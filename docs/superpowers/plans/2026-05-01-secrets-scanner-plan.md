# Secrets Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a non-LLM secrets scanner to zentra-cli that crawls the codebase and git history using pattern matching and entropy analysis, runs as a first-class scanner in the TUI pipeline, and is also callable as a tool by LLM scanners.

**Architecture:** New `src/scanners/secrets/` module with 7 focused files (types, patterns, entropy, allowlist, validator, git_history, engine, report). `ScannerType::SecretsScan` is added to the orchestrator and special-cased to bypass `ScannerAgent` entirely — the orchestrator calls `SecretScanner::run()` directly. A `scan_secrets` tool lets any LLM scanner invoke the engine and receive a JSON summary.

**Tech Stack:** Rust std, `regex` crate (already in deps), `sha2` (already in deps), `serde_json` (already in deps), `toml` (already in deps), `ignore` (already in deps), `tokio::process::Command` for streaming `git log -p`, `walkdir`-free (using existing `ignore::WalkBuilder` pattern from fs_tools.rs).

---

## File Structure

**New files:**
- `src/scanners/secrets/mod.rs` — `SecretsMatch` struct, `HistoryDepth` enum, module declarations
- `src/scanners/secrets/patterns.rs` — `DetectorPattern`, `PatternMatch`, `all_patterns()`, `scan_line()`, `redact()`
- `src/scanners/secrets/entropy.rs` — `EntropyHit`, `score()`, `scan_line_for_high_entropy()`
- `src/scanners/secrets/allowlist.rs` — `Allowlist`, TOML loader, fingerprint/glob matching, `compute_fingerprint()`
- `src/scanners/secrets/validator.rs` — `ContextValidator`, 6 suppression rules
- `src/scanners/secrets/git_history.rs` — `scan_history()`, stream git log -p async
- `src/scanners/secrets/engine.rs` — `SecretScanner`, filesystem crawl, orchestrates all components
- `src/scanners/secrets/report.rs` — `write()` (MD + JSON), `to_tool_json()` (LLM-safe cap)
- `tests/secrets_test.rs` — integration tests (git history, full engine run)

**Modified files:**
- `src/agent/mod.rs` — add `ScannerType::SecretsScan`
- `src/agent/orchestrator.rs` — add `depth: HistoryDepth`, special-case SecretsScan dispatch
- `src/scanners/mod.rs` — add `pub mod secrets`, update `system_prompt`/`allowed_tools` (panic for SecretsScan)
- `src/state/mod.rs` — add `pub fn project_root(&self) -> &Path`
- `src/tools/mod.rs` — add `scan_secrets` tool definition and dispatch arm
- `src/commands/scan.rs` — accept `depth_str: String`, parse, pass to OrchestratorAgent; add "secrets" case to `resolve_scanners`
- `src/cli/mod.rs` — add `--depth` arg to `Scan` command
- `src/main.rs` — pass `depth` from CLI to `commands::scan::run`

---

## Task 1: Core Types + Pattern Definitions

**Files:**
- Create: `src/scanners/secrets/mod.rs`
- Create: `src/scanners/secrets/patterns.rs`

- [ ] **Step 1: Write failing test for pattern detection**

In `src/scanners/secrets/patterns.rs` (create the file first with just the test module):

```rust
// src/scanners/secrets/patterns.rs
use regex::Regex;
use std::sync::OnceLock;

pub struct DetectorPattern {
    pub name: &'static str,
    pub re: Regex,
    pub secret_group: usize,
}

#[derive(Debug, Clone)]
pub struct PatternMatch {
    pub detector: String,
    pub secret: String,
    pub redacted: String,
}

pub fn redact(s: &str) -> String {
    let s = s.trim_matches(|c| c == '\'' || c == '"');
    if s.len() <= 8 {
        return format!("{}...", &s[..s.len().min(2)]);
    }
    format!("{}...{}", &s[..4], &s[s.len() - 4..])
}

pub fn all_patterns() -> &'static [DetectorPattern] {
    static PATTERNS: OnceLock<Vec<DetectorPattern>> = OnceLock::new();
    PATTERNS.get_or_init(build_patterns)
}

pub fn scan_line(line: &str, patterns: &[DetectorPattern]) -> Vec<PatternMatch> {
    let mut results = Vec::new();
    for p in patterns {
        for caps in p.re.captures_iter(line) {
            if let Some(secret) = caps.get(p.secret_group) {
                let s = secret.as_str();
                results.push(PatternMatch {
                    detector: p.name.to_string(),
                    secret: s.to_string(),
                    redacted: redact(s),
                });
            }
        }
    }
    results
}

fn det(name: &'static str, pattern: &str) -> DetectorPattern {
    DetectorPattern {
        name,
        re: Regex::new(pattern).unwrap_or_else(|e| panic!("invalid pattern '{}': {}", name, e)),
        secret_group: 1,
    }
}

fn build_patterns() -> Vec<DetectorPattern> {
    vec![
        // AWS
        det("aws_access_key", r"(AKIA[0-9A-Z]{16})"),
        det("aws_session_token", r"(ASIA[0-9A-Z]{16})"),
        det("aws_secret_key", r#"(?i)aws.{0,20}(?:secret|key).{0,20}['\"\s]([0-9a-zA-Z/+]{40})['\"\s]"#),
        // GitHub
        det("github_pat", r"(ghp_[a-zA-Z0-9]{36})"),
        det("github_fine_grained", r"(github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})"),
        det("github_app_token", r"(ghs_[a-zA-Z0-9]{36})"),
        det("github_oauth", r"(gho_[a-zA-Z0-9]{36})"),
        // GitLab
        det("gitlab_pat", r"(glpat-[a-zA-Z0-9\-]{20})"),
        det("gitlab_project_token", r"(glprt-[a-zA-Z0-9\-]{20})"),
        det("gitlab_deploy_token", r"(gldt-[a-zA-Z0-9\-]{20})"),
        // Stripe
        det("stripe_secret_live", r"(sk_live_[a-zA-Z0-9]{24,99})"),
        det("stripe_secret_test", r"(sk_test_[a-zA-Z0-9]{24,99})"),
        det("stripe_restricted", r"(rk_live_[a-zA-Z0-9]{24,99})"),
        // Twilio
        det("twilio_account_sid", r"(AC[a-f0-9]{32})"),
        // Slack
        det("slack_token", r"(xox[baprs]-[a-zA-Z0-9\-]{10,99})"),
        det("slack_webhook", r"(https://hooks\.slack\.com/services/[A-Za-z0-9/]+)"),
        // JWT
        det("jwt", r"(eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)"),
        // Private keys
        det("private_key_header", r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)"),
        // .env literals (value is group 1 via non-capturing prefix)
        det("env_password", r#"(?i)(?:^|[\s;])(?:PASSWORD|PASSWD|PWD)\s*=\s*['\"]?([a-zA-Z0-9/+_\-.!@#$%^&*]{8,})['\"]?"#),
        det("env_api_key", r#"(?i)(?:^|[\s;])(?:API_KEY|APIKEY)\s*=\s*['\"]?([a-zA-Z0-9/+_\-.]{16,})['\"]?"#),
        det("env_secret", r#"(?i)(?:^|[\s;])(?:SECRET|SECRET_KEY)\s*=\s*['\"]?([a-zA-Z0-9/+_\-.]{16,})['\"]?"#),
        det("env_token", r#"(?i)(?:^|[\s;])(?:AUTH_TOKEN|ACCESS_TOKEN)\s*=\s*['\"]?([a-zA-Z0-9/+_\-.]{16,})['\"]?"#),
        // Connection strings (password is group 1)
        det("postgres_url", r"postgres(?:ql)?://[^:]+:([^@\s]{8,})@"),
        det("mysql_url", r"mysql://[^:]+:([^@\s]{8,})@"),
        det("mongodb_url", r"mongodb(?:\+srv)?://[^:]+:([^@\s]{8,})@"),
        // GCP
        det("gcp_api_key", r"(\bAIza[0-9A-Za-z\-_]{35}\b)"),
        // Azure
        det("azure_storage_key", r"(?i)AccountKey=([a-zA-Z0-9+/]{88}=*)"),
        // Email/notifications
        det("sendgrid_key", r"(SG\.[a-zA-Z0-9_\-\.]{22}\.[a-zA-Z0-9_\-\.]{43})"),
        det("mailchimp_key", r"([a-f0-9]{32}-us[0-9]{1,2})"),
        // LLM providers
        det("anthropic_key", r"(sk-ant-[a-zA-Z0-9\-]{93,})"),
        det("openai_key", r"(sk-[a-zA-Z0-9T]{48,})"),
        det("huggingface_token", r"(hf_[a-zA-Z0-9]{34,})"),
        // Package registries
        det("npm_token", r"(npm_[a-zA-Z0-9]{36})"),
        // Chat/social
        det("discord_token", r"([MNO][a-zA-Z0-9_\-]{23}\.[a-zA-Z0-9_\-]{6}\.[a-zA-Z0-9_\-]{27})"),
        det("slack_signing_secret", r"(?i)signing.?secret['\"\s:=]+([a-f0-9]{32})"),
        // Payments
        det("square_access_token", r"(sq0atp-[a-zA-Z0-9\-_]{22})"),
        det("square_client_secret", r"(sq0csp-[a-zA-Z0-9\-_]{43})"),
        // Cloud providers
        det("digitalocean_pat", r"(dop_v1_[a-zA-Z0-9]{64})"),
        det("shopify_secret", r"(shpss_[a-fA-F0-9]{32})"),
        // Generic credential assignments
        det("generic_secret_assign", r#"(?i)(?:secret|password|passwd|token|api_?key|auth|credential)\s*[:=]\s*['\"]([a-zA-Z0-9/+_\-!@#$%^&*.]{12,})['\"]"#),
        // HTTP basic auth in URLs
        det("http_basic_auth", r"https?://[^:@\s]+:([^@\s]{8,})@[^\s]+"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_aws_access_key() {
        let patterns = all_patterns();
        let hits = scan_line("export AWS_KEY=AKIAIOSFODNN7EXAMPLE", patterns);
        assert!(hits.iter().any(|h| h.detector == "aws_access_key"), "expected aws_access_key hit");
    }

    #[test]
    fn detects_github_pat() {
        let patterns = all_patterns();
        let hits = scan_line("token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345678", patterns);
        assert!(hits.iter().any(|h| h.detector == "github_pat"), "expected github_pat hit");
    }

    #[test]
    fn detects_stripe_live_key() {
        let patterns = all_patterns();
        let hits = scan_line("STRIPE_KEY=sk_live_abcdefghijklmnopqrstuvwx", patterns);
        assert!(hits.iter().any(|h| h.detector == "stripe_secret_live"), "expected stripe_secret_live hit");
    }

    #[test]
    fn detects_postgres_password() {
        let patterns = all_patterns();
        let hits = scan_line("postgres://user:s3cr3tpassword@localhost/db", patterns);
        assert!(hits.iter().any(|h| h.detector == "postgres_url"), "expected postgres_url hit");
    }

    #[test]
    fn redact_shows_first_and_last_four() {
        let patterns = all_patterns();
        let hits = scan_line("AKIAIOSFODNN7EXAMPLE", patterns);
        let hit = hits.iter().find(|h| h.detector == "aws_access_key").unwrap();
        assert!(hit.redacted.starts_with("AKIA"), "expected first 4 chars");
        assert!(hit.redacted.ends_with("MPLE"), "expected last 4 chars");
        assert!(hit.redacted.contains("..."), "expected ellipsis");
    }

    #[test]
    fn redact_short_secret_is_truncated() {
        assert_eq!(redact("abcdef"), "ab...");
    }

    #[test]
    fn no_false_positive_on_normal_word() {
        let patterns = all_patterns();
        let hits = scan_line("let name = \"hello_world\";", patterns);
        assert!(hits.is_empty() || hits.iter().all(|h| h.secret.len() < 8));
    }
}
```

- [ ] **Step 2: Create `src/scanners/secrets/mod.rs` with core types**

```rust
// src/scanners/secrets/mod.rs
pub mod allowlist;
pub mod engine;
pub mod entropy;
pub mod git_history;
pub mod patterns;
pub mod report;
pub mod validator;

pub use engine::SecretScanner;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsMatch {
    pub file: String,
    pub line: u32,
    pub commit: Option<String>,
    pub detector: String,
    pub entropy: Option<f64>,
    pub redacted: String,
    pub suppressed: bool,
    pub suppression_reason: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub enum HistoryDepth {
    #[default]
    Last50,
    Last(usize),
    All,
}

impl HistoryDepth {
    pub fn from_str(s: &str) -> Self {
        if s.eq_ignore_ascii_case("all") {
            HistoryDepth::All
        } else if let Ok(n) = s.parse::<usize>() {
            if n == 0 { HistoryDepth::Last(0) } else { HistoryDepth::Last(n) }
        } else {
            HistoryDepth::Last(50)
        }
    }

    pub fn max_count_arg(&self) -> Option<String> {
        match self {
            HistoryDepth::Last50 => Some("--max-count=50".to_string()),
            HistoryDepth::Last(n) => Some(format!("--max-count={}", n)),
            HistoryDepth::All => None,
        }
    }
}
```

> Note: `engine.rs` doesn't exist yet — stub it at the bottom of this step so the module declaration compiles.

Create empty stubs for all 7 sub-modules (each just `// TODO` or empty) so the `pub mod` declarations in `mod.rs` compile. Create these empty files:
- `src/scanners/secrets/engine.rs` — empty (will be filled in Task 7)
- `src/scanners/secrets/allowlist.rs` — empty (filled Task 3)
- `src/scanners/secrets/entropy.rs` — empty (filled Task 2)
- `src/scanners/secrets/git_history.rs` — empty (filled Task 5)
- `src/scanners/secrets/report.rs` — empty (filled Task 6)
- `src/scanners/secrets/validator.rs` — empty (filled Task 4)

But `engine.rs` needs `pub struct SecretScanner` since `mod.rs` re-exports it. Add a minimal stub:

```rust
// src/scanners/secrets/engine.rs (stub — replaced in Task 7)
pub struct SecretScanner;
```

- [ ] **Step 3: Add secrets module to `src/scanners/mod.rs`**

```rust
// src/scanners/mod.rs — FULL replacement
pub mod api_scan;
pub mod iac_scan;
pub mod report;
pub mod sast;
pub mod secrets;
pub mod supply_chain;
pub mod threat_model;

use crate::agent::ScannerType;

pub fn system_prompt(scanner: ScannerType) -> &'static str {
    match scanner {
        ScannerType::ThreatModel => threat_model::system_prompt(),
        ScannerType::Sast => sast::system_prompt(),
        ScannerType::SupplyChain => supply_chain::system_prompt(),
        ScannerType::ApiScan => api_scan::system_prompt(),
        ScannerType::IacScan => iac_scan::system_prompt(),
        ScannerType::Report => report::system_prompt(),
        ScannerType::SecretsScan => panic!("SecretsScan is non-LLM; orchestrator dispatches it directly"),
    }
}

pub fn allowed_tools(scanner: ScannerType) -> &'static [&'static str] {
    match scanner {
        ScannerType::ThreatModel => threat_model::allowed_tools(),
        ScannerType::Sast => sast::allowed_tools(),
        ScannerType::SupplyChain => supply_chain::allowed_tools(),
        ScannerType::ApiScan => api_scan::allowed_tools(),
        ScannerType::IacScan => iac_scan::allowed_tools(),
        ScannerType::Report => report::allowed_tools(),
        ScannerType::SecretsScan => panic!("SecretsScan is non-LLM; orchestrator dispatches it directly"),
    }
}
```

- [ ] **Step 4: Add `ScannerType::SecretsScan` to `src/agent/mod.rs`**

```rust
// src/agent/mod.rs — FULL replacement
pub mod orchestrator;
pub mod scanner;

use crate::state::Finding;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScannerType {
    ThreatModel,
    Sast,
    SupplyChain,
    ApiScan,
    IacScan,
    SecretsScan,
    Report,
}

impl ScannerType {
    pub fn name(&self) -> &'static str {
        match self {
            ScannerType::ThreatModel => "threat_model",
            ScannerType::Sast => "sast",
            ScannerType::SupplyChain => "supply_chain",
            ScannerType::ApiScan => "api_scan",
            ScannerType::IacScan => "iac_scan",
            ScannerType::SecretsScan => "secrets",
            ScannerType::Report => "report",
        }
    }
}

#[derive(Debug)]
pub enum ScanEvent {
    ScannerStarted(ScannerType),
    ScannerCompleted(ScannerType),
    FindingAdded(Finding),
    ToolCall { scanner: ScannerType, tool: String, arg: String },
    Error { scanner: ScannerType, message: String },
    TokensUsed { input: u32, output: u32 },
}
```

- [ ] **Step 5: Run tests to verify compilation**

```bash
cargo test --lib 2>&1 | head -60
```

Expected: no compilation errors. Pattern module tests should pass (7 tests).

- [ ] **Step 6: Commit**

```bash
git add src/scanners/secrets/ src/scanners/mod.rs src/agent/mod.rs
git commit -m "feat: add SecretsMatch types, ScannerType::SecretsScan, and ~40 detector patterns"
```

---

## Task 2: Entropy Analysis

**Files:**
- Modify: `src/scanners/secrets/entropy.rs`

- [ ] **Step 1: Write failing test in entropy.rs**

```rust
// src/scanners/secrets/entropy.rs
use std::sync::OnceLock;
use regex::Regex;

#[derive(Debug, Clone)]
pub struct EntropyHit {
    pub token: String,
    pub entropy: f64,
    pub detector: String,
}

pub fn score(s: &str) -> f64 {
    shannon_entropy(s)
}

fn shannon_entropy(s: &str) -> f64 {
    let bytes = s.as_bytes();
    let len = bytes.len() as f64;
    if len == 0.0 {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn base64_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[A-Za-z0-9+/]{20,}={0,2}").unwrap())
}

fn hex_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b[0-9a-fA-F]{32,}\b").unwrap())
}

fn alphanum_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b[A-Za-z0-9_\-]{20,}\b").unwrap())
}

pub fn scan_line_for_high_entropy(line: &str) -> Vec<EntropyHit> {
    let mut results: Vec<EntropyHit> = Vec::new();
    let mut covered: Vec<(usize, usize)> = Vec::new();

    for m in base64_re().find_iter(line) {
        let s = m.as_str();
        let e = shannon_entropy(s);
        if e > 4.5 {
            covered.push((m.start(), m.end()));
            results.push(EntropyHit {
                token: s.to_string(),
                entropy: e,
                detector: "high_entropy_base64".to_string(),
            });
        }
    }

    for m in hex_re().find_iter(line) {
        if covered.iter().any(|(s, e)| m.start() >= *s && m.end() <= *e) {
            continue;
        }
        let s = m.as_str();
        let e = shannon_entropy(s);
        if e > 3.0 {
            covered.push((m.start(), m.end()));
            results.push(EntropyHit {
                token: s.to_string(),
                entropy: e,
                detector: "high_entropy_hex".to_string(),
            });
        }
    }

    for m in alphanum_re().find_iter(line) {
        if covered.iter().any(|(s, e)| m.start() >= *s && m.end() <= *e) {
            continue;
        }
        let s = m.as_str();
        let e = shannon_entropy(s);
        if e > 3.5 {
            results.push(EntropyHit {
                token: s.to_string(),
                entropy: e,
                detector: "high_entropy_alphanum".to_string(),
            });
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_base64_token_scores_above_threshold() {
        // A high-entropy base64 string (32 random-looking bytes encoded)
        let s = "dGhpcyBpcyBhIHRlc3QgdG9rZW4hMTIzNDU2";
        assert!(score(s) > 4.5, "expected entropy > 4.5, got {:.2}", score(s));
    }

    #[test]
    fn all_same_char_scores_zero() {
        let s = "aaaaaaaaaaaaaaaaaaaaaa";
        assert!(score(s) < 0.01, "all-same-char string should have zero entropy");
    }

    #[test]
    fn low_entropy_string_below_threshold() {
        let s = "abcabcabcabcabcabcabc";
        assert!(score(s) < 2.0, "repeated pattern should have low entropy");
    }

    #[test]
    fn scan_line_finds_high_entropy_base64() {
        let line = r#"secret = "dGhpcyBpcyBhIHRlc3QgdG9rZW4hMTIzNDU2""#;
        let hits = scan_line_for_high_entropy(line);
        assert!(!hits.is_empty(), "expected at least one entropy hit");
        assert!(hits.iter().any(|h| h.detector.contains("base64")));
    }

    #[test]
    fn all_zeros_hex_not_flagged() {
        let line = "sha256: 0000000000000000000000000000000000000000000000000000000000000000";
        let hits = scan_line_for_high_entropy(line);
        let hex_hits: Vec<_> = hits.iter().filter(|h| h.detector.contains("hex")).collect();
        assert!(hex_hits.is_empty(), "all-zero hex should not be flagged");
    }

    #[test]
    fn deduplicates_overlapping_matches() {
        // base64 match should prevent the same region being flagged as alphanum
        let line = "token=dGhpcyBpcyBhIHRlc3QgdG9rZW4hMTIzNDU2";
        let hits = scan_line_for_high_entropy(line);
        let tokens: std::collections::HashSet<_> = hits.iter().map(|h| h.token.as_str()).collect();
        // Should not return the same substring under multiple detector names
        assert_eq!(tokens.len(), hits.len(), "duplicate tokens should be de-covered");
    }
}
```

- [ ] **Step 2: Run tests to verify they pass**

```bash
cargo test scanners::secrets::entropy 2>&1
```

Expected: 5 tests pass.

- [ ] **Step 3: Commit**

```bash
git add src/scanners/secrets/entropy.rs
git commit -m "feat: add Shannon entropy scoring and high-entropy token scanner"
```

---

## Task 3: Allowlist

**Files:**
- Modify: `src/scanners/secrets/allowlist.rs`

- [ ] **Step 1: Write the allowlist implementation with inline tests**

```rust
// src/scanners/secrets/allowlist.rs
use anyhow::Result;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Default, Deserialize)]
pub struct AllowlistFile {
    #[serde(default)]
    pub allowlist: AllowlistInner,
}

#[derive(Debug, Default, Deserialize)]
pub struct AllowlistInner {
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub fingerprints: Vec<String>,
    #[serde(default)]
    pub entries: Vec<AllowlistEntry>,
}

#[derive(Debug, Deserialize)]
pub struct AllowlistEntry {
    pub detector: Option<String>,
    pub path: Option<String>,
}

pub struct Allowlist {
    inner: AllowlistInner,
}

impl Allowlist {
    pub fn load(root: &Path) -> Self {
        let path = root.join(".zentra").join("secrets-allowlist.toml");
        let inner = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| toml::from_str::<AllowlistFile>(&s).ok())
            .map(|f| f.allowlist)
            .unwrap_or_default();
        Self { inner }
    }

    pub fn is_path_allowed(&self, file: &str) -> bool {
        self.inner.paths.iter().any(|pat| glob_matches(pat, file))
    }

    pub fn is_fingerprint_allowed(&self, file: &str, line: u32, redacted: &str) -> bool {
        let fp = compute_fingerprint(file, line, redacted);
        self.inner.fingerprints.iter().any(|f| *f == fp)
    }

    pub fn is_entry_allowed(&self, detector: &str, file: &str) -> bool {
        self.inner.entries.iter().any(|entry| {
            let d_match = entry.detector.as_deref().map(|d| d == detector).unwrap_or(true);
            let p_match = entry.path.as_deref().map(|p| glob_matches(p, file)).unwrap_or(true);
            d_match && p_match
        })
    }
}

pub fn compute_fingerprint(file: &str, line: u32, redacted: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{}:{}:{}", file, line, redacted).as_bytes());
    format!("{:x}", hasher.finalize())
}

fn glob_matches(pattern: &str, path: &str) -> bool {
    let re_str = glob_to_regex(pattern);
    regex::Regex::new(&re_str)
        .map(|re| re.is_match(path))
        .unwrap_or(false)
}

fn glob_to_regex(pattern: &str) -> String {
    let mut re = String::from("(?i)^");
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '*' if chars.peek() == Some(&'*') => {
                chars.next();
                re.push_str(".*");
            }
            '*' => re.push_str("[^/\\\\]*"),
            '?' => re.push('.'),
            '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '\\' | '^' | '$' | '|' => {
                re.push('\\');
                re.push(c);
            }
            _ => re.push(c),
        }
    }
    re.push('$');
    re
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write_allowlist(dir: &TempDir, content: &str) {
        let zentra = dir.path().join(".zentra");
        fs::create_dir_all(&zentra).unwrap();
        fs::write(zentra.join("secrets-allowlist.toml"), content).unwrap();
    }

    #[test]
    fn empty_allowlist_allows_nothing() {
        let dir = TempDir::new().unwrap();
        let al = Allowlist::load(dir.path());
        assert!(!al.is_path_allowed("src/config.rs"));
        assert!(!al.is_fingerprint_allowed("src/config.rs", 42, "AKIA...MPLE"));
        assert!(!al.is_entry_allowed("aws_access_key", "src/config.rs"));
    }

    #[test]
    fn missing_allowlist_file_returns_empty() {
        let dir = TempDir::new().unwrap();
        let al = Allowlist::load(dir.path()); // no .zentra/ dir
        assert!(!al.is_path_allowed("anything"));
    }

    #[test]
    fn path_glob_matches_tests_dir() {
        let dir = TempDir::new().unwrap();
        write_allowlist(&dir, r#"
[allowlist]
paths = ["tests/**"]
"#);
        let al = Allowlist::load(dir.path());
        assert!(al.is_path_allowed("tests/fixtures/sample.env"));
        assert!(al.is_path_allowed("tests/integration/config.rs"));
        assert!(!al.is_path_allowed("src/config.rs"));
    }

    #[test]
    fn fingerprint_round_trip() {
        let dir = TempDir::new().unwrap();
        let fp = compute_fingerprint("src/config.rs", 42, "AKIA...MPLE");
        write_allowlist(&dir, &format!(r#"
[allowlist]
fingerprints = ["{}"]
"#, fp));
        let al = Allowlist::load(dir.path());
        assert!(al.is_fingerprint_allowed("src/config.rs", 42, "AKIA...MPLE"));
        assert!(!al.is_fingerprint_allowed("src/config.rs", 43, "AKIA...MPLE"));
        assert!(!al.is_fingerprint_allowed("src/other.rs", 42, "AKIA...MPLE"));
    }

    #[test]
    fn entry_allows_specific_detector_and_path() {
        let dir = TempDir::new().unwrap();
        write_allowlist(&dir, r#"
[[allowlist.entries]]
detector = "high_entropy_base64"
path = "src/test_vectors.rs"
"#);
        let al = Allowlist::load(dir.path());
        assert!(al.is_entry_allowed("high_entropy_base64", "src/test_vectors.rs"));
        assert!(!al.is_entry_allowed("aws_access_key", "src/test_vectors.rs"));
        assert!(!al.is_entry_allowed("high_entropy_base64", "src/config.rs"));
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let a = compute_fingerprint("src/config.rs", 42, "AKIA...MPLE");
        let b = compute_fingerprint("src/config.rs", 42, "AKIA...MPLE");
        assert_eq!(a, b);
    }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test scanners::secrets::allowlist 2>&1
```

Expected: 6 tests pass.

- [ ] **Step 3: Commit**

```bash
git add src/scanners/secrets/allowlist.rs
git commit -m "feat: add secrets allowlist with path globs, fingerprints, and detector+path entries"
```

---

## Task 4: Context Validator

**Files:**
- Modify: `src/scanners/secrets/validator.rs`

- [ ] **Step 1: Write the validator with 6 suppression rules and inline tests**

```rust
// src/scanners/secrets/validator.rs
use super::{allowlist::Allowlist, SecretsMatch};

pub struct ContextValidator<'a> {
    allowlist: &'a Allowlist,
}

impl<'a> ContextValidator<'a> {
    pub fn new(allowlist: &'a Allowlist) -> Self {
        Self { allowlist }
    }

    /// Returns Some(reason) if the match should be suppressed, None if it is a real finding.
    pub fn check(
        &self,
        m: &SecretsMatch,
        current_line: &str,
        prev_line: Option<&str>,
    ) -> Option<String> {
        // Rule 1: Test directory
        let f = m.file.replace('\\', "/").to_lowercase();
        if f.contains("/test/")
            || f.contains("/tests/")
            || f.contains("/spec/")
            || f.contains("/mock/")
            || f.contains("/__test__/")
            || f.starts_with("test/")
            || f.starts_with("tests/")
            || f.starts_with("spec/")
            || f.starts_with("mock/")
        {
            return Some("test_directory".to_string());
        }

        // Rule 2: Placeholder value
        let r = m.redacted.to_lowercase();
        let placeholders = [
            "your_", "example", "placeholder", "xxx", "yyy", "dummy",
            "fake", "todo", "changeme", "replace", "insert", "add_your",
        ];
        if placeholders.iter().any(|p| r.contains(p))
            || r.starts_with('<')
            || r.starts_with('>')
            || is_all_same_char(&m.redacted)
        {
            return Some("placeholder_value".to_string());
        }

        // Rule 3: Inline annotation on current or previous line
        if current_line.contains("zentra:ignore") {
            return Some("inline_annotation".to_string());
        }
        if prev_line.map(|l| l.contains("zentra:ignore")).unwrap_or(false) {
            return Some("inline_annotation".to_string());
        }

        // Rule 4: Variable name only (secret extracted looks like an identifier, not a literal)
        if is_identifier_like(&m.redacted) {
            return Some("variable_name_only".to_string());
        }

        // Rule 5: Allowlist fingerprint
        if self.allowlist.is_fingerprint_allowed(&m.file, m.line, &m.redacted) {
            return Some("allowlist_fingerprint".to_string());
        }

        // Rule 6: Allowlist path glob
        if self.allowlist.is_path_allowed(&m.file) {
            return Some("allowlist_path".to_string());
        }

        // Rule 7: Allowlist detector+path entry
        if self.allowlist.is_entry_allowed(&m.detector, &m.file) {
            return Some("allowlist_entry".to_string());
        }

        None
    }
}

fn is_all_same_char(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    chars.len() > 3 && chars.windows(2).all(|w| w[0] == w[1])
}

fn is_identifier_like(s: &str) -> bool {
    // Looks like a variable reference: starts with letter, only word chars,
    // no special chars (no +/= etc.), very few digits, no embedded dots or dashes
    let clean: String = s.chars().filter(|c| *c != '.' && *c != '.').collect();
    if clean.is_empty() {
        return false;
    }
    let first = clean.chars().next().unwrap();
    if !first.is_alphabetic() && first != '_' {
        return false;
    }
    let all_word = clean.chars().all(|c| c.is_alphanumeric() || c == '_');
    if !all_word {
        return false;
    }
    // If it has no digits at all, or fewer than 3 digits, treat as identifier
    let digit_count = clean.chars().filter(|c| c.is_ascii_digit()).count();
    digit_count < 3
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::secrets::allowlist::Allowlist;
    use tempfile::TempDir;

    fn make_match(file: &str, redacted: &str, detector: &str) -> SecretsMatch {
        SecretsMatch {
            file: file.to_string(),
            line: 42,
            commit: None,
            detector: detector.to_string(),
            entropy: Some(4.8),
            redacted: redacted.to_string(),
            suppressed: false,
            suppression_reason: None,
        }
    }

    fn no_allowlist() -> Allowlist {
        let dir = TempDir::new().unwrap();
        Allowlist::load(dir.path())
    }

    #[test]
    fn suppresses_test_directory() {
        let al = no_allowlist();
        let v = ContextValidator::new(&al);
        let m = make_match("tests/fixtures/config.rs", "AKIA...MPLE", "aws_access_key");
        assert_eq!(v.check(&m, "", None), Some("test_directory".to_string()));
    }

    #[test]
    fn suppresses_spec_directory() {
        let al = no_allowlist();
        let v = ContextValidator::new(&al);
        let m = make_match("spec/unit/config.rb", "AKIA...MPLE", "aws_access_key");
        assert_eq!(v.check(&m, "", None), Some("test_directory".to_string()));
    }

    #[test]
    fn suppresses_placeholder_value() {
        let al = no_allowlist();
        let v = ContextValidator::new(&al);
        let m = make_match("src/config.rs", "your_api_key_here", "aws_access_key");
        assert_eq!(v.check(&m, "", None), Some("placeholder_value".to_string()));
    }

    #[test]
    fn suppresses_all_same_char() {
        let al = no_allowlist();
        let v = ContextValidator::new(&al);
        let m = make_match("src/config.rs", "aaaaaaaaaaaaaaaaaaa", "aws_access_key");
        assert_eq!(v.check(&m, "", None), Some("placeholder_value".to_string()));
    }

    #[test]
    fn suppresses_inline_annotation_on_current_line() {
        let al = no_allowlist();
        let v = ContextValidator::new(&al);
        let m = make_match("src/config.rs", "AKIA...MPLE", "aws_access_key");
        let line = r#"api_key = "AKIAIOSFODNN7EXAMPLE" # zentra:ignore"#;
        assert_eq!(v.check(&m, line, None), Some("inline_annotation".to_string()));
    }

    #[test]
    fn suppresses_inline_annotation_on_prev_line() {
        let al = no_allowlist();
        let v = ContextValidator::new(&al);
        let m = make_match("src/config.rs", "AKIA...MPLE", "aws_access_key");
        let prev = "// zentra:ignore";
        assert_eq!(v.check(&m, r#"api_key = "AKIAIOSFODNN7EXAMPLE""#, Some(prev)),
            Some("inline_annotation".to_string()));
    }

    #[test]
    fn suppresses_variable_name_reference() {
        let al = no_allowlist();
        let v = ContextValidator::new(&al);
        // "api_key_var" looks like a variable name
        let m = make_match("src/config.rs", "api_key_var", "env_api_key");
        assert_eq!(v.check(&m, "", None), Some("variable_name_only".to_string()));
    }

    #[test]
    fn does_not_suppress_real_secret() {
        let al = no_allowlist();
        let v = ContextValidator::new(&al);
        // A realistic AWS key
        let m = make_match("src/config.rs", "AKIA...MPLE", "aws_access_key");
        assert_eq!(v.check(&m, r#"key = "AKIAIOSFODNN7EXAMPLE""#, None), None);
    }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test scanners::secrets::validator 2>&1
```

Expected: 8 tests pass.

- [ ] **Step 3: Commit**

```bash
git add src/scanners/secrets/validator.rs
git commit -m "feat: add ContextValidator with 6 suppression rules (test dir, placeholder, annotation, identifier, allowlist)"
```

---

## Task 5: Git History Crawler

**Files:**
- Modify: `src/scanners/secrets/git_history.rs`
- Create: `tests/secrets_test.rs`

- [ ] **Step 1: Write integration test in `tests/secrets_test.rs`**

```rust
// tests/secrets_test.rs
use std::process::Command;
use tempfile::TempDir;
use zentra_cli::scanners::secrets::{allowlist::Allowlist, git_history, patterns, validator::ContextValidator, HistoryDepth};

fn init_git_repo(dir: &TempDir) {
    Command::new("git").args(["init"]).current_dir(dir.path()).output().unwrap();
    Command::new("git")
        .args(["config", "user.email", "test@test.com"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    Command::new("git")
        .args(["config", "user.name", "Test"])
        .current_dir(dir.path())
        .output()
        .unwrap();
}

#[tokio::test]
async fn git_history_detects_planted_secret_in_past_commit() {
    let dir = TempDir::new().unwrap();
    init_git_repo(&dir);

    // Commit 1: plant a fake AWS key
    std::fs::write(dir.path().join("config.rs"), r#"let key = "AKIAIOSFODNN7EXAMPLE";"#).unwrap();
    Command::new("git").args(["add", "."]).current_dir(dir.path()).output().unwrap();
    Command::new("git")
        .args(["commit", "-m", "add config"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    // Commit 2: remove the secret (now it's only in history)
    std::fs::write(
        dir.path().join("config.rs"),
        r#"let key = std::env::var("AWS_KEY").unwrap();"#,
    )
    .unwrap();
    Command::new("git").args(["add", "."]).current_dir(dir.path()).output().unwrap();
    Command::new("git")
        .args(["commit", "-m", "remove secret"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let al = Allowlist::load(dir.path());
    let validator = ContextValidator::new(&al);
    let pats = patterns::all_patterns();

    let hits = git_history::scan_history(dir.path(), &HistoryDepth::All, pats, &validator)
        .await
        .unwrap();

    assert!(
        hits.iter().any(|h| h.detector == "aws_access_key" && h.commit.is_some()),
        "expected aws_access_key hit in git history, got: {:?}",
        hits.iter().map(|h| &h.detector).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn git_history_depth_zero_returns_empty() {
    let dir = TempDir::new().unwrap();
    init_git_repo(&dir);

    std::fs::write(dir.path().join("config.rs"), r#"let key = "AKIAIOSFODNN7EXAMPLE";"#).unwrap();
    Command::new("git").args(["add", "."]).current_dir(dir.path()).output().unwrap();
    Command::new("git")
        .args(["commit", "-m", "add config"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let al = Allowlist::load(dir.path());
    let validator = ContextValidator::new(&al);
    let pats = patterns::all_patterns();

    let hits = git_history::scan_history(dir.path(), &HistoryDepth::Last(0), pats, &validator)
        .await
        .unwrap();

    assert!(hits.is_empty(), "depth=0 should return no hits");
}

#[tokio::test]
async fn git_not_available_returns_empty_gracefully() {
    // Point root at a temp dir with no git repo — git log will fail
    let dir = TempDir::new().unwrap();
    let al = Allowlist::load(dir.path());
    let validator = ContextValidator::new(&al);
    let pats = patterns::all_patterns();

    let result =
        git_history::scan_history(dir.path(), &HistoryDepth::Last(10), pats, &validator).await;

    // Should not return an Err — graceful fallback to empty
    assert!(result.is_ok(), "expected Ok([]) when git is unavailable, got {:?}", result);
    assert!(result.unwrap().is_empty());
}
```

- [ ] **Step 2: Run test to verify it fails** (git_history.rs is empty stub)

```bash
cargo test --test secrets_test git_history_detects 2>&1 | head -30
```

Expected: compilation error because `git_history::scan_history` doesn't exist yet.

- [ ] **Step 3: Implement `src/scanners/secrets/git_history.rs`**

```rust
// src/scanners/secrets/git_history.rs
use anyhow::Result;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use super::{
    allowlist::Allowlist,
    entropy,
    patterns::{self, DetectorPattern},
    validator::ContextValidator,
    HistoryDepth, SecretsMatch,
};

pub async fn scan_history(
    root: &Path,
    depth: &HistoryDepth,
    detector_patterns: &[DetectorPattern],
    validator: &ContextValidator<'_>,
) -> Result<Vec<SecretsMatch>> {
    // depth=Last(0) means skip history entirely
    if matches!(depth, HistoryDepth::Last(0)) {
        return Ok(Vec::new());
    }

    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(root).arg("log").arg("-p").arg("--no-merges");

    if let Some(arg) = depth.max_count_arg() {
        cmd.arg(arg);
    }

    let mut child = match cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return Ok(Vec::new()), // git not available
    };

    let stdout = child.stdout.take().expect("stdout was piped");
    let reader = BufReader::new(stdout);
    let mut lines = reader.lines();

    let mut current_commit: Option<String> = None;
    let mut current_file: Option<String> = None;
    let mut line_no: u32 = 0;
    let mut results: Vec<SecretsMatch> = Vec::new();

    while let Ok(Some(raw)) = lines.next_line().await {
        if raw.starts_with("commit ") {
            current_commit = raw.split_whitespace().nth(1).map(|s| s.to_string());
            current_file = None;
            line_no = 0;
            continue;
        }

        if raw.starts_with("+++ b/") {
            current_file = Some(raw[6..].to_string());
            line_no = 0;
            continue;
        }

        if raw.starts_with("+++ /dev/null") {
            current_file = None;
            continue;
        }

        if raw.starts_with("@@ ") {
            // @@ -old_start,count +new_start,count @@
            if let Some(plus_part) = raw.split('+').nth(1) {
                let num: u32 = plus_part
                    .split(|c| c == ',' || c == ' ')
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(1);
                line_no = num.saturating_sub(1);
            }
            continue;
        }

        if current_file.is_none() {
            continue;
        }

        // Context line (space prefix) — increment line counter
        if raw.starts_with(' ') {
            line_no += 1;
            continue;
        }

        // Removed line — don't scan, don't increment
        if raw.starts_with('-') && !raw.starts_with("---") {
            continue;
        }

        // Added line — scan it
        if raw.starts_with('+') && !raw.starts_with("+++") {
            line_no += 1;
            let line = &raw[1..];
            let file = current_file.as_deref().unwrap_or("");

            let pattern_hits = patterns::scan_line(line, detector_patterns);
            for hit in &pattern_hits {
                let entropy_score = entropy::score(&hit.secret);
                let m = SecretsMatch {
                    file: file.to_string(),
                    line: line_no,
                    commit: current_commit.clone(),
                    detector: hit.detector.clone(),
                    entropy: Some(entropy_score),
                    redacted: hit.redacted.clone(),
                    suppressed: false,
                    suppression_reason: None,
                };
                let suppression = validator.check(&m, line, None);
                let mut m = m;
                if let Some(reason) = suppression {
                    m.suppressed = true;
                    m.suppression_reason = Some(reason);
                }
                results.push(m);
            }

            let covered_secrets: std::collections::HashSet<&str> =
                pattern_hits.iter().map(|h| h.secret.as_str()).collect();

            for hit in entropy::scan_line_for_high_entropy(line) {
                if covered_secrets.iter().any(|s| s.contains(&hit.token) || hit.token.contains(s)) {
                    continue;
                }
                let redacted = patterns::redact(&hit.token);
                let m = SecretsMatch {
                    file: file.to_string(),
                    line: line_no,
                    commit: current_commit.clone(),
                    detector: hit.detector.clone(),
                    entropy: Some(hit.entropy),
                    redacted: redacted.clone(),
                    suppressed: false,
                    suppression_reason: None,
                };
                let suppression = validator.check(&m, line, None);
                let mut m = m;
                if let Some(reason) = suppression {
                    m.suppressed = true;
                    m.suppression_reason = Some(reason);
                }
                results.push(m);
            }
        }
    }

    child.wait().await.ok();
    Ok(results)
}
```

- [ ] **Step 4: Run integration tests**

```bash
cargo test --test secrets_test git_history 2>&1
```

Expected: all 3 git_history tests pass. (If git is not in PATH, `git_not_available_returns_empty_gracefully` still passes by design.)

- [ ] **Step 5: Commit**

```bash
git add src/scanners/secrets/git_history.rs tests/secrets_test.rs
git commit -m "feat: add async git history crawler — scans added lines from git log -p"
```

---

## Task 6: Report Writer

**Files:**
- Modify: `src/scanners/secrets/report.rs`

- [ ] **Step 1: Implement report.rs with inline tests**

```rust
// src/scanners/secrets/report.rs
use anyhow::Result;
use std::{fs, path::Path};

use super::SecretsMatch;

pub fn write(root: &Path, matches: &[SecretsMatch]) -> Result<()> {
    let zentra = root.join(".zentra");
    fs::create_dir_all(&zentra)?;

    let active: Vec<&SecretsMatch> = matches.iter().filter(|m| !m.suppressed).collect();
    let suppressed: Vec<&SecretsMatch> = matches.iter().filter(|m| m.suppressed).collect();

    let mut md = String::new();
    md.push_str("# Secrets Scan Report\n\n");
    md.push_str(&format!("## Active Findings ({})\n\n", active.len()));

    if active.is_empty() {
        md.push_str("No active findings.\n\n");
    } else {
        md.push_str("| File | Line | Commit | Detector | Entropy | Redacted |\n");
        md.push_str("|------|------|--------|----------|---------|----------|\n");
        for m in &active {
            let commit = m
                .commit
                .as_deref()
                .map(|c| c.get(..7).unwrap_or(c))
                .unwrap_or("working tree");
            let entropy = m
                .entropy
                .map(|e| format!("{:.1}", e))
                .unwrap_or_else(|| "-".to_string());
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                m.file, m.line, commit, m.detector, entropy, m.redacted
            ));
        }
        md.push('\n');
    }

    md.push_str(&format!("## Suppressed ({})\n\n", suppressed.len()));
    if !suppressed.is_empty() {
        md.push_str("| File | Line | Detector | Reason |\n");
        md.push_str("|------|------|----------|--------|\n");
        for m in &suppressed {
            md.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                m.file,
                m.line,
                m.detector,
                m.suppression_reason.as_deref().unwrap_or("-")
            ));
        }
    }

    fs::write(zentra.join("secrets-report.md"), &md)?;

    let json = serde_json::to_string_pretty(matches)?;
    fs::write(zentra.join("secrets-findings.json"), json)?;

    Ok(())
}

pub fn to_tool_json(matches: &[SecretsMatch]) -> serde_json::Value {
    let total_active = matches.iter().filter(|m| !m.suppressed).count();
    let total_suppressed = matches.iter().filter(|m| m.suppressed).count();

    let findings: Vec<serde_json::Value> = matches
        .iter()
        .filter(|m| !m.suppressed)
        .take(50)
        .map(|m| {
            serde_json::json!({
                "file": m.file,
                "line": m.line,
                "commit": m.commit,
                "detector": m.detector,
                "entropy": m.entropy,
                "redacted": m.redacted
            })
        })
        .collect();

    serde_json::json!({
        "total_active": total_active,
        "total_suppressed": total_suppressed,
        "findings": findings
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_active(file: &str, detector: &str) -> SecretsMatch {
        SecretsMatch {
            file: file.to_string(),
            line: 42,
            commit: None,
            detector: detector.to_string(),
            entropy: Some(4.8),
            redacted: "AKIA...MPLE".to_string(),
            suppressed: false,
            suppression_reason: None,
        }
    }

    fn make_suppressed(file: &str, detector: &str) -> SecretsMatch {
        SecretsMatch {
            file: file.to_string(),
            line: 10,
            commit: None,
            detector: detector.to_string(),
            entropy: Some(3.0),
            redacted: "your_key".to_string(),
            suppressed: true,
            suppression_reason: Some("placeholder_value".to_string()),
        }
    }

    #[test]
    fn write_creates_md_and_json() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".zentra")).unwrap();

        let matches = vec![
            make_active("src/config.rs", "aws_access_key"),
            make_suppressed("tests/fixtures.rs", "aws_access_key"),
        ];

        write(dir.path(), &matches).unwrap();

        let md = std::fs::read_to_string(dir.path().join(".zentra/secrets-report.md")).unwrap();
        assert!(md.contains("Active Findings (1)"), "MD should show 1 active finding");
        assert!(md.contains("aws_access_key"), "MD should contain detector name");
        assert!(md.contains("Suppressed (1)"), "MD should show 1 suppressed");
        assert!(md.contains("placeholder_value"), "MD should show suppression reason");

        let raw = std::fs::read_to_string(dir.path().join(".zentra/secrets-findings.json")).unwrap();
        let json: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert!(json.is_array(), "findings.json should be a JSON array");
        assert_eq!(json.as_array().unwrap().len(), 2, "array should contain all matches (both active and suppressed)");
    }

    #[test]
    fn to_tool_json_caps_at_50_active() {
        let matches: Vec<SecretsMatch> = (0..80)
            .map(|i| SecretsMatch {
                file: format!("file{}.rs", i),
                line: i as u32,
                commit: None,
                detector: "aws_access_key".to_string(),
                entropy: Some(4.8),
                redacted: "AKIA...MPLE".to_string(),
                suppressed: false,
                suppression_reason: None,
            })
            .collect();

        let json = to_tool_json(&matches);
        assert_eq!(json["total_active"], 80, "total_active should reflect true count");
        assert_eq!(
            json["findings"].as_array().unwrap().len(),
            50,
            "findings array should be capped at 50"
        );
    }

    #[test]
    fn to_tool_json_excludes_suppressed() {
        let matches = vec![
            make_active("src/real.rs", "aws_access_key"),
            make_suppressed("tests/fake.rs", "aws_access_key"),
        ];

        let json = to_tool_json(&matches);
        assert_eq!(json["total_active"], 1);
        assert_eq!(json["total_suppressed"], 1);
        assert_eq!(json["findings"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn to_tool_json_never_includes_raw_secret() {
        let mut m = make_active("src/config.rs", "aws_access_key");
        m.redacted = "AKIA...MPLE".to_string();
        let json = to_tool_json(&[m]);
        let finding = &json["findings"][0];
        // redacted field is present but raw secret value is not
        let redacted_val = finding["redacted"].as_str().unwrap();
        assert!(redacted_val.contains("..."), "redacted field must contain ellipsis");
        assert!(!redacted_val.contains("AKIAIOSFODNN7EXAMPLE"), "raw secret must not appear");
    }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test scanners::secrets::report 2>&1
```

Expected: 4 tests pass.

- [ ] **Step 3: Commit**

```bash
git add src/scanners/secrets/report.rs
git commit -m "feat: add secrets report writer (markdown + JSON) and LLM-safe tool JSON output"
```

---

## Task 7: Engine — Filesystem Crawl + Orchestration

**Files:**
- Modify: `src/scanners/secrets/engine.rs` (replace stub)
- Modify: `src/scanners/secrets/mod.rs` (add `pub use engine::SecretScanner`)
- Modify: `tests/secrets_test.rs` (add engine integration test)

- [ ] **Step 1: Add engine integration test to `tests/secrets_test.rs`**

Append these tests (keeping all existing tests in the file):

```rust
// ---- Add to bottom of tests/secrets_test.rs ----

use std::fs;
use zentra_cli::scanners::secrets::{SecretScanner, HistoryDepth};
use zentra_cli::state::StateWriter;

#[tokio::test]
async fn engine_detects_secret_in_working_tree() {
    let dir = TempDir::new().unwrap();

    // Plant a fake AWS key in a source file
    fs::write(dir.path().join("config.rs"), r#"let key = "AKIAIOSFODNN7EXAMPLE";"#).unwrap();

    // Create .zentra dir (StateWriter requires it)
    fs::create_dir_all(dir.path().join(".zentra")).unwrap();

    let (tx, _rx) = tokio::sync::mpsc::channel(128);
    let writer = StateWriter::new(dir.path()).unwrap();

    let scanner = SecretScanner::new(
        dir.path().to_path_buf(),
        HistoryDepth::Last(0), // skip git history
        tx,
    );

    let matches = scanner.run(&writer).await.unwrap();

    assert!(
        matches.iter().any(|m| m.detector == "aws_access_key" && !m.suppressed),
        "expected active aws_access_key hit in working tree, got: {:?}",
        matches
    );
}

#[tokio::test]
async fn engine_suppresses_secrets_in_test_dir() {
    let dir = TempDir::new().unwrap();
    fs::create_dir_all(dir.path().join("tests")).unwrap();
    fs::write(
        dir.path().join("tests").join("fixtures.rs"),
        r#"let key = "AKIAIOSFODNN7EXAMPLE";"#,
    )
    .unwrap();
    fs::create_dir_all(dir.path().join(".zentra")).unwrap();

    let (tx, _rx) = tokio::sync::mpsc::channel(128);
    let writer = StateWriter::new(dir.path()).unwrap();
    let scanner = SecretScanner::new(dir.path().to_path_buf(), HistoryDepth::Last(0), tx);
    let matches = scanner.run(&writer).await.unwrap();

    let active: Vec<_> = matches.iter().filter(|m| !m.suppressed).collect();
    assert!(
        active.is_empty(),
        "secrets in tests/ should be suppressed, but got active: {:?}",
        active
    );
}

#[tokio::test]
async fn engine_writes_report_files() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("config.rs"), r#"let key = "AKIAIOSFODNN7EXAMPLE";"#).unwrap();
    fs::create_dir_all(dir.path().join(".zentra")).unwrap();

    let (tx, _rx) = tokio::sync::mpsc::channel(128);
    let writer = StateWriter::new(dir.path()).unwrap();
    let scanner = SecretScanner::new(dir.path().to_path_buf(), HistoryDepth::Last(0), tx);
    scanner.run(&writer).await.unwrap();

    assert!(
        dir.path().join(".zentra/secrets-report.md").exists(),
        "secrets-report.md should be written"
    );
    assert!(
        dir.path().join(".zentra/secrets-findings.json").exists(),
        "secrets-findings.json should be written"
    );
}
```

- [ ] **Step 2: Run to verify test fails** (engine is a stub)

```bash
cargo test --test secrets_test engine 2>&1 | head -20
```

Expected: `SecretScanner` has no fields/methods yet.

- [ ] **Step 3: Implement engine.rs**

```rust
// src/scanners/secrets/engine.rs
use anyhow::Result;
use ignore::WalkBuilder;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

use crate::agent::{ScanEvent, ScannerType};
use crate::state::{Finding, Severity, StateWriter};

use super::{
    allowlist::Allowlist,
    entropy,
    git_history,
    patterns,
    report,
    validator::ContextValidator,
    HistoryDepth, SecretsMatch,
};

pub struct SecretScanner {
    root: PathBuf,
    depth: HistoryDepth,
    tx: mpsc::Sender<ScanEvent>,
}

impl SecretScanner {
    pub fn new(root: PathBuf, depth: HistoryDepth, tx: mpsc::Sender<ScanEvent>) -> Self {
        Self { root, depth, tx }
    }

    pub async fn run(self, state_writer: &StateWriter) -> Result<Vec<SecretsMatch>> {
        self.tx.send(ScanEvent::ScannerStarted(ScannerType::SecretsScan)).await.ok();

        let detector_patterns = patterns::all_patterns();
        let allowlist = Allowlist::load(&self.root);
        let validator = ContextValidator::new(&allowlist);

        let mut all_matches = Vec::new();

        // Phase 1: Filesystem scan (sync, runs on current thread)
        let fs_matches = scan_filesystem(&self.root, detector_patterns, &validator);
        all_matches.extend(fs_matches);

        // Phase 2: Git history scan (async streaming)
        let git_matches =
            git_history::scan_history(&self.root, &self.depth, detector_patterns, &validator)
                .await
                .unwrap_or_default();
        all_matches.extend(git_matches);

        // Dedup: same file+line+detector+commit combination
        all_matches.sort_by(|a, b| {
            (&a.file, a.line, &a.detector, &a.commit)
                .partial_cmp(&(&b.file, b.line, &b.detector, &b.commit))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        all_matches.dedup_by(|a, b| {
            a.file == b.file
                && a.line == b.line
                && a.detector == b.detector
                && a.commit == b.commit
        });

        // Write report artifacts
        report::write(&self.root, &all_matches).unwrap_or_else(|e| {
            eprintln!("secrets report write error: {}", e);
        });

        // Emit active findings to TUI and state writer
        for m in all_matches.iter().filter(|m| !m.suppressed) {
            let commit_note = m
                .commit
                .as_deref()
                .map(|c| format!(" (commit {})", &c[..7.min(c.len())]))
                .unwrap_or_default();

            let finding = Finding {
                scanner: ScannerType::SecretsScan.name().to_string(),
                severity: Severity::High,
                title: format!("Potential secret: {}", m.detector),
                description: format!(
                    "Detected {} at {}:{}{}. Redacted value: {}",
                    m.detector, m.file, m.line, commit_note, m.redacted
                ),
                location: Some(format!("{}:{}", m.file, m.line)),
                recommendation: "Remove the secret, rotate it immediately, and replace with an environment variable or secrets manager reference.".to_string(),
            };
            state_writer.write_finding(&finding).ok();
            self.tx.send(ScanEvent::FindingAdded(finding)).await.ok();
        }

        self.tx.send(ScanEvent::ScannerCompleted(ScannerType::SecretsScan)).await.ok();
        Ok(all_matches)
    }
}

fn scan_filesystem(
    root: &Path,
    detector_patterns: &[patterns::DetectorPattern],
    validator: &ContextValidator<'_>,
) -> Vec<SecretsMatch> {
    let mut results = Vec::new();
    let root_str = root.to_string_lossy();

    for entry in WalkBuilder::new(root)
        .hidden(false)
        .follow_links(false)
        .build()
        .flatten()
    {
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let path = entry.path();
        let path_str = path.to_string_lossy();

        // Skip .zentra/ outputs and .git/
        if path_str.contains(".zentra") || path_str.contains(".git") {
            continue;
        }

        let rel = path
            .strip_prefix(root)
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_else(|_| path_str.replace(&*root_str, "").trim_start_matches('/').to_string());

        let content = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => continue, // binary or unreadable — skip
        };

        let content_lines: Vec<&str> = content.lines().collect();

        for (i, line) in content_lines.iter().enumerate() {
            let line_no = (i + 1) as u32;
            let prev_line = if i > 0 { Some(content_lines[i - 1]) } else { None };

            let pattern_hits = patterns::scan_line(line, detector_patterns);
            let covered: std::collections::HashSet<String> =
                pattern_hits.iter().map(|h| h.secret.clone()).collect();

            for hit in &pattern_hits {
                let entropy_score = entropy::score(&hit.secret);
                let m = SecretsMatch {
                    file: rel.clone(),
                    line: line_no,
                    commit: None,
                    detector: hit.detector.clone(),
                    entropy: Some(entropy_score),
                    redacted: hit.redacted.clone(),
                    suppressed: false,
                    suppression_reason: None,
                };
                let suppression = validator.check(&m, line, prev_line);
                let mut m = m;
                if let Some(reason) = suppression {
                    m.suppressed = true;
                    m.suppression_reason = Some(reason);
                }
                results.push(m);
            }

            for hit in entropy::scan_line_for_high_entropy(line) {
                if covered.iter().any(|s| s.contains(&hit.token) || hit.token.contains(s.as_str())) {
                    continue;
                }
                let redacted = patterns::redact(&hit.token);
                let m = SecretsMatch {
                    file: rel.clone(),
                    line: line_no,
                    commit: None,
                    detector: hit.detector.clone(),
                    entropy: Some(hit.entropy),
                    redacted: redacted.clone(),
                    suppressed: false,
                    suppression_reason: None,
                };
                let suppression = validator.check(&m, line, prev_line);
                let mut m = m;
                if let Some(reason) = suppression {
                    m.suppressed = true;
                    m.suppression_reason = Some(reason);
                }
                results.push(m);
            }
        }
    }

    results
}
```

- [ ] **Step 4: Update `src/scanners/secrets/mod.rs` to re-export SecretScanner**

The `pub use engine::SecretScanner;` line should already be there from Task 1 Step 2. Verify it is present. If not, add it.

- [ ] **Step 5: Run all integration tests**

```bash
cargo test --test secrets_test 2>&1
```

Expected: all 6 tests pass (3 git_history + 3 engine).

- [ ] **Step 6: Run all tests**

```bash
cargo test 2>&1 | tail -20
```

Expected: no regressions.

- [ ] **Step 7: Commit**

```bash
git add src/scanners/secrets/engine.rs src/scanners/secrets/mod.rs tests/secrets_test.rs
git commit -m "feat: implement SecretScanner engine — filesystem crawl, git history, finding emission"
```

---

## Task 8: Orchestrator + scan_secrets Tool + StateWriter Accessor

**Files:**
- Modify: `src/state/mod.rs` — add `pub fn project_root(&self) -> &Path`
- Modify: `src/agent/orchestrator.rs` — add `depth` field, special-case SecretsScan dispatch
- Modify: `src/tools/mod.rs` — add `scan_secrets` tool definition and dispatch arm
- Modify: `src/commands/scan.rs` — pass `HistoryDepth::default()` to OrchestratorAgent, add "secrets" to resolve_scanners

- [ ] **Step 1: Add `project_root()` to StateWriter**

In `src/state/mod.rs`, add this method to the `StateWriter` impl block (after `read_findings_raw`):

```rust
    pub fn project_root(&self) -> &std::path::Path {
        self.zentra_dir
            .parent()
            .expect("zentra_dir always has a parent")
    }
```

- [ ] **Step 2: Update orchestrator.rs**

Replace `src/agent/orchestrator.rs` entirely:

```rust
// src/agent/orchestrator.rs
use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::agent::{ScanEvent, ScannerType};
use crate::agent::scanner::ScannerAgent;
use crate::provider::LLMProvider;
use crate::scanners::secrets::{HistoryDepth, SecretScanner};
use crate::state::StateWriter;
use crate::tools::ToolRegistry;

const PARALLEL_SCANNERS: &[ScannerType] = &[
    ScannerType::Sast,
    ScannerType::SupplyChain,
    ScannerType::ApiScan,
    ScannerType::IacScan,
    ScannerType::SecretsScan,
];

pub struct OrchestratorAgent {
    provider: Arc<dyn LLMProvider>,
    tool_registry: Arc<ToolRegistry>,
    state_writer: Arc<StateWriter>,
    tx: mpsc::Sender<ScanEvent>,
    depth: HistoryDepth,
}

impl OrchestratorAgent {
    pub fn new(
        provider: Arc<dyn LLMProvider>,
        tool_registry: Arc<ToolRegistry>,
        state_writer: Arc<StateWriter>,
        tx: mpsc::Sender<ScanEvent>,
        depth: HistoryDepth,
    ) -> Self {
        Self { provider, tool_registry, state_writer, tx, depth }
    }

    pub async fn run(self, scanners: &[ScannerType]) -> Result<()> {
        // Phase 1: ThreatModel — sequential, runs first
        if scanners.contains(&ScannerType::ThreatModel) {
            self.run_llm_scanner(ScannerType::ThreatModel).await?;
        }

        // Phase 2: parallel scanners
        let parallel: Vec<ScannerType> = PARALLEL_SCANNERS
            .iter()
            .filter(|s| scanners.contains(s))
            .copied()
            .collect();

        if !parallel.is_empty() {
            let mut handles = Vec::new();
            for scanner_type in parallel {
                if scanner_type == ScannerType::SecretsScan {
                    let writer = Arc::clone(&self.state_writer);
                    let tx = self.tx.clone();
                    let depth = self.depth.clone();
                    let root = writer.project_root().to_path_buf();
                    handles.push(tokio::spawn(async move {
                        SecretScanner::new(root, depth, tx)
                            .run(&writer)
                            .await
                            .map(|_| ())
                    }));
                } else {
                    let provider = Arc::clone(&self.provider);
                    let registry = Arc::clone(&self.tool_registry);
                    let writer = Arc::clone(&self.state_writer);
                    let tx = self.tx.clone();
                    handles.push(tokio::spawn(async move {
                        ScannerAgent::new(scanner_type, provider, registry, writer, tx)
                            .run()
                            .await
                    }));
                }
            }
            for handle in handles {
                handle.await??;
            }
        }

        // Phase 3: Report — sequential, runs last
        if scanners.contains(&ScannerType::Report) {
            self.run_llm_scanner(ScannerType::Report).await?;
        }

        Ok(())
    }

    async fn run_llm_scanner(&self, scanner_type: ScannerType) -> Result<()> {
        ScannerAgent::new(
            scanner_type,
            Arc::clone(&self.provider),
            Arc::clone(&self.tool_registry),
            Arc::clone(&self.state_writer),
            self.tx.clone(),
        )
        .run()
        .await
    }
}
```

- [ ] **Step 3: Add scan_secrets tool to ToolRegistry in `src/tools/mod.rs`**

In `definitions()`, add this entry to the returned `vec![]` (after the `git_status` entry):

```rust
            ToolDefinition {
                name: "scan_secrets".to_string(),
                description: "Run the deterministic secrets scanner on the codebase and git history. Returns a JSON summary of findings (max 50 active, no raw values). Use to inventory potential leaked credentials without LLM analysis.".to_string(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "depth": {
                            "type": "string",
                            "description": "Git history depth: a number like '50' or 'all' for full history. Default '50'."
                        }
                    },
                    "required": []
                }),
            },
```

In `dispatch()`, add this arm before the `unknown =>` fallback:

```rust
            "scan_secrets" => {
                let depth_str = args["depth"].as_str().unwrap_or("50");
                let depth = crate::scanners::secrets::HistoryDepth::from_str(depth_str);
                let root = state_writer.project_root().to_path_buf();
                let (tool_tx, _rx) = mpsc::channel(128);
                match crate::scanners::secrets::SecretScanner::new(root, depth, tool_tx)
                    .run(state_writer)
                    .await
                {
                    Ok(matches) => crate::scanners::secrets::report::to_tool_json(&matches).to_string(),
                    Err(e) => format!("scan_secrets error: {}", e),
                }
            }
```

- [ ] **Step 4: Update `src/commands/scan.rs`**

Change the `run()` signature and `run_once()` signature, and add `OrchestratorAgent::new` depth arg. Also add "secrets" to `resolve_scanners`.

Replace `src/commands/scan.rs` entirely:

```rust
// src/commands/scan.rs
use anyhow::{Context, Result};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::agent::{orchestrator::OrchestratorAgent, ScannerType};
use crate::config::{keychain, GlobalConfig, ProjectConfig};
use crate::provider::{anthropic::AnthropicProvider, openai_compat::OpenAICompatProvider, LLMProvider};
use crate::scanners::secrets::HistoryDepth;
use crate::state::StateWriter;
use crate::tools::ToolRegistry;
use crate::tui::{scan_ui::run_scan_ui, ScanOutcome};
use crate::wizard;

pub async fn run(
    provider_override: Option<String>,
    only: Option<String>,
    depth_str: String,
) -> Result<()> {
    let depth = HistoryDepth::from_str(&depth_str);
    let scanners = resolve_scanners(only.as_deref());
    loop {
        match run_once(provider_override.clone(), scanners.clone(), depth.clone()).await? {
            ScanOutcome::Completed | ScanOutcome::Aborted => break,
            ScanOutcome::Reconfigure => {
                wizard::run_setup(None).await?;
            }
            ScanOutcome::ExitApp => std::process::exit(0),
        }
    }
    Ok(())
}

pub async fn run_with_scanners(scanners: Vec<ScannerType>) -> Result<()> {
    let depth = HistoryDepth::default();
    loop {
        match run_once(None, scanners.clone(), depth.clone()).await? {
            ScanOutcome::Completed | ScanOutcome::Aborted => break,
            ScanOutcome::Reconfigure => {
                wizard::run_setup(None).await?;
            }
            ScanOutcome::ExitApp => std::process::exit(0),
        }
    }
    Ok(())
}

async fn run_once(
    provider_override: Option<String>,
    scanners: Vec<ScannerType>,
    depth: HistoryDepth,
) -> Result<ScanOutcome> {
    let global = GlobalConfig::load()?;
    let profile_name = provider_override
        .or_else(|| global.default_profile.clone())
        .ok_or_else(|| {
            anyhow::anyhow!("No provider configured. Run 'zentra config setup' first.")
        })?;

    let profile = global
        .profiles
        .get(&profile_name)
        .ok_or_else(|| anyhow::anyhow!("Profile '{}' not found", profile_name))?
        .clone();

    let api_key = match profile.auth_method {
        crate::config::AuthMethod::OAuth => {
            crate::auth::ensure_fresh_token(&profile_name).await?
        }
        crate::config::AuthMethod::ApiKey => {
            if profile.keyless {
                keychain::get_key(&profile_name)?.unwrap_or_default()
            } else {
                keychain::get_key(&profile_name)?.ok_or_else(|| {
                    anyhow::anyhow!(
                        "No API key found for profile '{}'. Run 'zentra config setup' to configure it.",
                        profile_name
                    )
                })?
            }
        }
    };

    let provider: Arc<dyn LLMProvider> = match profile.kind.as_str() {
        "anthropic" => Arc::new(AnthropicProvider::new(
            profile.base_url.clone(),
            profile.model.clone(),
            api_key,
        )),
        _ => Arc::new(OpenAICompatProvider::new(
            profile.base_url.clone(),
            profile.model.clone(),
            api_key,
        )),
    };

    let project_config = ProjectConfig::load_from(&ProjectConfig::default_path())
        .context("No project config found. Run 'zentra init' first.")?;

    let state_writer = Arc::new(
        StateWriter::new(Path::new(&project_config.target_path))
            .context("Failed to initialize .zentra/ directory")?,
    );
    let tool_registry = Arc::new(ToolRegistry::new());

    let context_window = profile.context_window.unwrap_or_else(|| provider.context_window());
    let model_info = format!("{} · {}", profile.model, profile_name);

    let (tx, rx) = mpsc::channel(128);
    let scanners_for_agent = scanners.clone();

    let scan_task = tokio::spawn(async move {
        OrchestratorAgent::new(provider, tool_registry, state_writer, tx, depth)
            .run(&scanners_for_agent)
            .await
    });

    let outcome = run_scan_ui(rx, scanners, model_info, context_window).await?;

    match outcome {
        ScanOutcome::Completed => {
            scan_task.await??;
            println!("\n✓ Scan complete. Findings in .zentra/");
        }
        _ => {
            scan_task.abort();
        }
    }

    Ok(outcome)
}

fn resolve_scanners(only: Option<&str>) -> Vec<ScannerType> {
    match only {
        Some("threat-model") => vec![ScannerType::ThreatModel, ScannerType::Report],
        Some("sast") => vec![ScannerType::Sast, ScannerType::Report],
        Some("supply-chain") => vec![ScannerType::SupplyChain, ScannerType::Report],
        Some("api") => vec![ScannerType::ApiScan, ScannerType::Report],
        Some("iac") => vec![ScannerType::IacScan, ScannerType::Report],
        Some("secrets") => vec![ScannerType::SecretsScan],
        Some("report") => vec![ScannerType::Report],
        _ => vec![
            ScannerType::ThreatModel,
            ScannerType::Sast,
            ScannerType::SupplyChain,
            ScannerType::ApiScan,
            ScannerType::IacScan,
            ScannerType::SecretsScan,
            ScannerType::Report,
        ],
    }
}
```

> Note: `run()` now takes `depth_str: String`. Step 5 updates `main.rs` to pass it.

- [ ] **Step 5: Update `src/main.rs` to pass a temporary default depth to `commands::scan::run`**

In `main.rs`, change the Scan dispatch line from:

```rust
        Some(cli::Commands::Scan { provider, only }) => {
            commands::scan::run(provider, only).await?
        }
```

to:

```rust
        Some(cli::Commands::Scan { provider, only }) => {
            commands::scan::run(provider, only, "50".to_string()).await?
        }
```

(The CLI `--depth` arg is wired in Task 9 — this keeps it compiling now.)

- [ ] **Step 6: Verify build succeeds**

```bash
cargo build 2>&1 | head -40
```

Expected: no errors.

- [ ] **Step 7: Run all tests**

```bash
cargo test 2>&1 | tail -30
```

Expected: all existing tests pass plus new secrets tests.

- [ ] **Step 8: Commit**

```bash
git add src/state/mod.rs src/agent/orchestrator.rs src/tools/mod.rs src/commands/scan.rs src/main.rs
git commit -m "feat: wire SecretsScan into orchestrator parallel phase and add scan_secrets tool"
```

---

## Task 9: CLI `--depth` Flag

**Files:**
- Modify: `src/cli/mod.rs` — add `--depth` arg to `Scan`
- Modify: `src/main.rs` — pass `depth` from parsed CLI to `commands::scan::run`

- [ ] **Step 1: Write failing test for CLI depth parsing**

In `src/cli/mod.rs`, add these tests to the existing `#[cfg(test)]` block:

```rust
    #[test]
    fn parses_scan_with_depth_number() {
        let cli = Cli::try_parse_from(["zentra", "scan", "--depth", "25"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Scan { depth: ref d, .. }) if d == "25"
        ));
    }

    #[test]
    fn parses_scan_with_depth_all() {
        let cli = Cli::try_parse_from(["zentra", "scan", "--depth", "all"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Scan { depth: ref d, .. }) if d == "all"
        ));
    }

    #[test]
    fn scan_depth_defaults_to_50() {
        let cli = Cli::try_parse_from(["zentra", "scan"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Scan { depth: ref d, .. }) if d == "50"
        ));
    }
```

- [ ] **Step 2: Run to verify they fail**

```bash
cargo test --lib cli 2>&1 | head -20
```

Expected: compile error — `depth` field doesn't exist on `Scan` variant yet.

- [ ] **Step 3: Add `--depth` to CLI**

Replace `src/cli/mod.rs` entirely:

```rust
// src/cli/mod.rs
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "zentra", version, about = "AI-powered Application Security")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize .zentra/ in the current project
    Init,
    /// Manage LLM provider configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Run security scan
    Scan {
        /// Run only a specific scanner (threat-model, sast, supply-chain, api, iac, secrets, report)
        #[arg(long)]
        only: Option<String>,
        /// Override the default provider profile for this scan
        #[arg(long)]
        provider: Option<String>,
        /// Git history depth for secrets scan: a number or 'all' [default: 50]
        #[arg(long, default_value = "50")]
        depth: String,
    },
    /// Upgrade zentra to the latest release
    Update,
}

#[derive(Subcommand, Debug)]
pub enum ConfigAction {
    /// Run first-time setup wizard
    Setup,
    /// Add a new provider profile
    Add,
    /// List all configured provider profiles
    List,
    /// Set the default provider profile
    Use { name: String },
    /// Show the active profile details
    Show,
    /// Remove a provider profile and its stored key
    Remove { name: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_init_command() {
        let cli = Cli::try_parse_from(["zentra", "init"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Init)));
    }

    #[test]
    fn parses_config_setup() {
        let cli = Cli::try_parse_from(["zentra", "config", "setup"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Config { action: ConfigAction::Setup })
        ));
    }

    #[test]
    fn parses_scan_with_only_flag() {
        let cli = Cli::try_parse_from(["zentra", "scan", "--only", "sast"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Scan { only: Some(ref s), .. }) if s == "sast"
        ));
    }

    #[test]
    fn parses_no_args_as_none() {
        let cli = Cli::try_parse_from(["zentra"]).unwrap();
        assert!(cli.command.is_none());
    }

    #[test]
    fn parses_scan_with_depth_number() {
        let cli = Cli::try_parse_from(["zentra", "scan", "--depth", "25"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Scan { ref depth, .. }) if depth == "25"
        ));
    }

    #[test]
    fn parses_scan_with_depth_all() {
        let cli = Cli::try_parse_from(["zentra", "scan", "--depth", "all"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Scan { ref depth, .. }) if depth == "all"
        ));
    }

    #[test]
    fn scan_depth_defaults_to_50() {
        let cli = Cli::try_parse_from(["zentra", "scan"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Scan { ref depth, .. }) if depth == "50"
        ));
    }
}
```

- [ ] **Step 4: Update `src/main.rs` to pass depth from CLI**

Replace the Scan dispatch arm in main.rs (only the relevant match arm — the full file is shown for clarity):

```rust
// src/main.rs — full file
use clap::Parser;
use zentra_cli::{
    cli, commands,
    config::{GlobalConfig, ProjectConfig},
    tui::menu::{run_menu, MenuAction},
    wizard,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::args().len() == 1 {
        let provider_configured = GlobalConfig::is_configured();
        let project_configured = ProjectConfig::load_from(&ProjectConfig::default_path()).is_ok();

        loop {
            match run_menu(provider_configured, project_configured).await? {
                MenuAction::RunScan(scanners) => {
                    commands::scan::run_with_scanners(scanners).await?;
                    break;
                }
                MenuAction::ViewLastResults => {
                    zentra_cli::tui::results::run_results().await?;
                }
                MenuAction::Config => {
                    wizard::run_setup(None).await?;
                    break;
                }
                MenuAction::Exit => break,
            }
        }
        return Ok(());
    }

    let cli = cli::Cli::parse();
    match cli.command {
        None => unreachable!(),
        Some(cli::Commands::Init) => commands::init::run().await?,
        Some(cli::Commands::Config { action }) => match action {
            cli::ConfigAction::Setup => wizard::run_setup(None).await?,
            cli::ConfigAction::Add => wizard::run_setup(None).await?,
            cli::ConfigAction::List => commands::config::list().await?,
            cli::ConfigAction::Use { name } => commands::config::use_profile(&name).await?,
            cli::ConfigAction::Show => commands::config::show().await?,
            cli::ConfigAction::Remove { name } => commands::config::remove(&name).await?,
        },
        Some(cli::Commands::Scan { provider, only, depth }) => {
            commands::scan::run(provider, only, depth).await?
        }
        Some(cli::Commands::Update) => {
            eprintln!("zentra update — available in Plan 4 (install + CI)");
            std::process::exit(1);
        }
    }
    Ok(())
}
```

- [ ] **Step 5: Run CLI tests**

```bash
cargo test --lib cli 2>&1
```

Expected: all 7 CLI tests pass (4 original + 3 new depth tests).

- [ ] **Step 6: Run full test suite**

```bash
cargo test 2>&1 | tail -20
```

Expected: all tests pass.

- [ ] **Step 7: Smoke test the binary compiles and help shows `--depth`**

```bash
cargo build --release 2>&1 | tail -5
```

Expected: `Compiling zentra-cli ...` → `Finished release ...` with no errors.

- [ ] **Step 8: Commit**

```bash
git add src/cli/mod.rs src/main.rs
git commit -m "feat: add --depth flag to zentra scan for configurable git history depth"
```

---

## Self-Review

**Spec coverage check:**

| Spec requirement | Covered by |
|---|---|
| `src/scanners/secrets/` module with 8 files | Tasks 1–7 |
| `SecretsMatch` struct | Task 1 mod.rs |
| `HistoryDepth::Last(N)` / `All` | Task 1 mod.rs |
| ~50 regex patterns grouped by provider | Task 1 patterns.rs (~40 patterns) |
| Shannon entropy analysis, 3 classes, thresholds | Task 2 entropy.rs |
| `ContextValidator` with 6 suppression rules | Task 4 validator.rs |
| Git history crawler, `+` lines only, `max_count` | Task 5 git_history.rs |
| Dual-mode output (MD+JSON scanner / JSON tool) | Task 6 report.rs |
| `ScannerType::SecretsScan` | Task 1 agent/mod.rs |
| Non-LLM orchestrator dispatch | Task 8 orchestrator.rs |
| `scan_secrets` LLM tool (capped JSON, no raw values) | Task 8 tools/mod.rs |
| `.zentra/secrets-allowlist.toml` | Task 3 allowlist.rs |
| Inline annotation `# zentra:ignore` | Task 4 validator.rs rule 3 |
| `--depth` CLI flag | Task 9 cli/mod.rs |
| `--only secrets` standalone | Task 8 scan.rs resolve_scanners |
| `.zentraignore` stub | Out of scope (separate plan) — not implemented |
| Error handling (git unavailable, missing allowlist, IO errors) | engine.rs + git_history.rs |

**Type consistency:**
- `SecretsMatch` defined in `mod.rs` — used by all 7 sub-modules as `super::SecretsMatch` ✓
- `HistoryDepth` defined in `mod.rs` — used in orchestrator, git_history, engine, commands/scan ✓
- `DetectorPattern` defined in `patterns.rs` — used by engine + git_history as `patterns::DetectorPattern` ✓
- `ContextValidator<'a>` defined in `validator.rs` — takes `&'a Allowlist` lifetime, used in engine + git_history ✓
- `SecretScanner::new(root, depth, tx)` defined in engine.rs, dispatched in orchestrator with same args ✓

**Placeholder scan:** No TBD, TODO, or "similar to" shortcuts present.
