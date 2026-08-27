use crate::agent::ScannerType;
use crate::scanners;
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::time::Instant;

/// Per-scanner gate. All blocks are non-fatal at the call site: a blocked call
/// returns an error string to the LLM and the scan continues. This keeps a false
/// positive from killing an otherwise-valid scan while still denying the action.
pub struct SecurityGate {
    profile: ToolProfile,
    rate_limiter: RateLimiter,
    state_machine: ToolStateMachine,
    arg_validator: ArgValidator,
    pub enabled: bool,
}

/// The capability set a gate applies to. Chat is deliberately not represented
/// as a scanner: scanner allowlists include write and process tools which must
/// never become available to the interactive read-only path.
#[derive(Clone, Copy)]
enum ToolProfile {
    Scanner(ScannerType),
    Chat,
}

/// The complete, closed read-only capability set for scan chat.
pub const CHAT_ALLOWED_TOOLS: &[&str] = &[
    "list_files",
    "read_file",
    "grep_code",
    "git_log",
    "git_diff",
    "git_blame",
    "git_status",
];

impl SecurityGate {
    pub fn new(scanner: ScannerType, enabled: bool) -> Self {
        Self {
            profile: ToolProfile::Scanner(scanner),
            rate_limiter: RateLimiter::new(),
            state_machine: ToolStateMachine::new(),
            arg_validator: ArgValidator,
            enabled,
        }
    }

    /// Create the least-privilege gate used by the interactive scan chat.
    /// This is separate from scanner policy so no fake `ScannerType` can inherit
    /// scanner write or process capabilities.
    pub fn chat(enabled: bool) -> Self {
        Self {
            profile: ToolProfile::Chat,
            rate_limiter: RateLimiter::new(),
            state_machine: ToolStateMachine::new(),
            arg_validator: ArgValidator,
            enabled,
        }
    }

    /// Returns `Err` if this individual tool call should be blocked.
    pub fn check(&mut self, name: &str, args: &serde_json::Value) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        self.check_allowlist(name)?;
        self.rate_limiter.check(name)?;
        self.state_machine.check(name, args)?;
        self.arg_validator.validate(name, args)?;
        Ok(())
    }

    fn check_allowlist(&self, tool: &str) -> Result<()> {
        match self.profile {
            ToolProfile::Scanner(scanner) => {
                let allowed = scanners::allowed_tools(scanner);
                if !allowed.contains(&tool) {
                    bail!(
                        "Tool '{}' is not permitted for scanner '{}'",
                        tool,
                        scanner.name()
                    );
                }
            }
            ToolProfile::Chat if !CHAT_ALLOWED_TOOLS.contains(&tool) => {
                bail!(
                    "Tool '{}' is not permitted for the read-only chat profile",
                    tool
                );
            }
            ToolProfile::Chat => {}
        }
        Ok(())
    }
}

// ── Rate limiter ────────────────────────────────────────────────────────────
// Limits are generous: a thorough SAST scan legitimately reads dozens of files.
// The goal is only to cap the blast radius of a true runaway, not to throttle
// normal work.

struct RateLimiter {
    window_start: Instant,
    calls_in_window: u32,
    per_tool: HashMap<String, u32>,
}

const WINDOW_SECS: u64 = 60;
const MAX_PER_WINDOW: u32 = 250;
const MAX_PER_TOOL: u32 = 120;

impl RateLimiter {
    fn new() -> Self {
        Self {
            window_start: Instant::now(),
            calls_in_window: 0,
            per_tool: HashMap::new(),
        }
    }

    fn check(&mut self, tool: &str) -> Result<()> {
        if self.window_start.elapsed().as_secs() > WINDOW_SECS {
            self.window_start = Instant::now();
            self.calls_in_window = 0;
            self.per_tool.clear();
        }

        self.calls_in_window += 1;
        if self.calls_in_window > MAX_PER_WINDOW {
            bail!(
                "Tool call rate limit exceeded ({} calls / {}s window)",
                MAX_PER_WINDOW,
                WINDOW_SECS
            );
        }

        let count = self.per_tool.entry(tool.to_string()).or_insert(0);
        *count += 1;
        if *count > MAX_PER_TOOL {
            bail!(
                "'{}' called too frequently ({} times this window)",
                tool,
                count
            );
        }

        Ok(())
    }
}

// ── State machine ────────────────────────────────────────────────────────────
// Behavioral checks. A runaway loop repeats the *identical* call (same tool AND
// same arguments); reading many distinct files in a row is normal and allowed.

struct ToolStateMachine {
    any_read: bool,
    last_fingerprint: String,
    consecutive_identical: u32,
}

const CONSECUTIVE_IDENTICAL_LIMIT: u32 = 5;

impl ToolStateMachine {
    fn new() -> Self {
        Self {
            any_read: false,
            last_fingerprint: String::new(),
            consecutive_identical: 0,
        }
    }

    fn check(&mut self, tool: &str, args: &serde_json::Value) -> Result<()> {
        let fingerprint = format!("{}:{}", tool, args);
        if fingerprint == self.last_fingerprint {
            self.consecutive_identical += 1;
        } else {
            self.last_fingerprint = fingerprint;
            self.consecutive_identical = 1;
        }
        if self.consecutive_identical > CONSECUTIVE_IDENTICAL_LIMIT {
            bail!(
                "Identical '{}' call repeated {} times — possible runaway loop",
                tool,
                self.consecutive_identical
            );
        }

        if is_read_tool(tool) {
            self.any_read = true;
        }

        // Recording a finding before any evidence was gathered is a classic
        // sign of an injected/fabricated result.
        if tool == "write_finding" && !self.any_read {
            bail!("write_finding called before any file was read — no evidence gathered");
        }

        Ok(())
    }
}

fn is_read_tool(tool: &str) -> bool {
    matches!(
        tool,
        "read_file"
            | "grep_code"
            | "list_files"
            | "git_log"
            | "git_diff"
            | "git_blame"
            | "git_status"
            | "run_audit"
    )
}

// ── Argument validator ───────────────────────────────────────────────────────
// Always-on, zero-false-positive checks: these never trigger on legitimate scan
// behavior because no scanner has a reason to touch these paths.

struct ArgValidator;

const SENSITIVE_PATH_FRAGMENTS: &[&str] = &[
    ".env",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    "/.ssh",
    ".ssh/",
    ".aws",
    ".gnupg",
    "shadow",
    "/etc/passwd",
    ".netrc",
    "htpasswd",
    ".npmrc",
    ".pypirc",
];

impl ArgValidator {
    fn validate(&self, tool: &str, args: &serde_json::Value) -> Result<()> {
        match tool {
            "read_file" => self.validate_path(args["path"].as_str().unwrap_or(""))?,
            "list_files" => self.validate_path(args["dir"].as_str().unwrap_or("."))?,
            "grep_code" => {
                let pattern = args["pattern"].as_str().unwrap_or("");
                if pattern.len() > 500 {
                    bail!("Regex pattern too long ({} chars, max 500)", pattern.len());
                }
                if let Some(path) = args["path"].as_str() {
                    self.validate_path(path)?;
                }
            }
            "git_diff" => {
                let since = args["since"].as_str().unwrap_or("");
                if since.len() > 100 {
                    bail!("git_diff 'since' argument too long");
                }
                if since
                    .chars()
                    .any(|c| matches!(c, ';' | '|' | '&' | '$' | '`' | '\n' | '\r' | '(' | ')'))
                {
                    bail!("git_diff 'since' argument contains disallowed characters");
                }
            }
            "git_blame" => self.validate_path(args["file"].as_str().unwrap_or(""))?,
            "write_finding" => {
                let title = args["title"].as_str().unwrap_or("");
                if title.len() > 200 {
                    bail!("Finding title too long ({} chars, max 200)", title.len());
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn validate_path(&self, path: &str) -> Result<()> {
        if std::path::Path::new(path)
            .components()
            .any(|c| c == std::path::Component::ParentDir)
        {
            bail!("Path '{}' contains a '..' component", path);
        }
        let lower = path.to_lowercase().replace('\\', "/");
        for fragment in SENSITIVE_PATH_FRAGMENTS {
            if lower.contains(fragment) {
                bail!("Path '{}' references a sensitive file or directory", path);
            }
        }
        let components = std::path::Path::new(path).components().count();
        if components > 12 {
            bail!(
                "Path '{}' has too many components ({}, max 12)",
                path,
                components
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sast_gate() -> SecurityGate {
        SecurityGate::new(ScannerType::Sast, true)
    }

    #[test]
    fn blocks_tool_outside_scanner_allowlist() {
        let mut gate = sast_gate();
        // browser_navigate is a pentest tool, never allowed for SAST.
        assert!(gate.check("browser_navigate", &json!({})).is_err());
    }

    #[test]
    fn allows_normal_read_sequence() {
        let mut gate = sast_gate();
        assert!(gate.check("list_files", &json!({"dir": "."})).is_ok());
        for f in ["a.rs", "b.rs", "c.rs", "d.rs", "e.rs", "f.rs", "g.rs"] {
            assert!(gate.check("read_file", &json!({"path": f})).is_ok());
        }
    }

    #[test]
    fn blocks_identical_call_loop() {
        let mut gate = sast_gate();
        gate.check("list_files", &json!({"dir": "."})).unwrap();
        let args = json!({"path": "same.rs"});
        for _ in 0..CONSECUTIVE_IDENTICAL_LIMIT {
            assert!(gate.check("read_file", &args).is_ok());
        }
        assert!(gate.check("read_file", &args).is_err());
    }

    #[test]
    fn blocks_sensitive_paths() {
        let mut gate = sast_gate();
        gate.check("list_files", &json!({"dir": "."})).unwrap();
        assert!(gate.check("read_file", &json!({"path": ".env"})).is_err());
        assert!(gate
            .check("read_file", &json!({"path": "../../.ssh/id_rsa"}))
            .is_err());
        // ~/.aws/credentials is blocked via the ".aws" fragment...
        assert!(gate
            .check("read_file", &json!({"path": "home/user/.aws/credentials"}))
            .is_err());
        // ...and package registry tokens via ".npmrc".
        assert!(gate
            .check("read_file", &json!({"path": "../.npmrc"}))
            .is_err());
        // But a source file that merely contains the word "credentials" is fine —
        // SAST scanners legitimately read these.
        assert!(gate
            .check("read_file", &json!({"path": "src/auth/credentials.rs"}))
            .is_ok());
    }

    #[test]
    fn blocks_finding_before_any_read() {
        let mut gate = sast_gate();
        assert!(gate
            .check("write_finding", &json!({"title": "x", "severity": "high"}))
            .is_err());
    }

    #[test]
    fn disabled_gate_allows_everything() {
        let mut gate = SecurityGate::new(ScannerType::Sast, false);
        assert!(gate.check("browser_navigate", &json!({})).is_ok());
        assert!(gate.check("read_file", &json!({"path": ".env"})).is_ok());
    }

    #[test]
    fn chat_gate_allows_exactly_the_read_only_profile() {
        let mut gate = SecurityGate::chat(true);
        for tool in CHAT_ALLOWED_TOOLS {
            assert!(
                gate.check(tool, &json!({})).is_ok(),
                "{tool} should be allowed"
            );
        }
        for tool in [
            "run_audit",
            "write_finding",
            "write_report",
            "write_architecture",
            "shell_exec",
        ] {
            assert!(
                gate.check(tool, &json!({})).is_err(),
                "{tool} should be blocked"
            );
        }
    }

    #[test]
    fn chat_gate_retains_path_and_git_ref_validation() {
        let mut gate = SecurityGate::chat(true);
        assert!(gate
            .check("read_file", &json!({"path": "../outside.rs"}))
            .is_err());
        assert!(gate
            .check("git_diff", &json!({"since": "HEAD;rm -rf /"}))
            .is_err());
        assert!(gate
            .check("git_blame", &json!({"file": "../outside.rs", "line": 1}))
            .is_err());
    }
}
