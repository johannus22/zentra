pub mod audit;
pub mod fs_tools;
pub mod git_tools;

use crate::agent::{ScanEvent, ScannerType};
use crate::provider::ToolDefinition;
use crate::security::tool_gate::CHAT_ALLOWED_TOOLS;
use crate::state::{Finding, Severity, StateWriter};
use tokio::sync::mpsc;

pub struct ToolRegistry {
    /// What the agents actually read. Phase 2 shares one registry across four
    /// runtime threads, so the ledger carries its own lock. `dispatch` records
    /// here rather than in the scanner loop, which keeps the outcome and the
    /// agent-visible string from ever diverging.
    coverage: std::sync::Mutex<crate::agent::coverage::CoverageLedger>,
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            coverage: std::sync::Mutex::new(crate::agent::coverage::CoverageLedger::default()),
        }
    }

    /// A snapshot of what the agents read this run.
    ///
    /// Poison-tolerant, like `StateWriter::findings_lock`: the guarded value is a
    /// set of counters with no cross-field invariant, so recovering the guard is
    /// safer than turning one panicked scanner into a failed run.
    pub fn coverage_snapshot(
        &self,
        candidate_count: usize,
    ) -> crate::agent::coverage::CoverageSummary {
        match self.coverage.lock() {
            Ok(guard) => guard.summary(candidate_count),
            Err(poisoned) => poisoned.into_inner().summary(candidate_count),
        }
    }

    /// Candidate files that no scanner read this run.
    pub fn never_read_snapshot(&self, candidates: &[String]) -> Vec<String> {
        match self.coverage.lock() {
            Ok(guard) => guard.never_read(candidates),
            Err(poisoned) => poisoned.into_inner().never_read(candidates),
        }
    }

    /// The outcome of the most recent read of `path` by `scanner`. The scanner
    /// loop uses this to emit `ScanEvent::FileRead` without parsing the result
    /// string it just handed to the model.
    pub fn last_outcome_for(
        &self,
        scanner: ScannerType,
        path: &str,
    ) -> Option<crate::tools::fs_tools::ReadOutcome> {
        match self.coverage.lock() {
            Ok(guard) => guard.last_outcome_for(scanner, path),
            Err(poisoned) => poisoned.into_inner().last_outcome_for(scanner, path),
        }
    }

    fn record_read(
        &self,
        scanner: ScannerType,
        path: &str,
        outcome: crate::tools::fs_tools::ReadOutcome,
    ) {
        match self.coverage.lock() {
            Ok(mut guard) => guard.record_read(scanner, path, outcome),
            Err(poisoned) => poisoned.into_inner().record_read(scanner, path, outcome),
        }
    }

    fn record_listing(&self, scanner: ScannerType) {
        match self.coverage.lock() {
            Ok(mut guard) => guard.record_listing(scanner),
            Err(poisoned) => poisoned.into_inner().record_listing(scanner),
        }
    }

    fn record_search(&self, scanner: ScannerType) {
        match self.coverage.lock() {
            Ok(mut guard) => guard.record_search(scanner),
            Err(poisoned) => poisoned.into_inner().record_search(scanner),
        }
    }

    pub fn definitions(&self) -> Vec<ToolDefinition> {
        vec![
            ToolDefinition {
                name: "read_file".to_string(),
                description: "Read the contents of a file. Returns file contents or an error.".to_string(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Path to the file to read"}
                    },
                    "required": ["path"]
                }),
            },
            ToolDefinition {
                name: "list_files".to_string(),
                description: "List files in a directory, respecting .gitignore. Returns newline-separated paths.".to_string(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "dir": {"type": "string", "description": "Directory to list. Use '.' for project root."},
                        "pattern": {"type": "string", "description": "Optional substring to filter file paths"}
                    },
                    "required": ["dir"]
                }),
            },
            ToolDefinition {
                name: "grep_code".to_string(),
                description: "Regex search across source files. Returns matching lines with file:line context.".to_string(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string", "description": "Regex pattern to search for"},
                        "path": {"type": "string", "description": "Optional directory to restrict search to"}
                    },
                    "required": ["pattern"]
                }),
            },
            ToolDefinition {
                name: "write_finding".to_string(),
                description: "Record a security finding. Writes to .zentra/detailed-findings.md and notifies the UI.".to_string(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "severity": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low", "info"],
                            "description": "Finding severity"
                        },
                        "title": {"type": "string", "description": "Short finding title (under 80 chars)"},
                        "description": {"type": "string", "description": "What the vulnerability is and where it occurs. Use short, plain, active-voice sentences."},
                        "location": {"type": "string", "description": "File and line, for example src/auth.rs:42"},
                        "recommendation": {"type": "string", "description": "The concrete fix, written as a short, direct instruction."},
                        "cwe": {"type": "string", "description": "Primary CWE id, for example CWE-89"},
                        "secondary_cwe": {"type": "array", "items": {"type": "string"}, "description": "Additional related CWE ids, for example [\"CWE-20\"]"},
                        "cvss_vector": {"type": "string", "description": "CVSS v3.1 base vector, for example CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (provide the vector, not a score)"},
                        "owasp": {"type": "string", "description": "OWASP Top 10 category, for example A03:2021-Injection"}
                    },
                    "required": ["severity", "title", "description", "recommendation"]
                }),
            },
            ToolDefinition {
                name: "write_report".to_string(),
                description: "Write the final markdown report to .zentra/reports/YYYYMMDD-report.md.".to_string(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "content": {
                            "type": "string",
                            "description": "Full markdown report content"
                        }
                    },
                    "required": ["content"]
                }),
            },
            ToolDefinition {
                name: "run_audit".to_string(),
                description: "Run a dependency audit tool. Returns JSON audit results or a fallback message.".to_string(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "tool": {
                            "type": "string",
                            "enum": ["npm", "cargo", "pip", "go"],
                            "description": "Which audit tool to run"
                        }
                    },
                    "required": ["tool"]
                }),
            },
            ToolDefinition {
                name: "git_log".to_string(),
                description: "Get recent git commit history (oneline format).".to_string(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "n": {"type": "integer", "description": "Number of commits to return (default 10)"}
                    },
                    "required": []
                }),
            },
            ToolDefinition {
                name: "git_diff".to_string(),
                description: "Get git diff --stat since a commit or tag.".to_string(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "since": {"type": "string", "description": "Commit hash or tag to diff from"}
                    },
                    "required": ["since"]
                }),
            },
            ToolDefinition {
                name: "git_blame".to_string(),
                description: "Get git blame for a specific file and line number.".to_string(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "file": {"type": "string"},
                        "line": {"type": "integer", "description": "Line number to blame"}
                    },
                    "required": ["file", "line"]
                }),
            },
            ToolDefinition {
                name: "git_status".to_string(),
                description: "Get current git status (modified/untracked files).".to_string(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {},
                    "required": []
                }),
            },
            ToolDefinition {
                name: "write_architecture".to_string(),
                description: "Write the full framework and tech-stack analysis to \
.zentra/architecture.md. Call once with the complete analysis. Other scanners will read this \
document to calibrate their findings and avoid false positives.".to_string(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "content": {
                            "type": "string",
                            "description": "Full markdown analysis of the tech stack, frameworks, \
data entry points, security middleware already present, and known safety guarantees"
                        }
                    },
                    "required": ["content"]
                }),
            },
        ]
    }

    /// Definitions exposed to interactive scan chat. This intentionally filters
    /// the registry's actual definitions instead of maintaining a second list:
    /// a chat capability is unavailable until its implementation is registered.
    pub fn chat_definitions(&self) -> Vec<ToolDefinition> {
        let definitions = self.definitions();
        CHAT_ALLOWED_TOOLS
            .iter()
            .filter_map(|name| definitions.iter().find(|tool| tool.name == *name).cloned())
            .collect()
    }

    /// Run one chat read-only tool call. Chat callers must first pass the call
    /// through `SecurityGate::chat`; this method is the registry boundary that
    /// additionally makes unregistered and non-chat tools unavailable. It has
    /// no `StateWriter`, event sender, or scanner identity, and deliberately
    /// does not update scanner coverage.
    pub async fn dispatch_chat(&self, name: &str, args: &serde_json::Value) -> String {
        if !CHAT_ALLOWED_TOOLS.contains(&name) {
            return format!(
                "Chat tool '{}' is not permitted by the read-only profile",
                name
            );
        }
        if !self.definitions().iter().any(|tool| tool.name == name) {
            return format!("Chat tool '{}' is not registered", name);
        }
        // Every name in CHAT_ALLOWED_TOOLS is handled above. Keep this explicit
        // fallback in case a future profile entry is added without a registry
        // implementation.
        self.dispatch_read_only(name, args)
            .map(|(body, _)| body)
            .unwrap_or_else(|| format!("Chat tool '{}' is unavailable", name))
    }

    /// Execute the shared filesystem/git implementations without scanner
    /// accounting. Scanner dispatch records coverage around this helper; chat
    /// dispatch uses it directly so chat exploration cannot affect scan output.
    fn dispatch_read_only(
        &self,
        name: &str,
        args: &serde_json::Value,
    ) -> Option<(String, Option<fs_tools::ReadOutcome>)> {
        match name {
            "read_file" => {
                let (body, outcome) =
                    fs_tools::read_file_with_outcome(args["path"].as_str().unwrap_or(""));
                Some((body, Some(outcome)))
            }
            "list_files" => Some((
                fs_tools::list_files(
                    args["dir"].as_str().unwrap_or("."),
                    args["pattern"].as_str(),
                ),
                None,
            )),
            "grep_code" => Some((
                fs_tools::grep_code(
                    args["pattern"].as_str().unwrap_or(""),
                    args["path"].as_str(),
                ),
                None,
            )),
            "git_log" => Some((
                git_tools::git_log(args["n"].as_u64().unwrap_or(10) as u32),
                None,
            )),
            "git_diff" => Some((
                git_tools::git_diff(args["since"].as_str().unwrap_or("HEAD~1")),
                None,
            )),
            "git_blame" => Some((
                git_tools::git_blame(
                    args["file"].as_str().unwrap_or(""),
                    args["line"].as_u64().unwrap_or(1) as u32,
                ),
                None,
            )),
            "git_status" => Some((git_tools::git_status(), None)),
            _ => None,
        }
    }

    pub async fn dispatch(
        &self,
        name: &str,
        args: &serde_json::Value,
        state_writer: &StateWriter,
        tx: &mpsc::Sender<ScanEvent>,
        scanner: ScannerType,
    ) -> String {
        match name {
            "read_file" => {
                let path = args["path"].as_str().unwrap_or("");
                let (body, outcome) = self
                    .dispatch_read_only(name, args)
                    .expect("read_file is a registered read-only tool");
                self.record_read(
                    scanner,
                    path,
                    outcome.expect("read_file returns a coverage outcome"),
                );
                body
            }
            "list_files" => {
                self.record_listing(scanner);
                self.dispatch_read_only(name, args)
                    .expect("list_files is a registered read-only tool")
                    .0
            }
            "grep_code" => {
                self.record_search(scanner);
                self.dispatch_read_only(name, args)
                    .expect("grep_code is a registered read-only tool")
                    .0
            }
            "write_finding" => {
                let severity = parse_severity(args["severity"].as_str().unwrap_or("info"));

                // Validate CWE ids: keep only well-formed "CWE-<digits>".
                let is_cwe = |s: &str| {
                    s.strip_prefix("CWE-")
                        .map(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
                        .unwrap_or(false)
                };
                let cwe = args["cwe"]
                    .as_str()
                    .map(str::trim)
                    .filter(|s| is_cwe(s))
                    .map(str::to_string);
                let secondary_cwe: Vec<String> = args["secondary_cwe"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str())
                            .map(str::trim)
                            .filter(|s| is_cwe(s))
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();

                // CVSS: compute the score ourselves; keep the vector only if it parsed.
                let (cvss_vector, cvss_score) = match args["cvss_vector"].as_str() {
                    Some(v) => match crate::state::cvss::compute_base_score(v) {
                        Some((score, _)) => (Some(v.to_string()), Some(score)),
                        None => (None, None),
                    },
                    None => (None, None),
                };

                let owasp = args["owasp"]
                    .as_str()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);

                let finding = Finding {
                    scanner: scanner.name().to_string(),
                    severity,
                    title: args["title"]
                        .as_str()
                        .unwrap_or("Untitled Finding")
                        .to_string(),
                    description: args["description"].as_str().unwrap_or("").to_string(),
                    location: args["location"].as_str().map(str::to_string),
                    recommendation: args["recommendation"].as_str().unwrap_or("").to_string(),
                    corroborated_by: Vec::new(),
                    cwe,
                    secondary_cwe,
                    cvss_vector,
                    cvss_score,
                    owasp,
                    // Screening belongs to the audit pass. A scanner grading its
                    // own finding is not evidence, so `write_finding` cannot set
                    // these and the tool schema does not expose them.
                    confidence: None,
                    screening: None,
                    evidence: None,
                };
                if let Err(e) = state_writer.write_finding(&finding) {
                    return format!("Error writing finding: {}", e);
                }
                tx.send(ScanEvent::FindingAdded(finding)).await.ok();
                "Finding recorded.".to_string()
            }
            "write_report" => {
                let content = args["content"].as_str().unwrap_or("");
                match state_writer.write_report(content) {
                    Ok(_) => "Report written to .zentra/reports.".to_string(),
                    Err(e) => format!("Error writing report: {}", e),
                }
            }
            "run_audit" => {
                let tool = args["tool"].as_str().unwrap_or("npm");
                audit::run_audit(tool)
            }
            "git_log" | "git_diff" | "git_blame" | "git_status" => {
                self.dispatch_read_only(name, args)
                    .expect("git tool is a registered read-only tool")
                    .0
            }
            "write_architecture" => {
                let content = args["content"].as_str().unwrap_or("");
                match state_writer.write_architecture(content) {
                    Ok(_) => "Architecture written to .zentra/architecture.md.".to_string(),
                    Err(e) => format!("Error writing architecture: {}", e),
                }
            }
            unknown => format!("Unknown tool: '{}'", unknown),
        }
    }
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" | "med" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::ScannerType;
    use serde_json::json;

    #[test]
    fn chat_definitions_are_the_exact_read_only_profile() {
        let registry = ToolRegistry::new();
        let names: Vec<_> = registry
            .chat_definitions()
            .into_iter()
            .map(|tool| tool.name)
            .collect();
        assert_eq!(names, CHAT_ALLOWED_TOOLS);
    }

    #[tokio::test]
    async fn chat_dispatch_rejects_every_non_chat_registry_tool() {
        let registry = ToolRegistry::new();
        for tool in registry.definitions() {
            if !CHAT_ALLOWED_TOOLS.contains(&tool.name.as_str()) {
                let result = registry.dispatch_chat(&tool.name, &json!({})).await;
                assert!(
                    result.contains("not permitted"),
                    "{} unexpectedly dispatched: {result}",
                    tool.name
                );
            }
        }
        assert!(registry
            .dispatch_chat("process_exec", &json!({}))
            .await
            .contains("not permitted"));
    }

    #[tokio::test]
    async fn chat_dispatches_all_allowed_tools_without_scanner_dependencies() {
        let registry = ToolRegistry::new();
        for (name, args) in [
            ("list_files", json!({"dir": "."})),
            ("read_file", json!({"path": "Cargo.toml"})),
            (
                "grep_code",
                json!({"pattern": "zentra", "path": "Cargo.toml"}),
            ),
            ("git_log", json!({"n": 1})),
            ("git_diff", json!({"since": "HEAD~1"})),
            ("git_blame", json!({"file": "Cargo.toml", "line": 1})),
            ("git_status", json!({})),
        ] {
            let result = registry.dispatch_chat(name, &args).await;
            assert!(
                !result.contains("not permitted") && !result.contains("not registered"),
                "{name} was not dispatched: {result}"
            );
        }
    }

    #[tokio::test]
    async fn chat_reads_leave_scanner_coverage_and_last_outcome_unchanged() {
        let registry = ToolRegistry::new();
        let temp = tempfile::TempDir::new().unwrap();
        let writer = StateWriter::new(temp.path()).unwrap();
        let (tx, _rx) = mpsc::channel(1);

        registry
            .dispatch(
                "read_file",
                &json!({"path": "Cargo.toml"}),
                &writer,
                &tx,
                ScannerType::Sast,
            )
            .await;
        let coverage_before = registry.coverage_snapshot(10);
        let outcome_before = registry.last_outcome_for(ScannerType::Sast, "Cargo.toml");

        for (name, args) in [
            ("read_file", json!({"path": "Cargo.toml"})),
            ("list_files", json!({"dir": "."})),
            (
                "grep_code",
                json!({"pattern": "zentra", "path": "Cargo.toml"}),
            ),
        ] {
            registry.dispatch_chat(name, &args).await;
        }

        assert_eq!(registry.coverage_snapshot(10), coverage_before);
        assert_eq!(
            registry.last_outcome_for(ScannerType::Sast, "Cargo.toml"),
            outcome_before
        );
    }
}
