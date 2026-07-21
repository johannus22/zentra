pub mod audit;
pub mod diagnostics;
pub mod fs_tools;
pub mod git_tools;

use crate::agent::{ScanEvent, ScannerType};
use crate::provider::ToolDefinition;
use crate::state::{Finding, Severity, StateWriter};
use tokio::sync::mpsc;

pub struct ToolRegistry;

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self
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
                        "description": {"type": "string", "description": "Detailed description of the vulnerability"},
                        "location": {"type": "string", "description": "File and line, e.g. src/auth.rs:42"},
                        "recommendation": {"type": "string", "description": "Concrete fix recommendation"},
                        "cwe": {"type": "string", "description": "Primary CWE id, e.g. CWE-89"},
                        "secondary_cwe": {"type": "array", "items": {"type": "string"}, "description": "Additional related CWE ids, e.g. [\"CWE-20\"]"},
                        "cvss_vector": {"type": "string", "description": "CVSS v3.1 base vector, e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (provide the vector, not a score)"},
                        "owasp": {"type": "string", "description": "OWASP Top 10 category, e.g. A03:2021-Injection"}
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
                fs_tools::read_file(path)
            }
            "list_files" => {
                let dir = args["dir"].as_str().unwrap_or(".");
                let pattern = args["pattern"].as_str();
                fs_tools::list_files(dir, pattern)
            }
            "grep_code" => {
                let pattern = args["pattern"].as_str().unwrap_or("");
                let path = args["path"].as_str();
                fs_tools::grep_code(pattern, path)
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
            "git_log" => {
                let n = args["n"].as_u64().unwrap_or(10) as u32;
                git_tools::git_log(n)
            }
            "git_diff" => {
                let since = args["since"].as_str().unwrap_or("HEAD~1");
                git_tools::git_diff(since)
            }
            "git_blame" => {
                let file = args["file"].as_str().unwrap_or("");
                let line = args["line"].as_u64().unwrap_or(1) as u32;
                git_tools::git_blame(file, line)
            }
            "git_status" => git_tools::git_status(),
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
