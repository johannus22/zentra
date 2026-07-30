use crate::agent::context_budget::{self, Outcome};
use crate::agent::{ScanEvent, ScannerType};
use crate::provider::{AgentMessage, LLMProvider};
use crate::scanners;
use crate::security::audit_log::{sha256_json, sha256_str};
use crate::security::{AuditEvent, SecurityContext};
use crate::state::StateWriter;
use crate::tools::ToolRegistry;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const MAX_ITERATIONS: usize = 30;

pub struct ScannerAgent {
    scanner_type: ScannerType,
    provider: Arc<dyn LLMProvider>,
    tool_registry: Arc<ToolRegistry>,
    state_writer: Arc<StateWriter>,
    tx: mpsc::Sender<ScanEvent>,
    context: Option<String>,
    focus_context: Option<String>,
    incremental_scope: Option<Vec<String>>,
    /// The whole filtered repository, when pack mode is on. Shared across every
    /// scanner in the run, so it is behind an Arc rather than cloned per scanner.
    pack: Option<Arc<String>>,
    cancel_token: CancellationToken,
    security: SecurityContext,
}

/// Render the impact-set file list for both the initial prompt and blocked-call
/// messages. Empty scope is a real but rare case (e.g. only manifest/IaC files
/// changed, nothing relevant to this scanner) — it gets an explicit placeholder
/// rather than a blank list.
fn format_scope_list(scope: &[String]) -> String {
    if scope.is_empty() {
        "(none — no impacted files for this scanner this run)".to_string()
    } else {
        scope
            .iter()
            .map(|f| format!("- {f}"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn normalize_scope_path(p: &str) -> String {
    p.replace('\\', "/")
}

fn path_in_scope(path: &str, scope: &[String]) -> bool {
    let p = normalize_scope_path(path);
    scope.iter().any(|s| normalize_scope_path(s) == p)
}

/// Build the initial user prompt for a scanner run. Incremental scope, when
/// present, replaces the generic "list the project files" opener with the
/// exact impact-set file list so the model never needs to crawl the tree.
fn initial_prompt_for(
    scanner_type: ScannerType,
    incremental_scope: Option<&[String]>,
    pack: Option<&str>,
) -> String {
    // Pack mode wins over both other openers: the whole filtered repository is
    // already in the message, so there is nothing to navigate to. It applies to
    // FrameworkAnalysis too — the manifest is in the pack.
    if let Some(pack) = pack {
        return pack.to_string();
    }
    if scanner_type == ScannerType::FrameworkAnalysis {
        return "Begin the framework analysis. Start by listing the project files and reading the package manifest.".to_string();
    }
    match incremental_scope {
        Some(scope) => format!(
            "Incremental rescan. Only these files changed or are impacted since the last scan:\n{}\n\n\
             Read exactly these files with read_file; do not call list_files. Report findings only for code in this set.",
            format_scope_list(scope)
        ),
        None => "Begin your security scan. Start by listing the project files.".to_string(),
    }
}

/// Returns `Err(detail)` when `name`/`args` fall outside `scope` for an
/// incremental rescan. Only the three source-reading tools are restricted;
/// every other tool (write_finding, git_*, run_audit, write_architecture) is
/// always allowed regardless of scope.
fn check_incremental_scope(
    name: &str,
    args: &serde_json::Value,
    scope: &[String],
) -> Result<(), String> {
    match name {
        "list_files" => Err(format!(
            "Directory listing is disabled for this incremental scan. In-scope files:\n{}\n\
             Read one of the files listed above with read_file instead.",
            format_scope_list(scope)
        )),
        "read_file" => {
            let path = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
            if path_in_scope(path, scope) {
                Ok(())
            } else {
                Err(format!(
                    "'{}' is out of scope for this incremental scan. In-scope files:\n{}",
                    path,
                    format_scope_list(scope)
                ))
            }
        }
        "grep_code" => match args.get("path").and_then(|v| v.as_str()) {
            Some(p) if path_in_scope(p, scope) => Ok(()),
            _ => Err(format!(
                "grep_code must target a specific in-scope file for this incremental scan. In-scope files:\n{}",
                format_scope_list(scope)
            )),
        },
        _ => Ok(()),
    }
}

impl ScannerAgent {
    pub fn new(
        scanner_type: ScannerType,
        provider: Arc<dyn LLMProvider>,
        tool_registry: Arc<ToolRegistry>,
        state_writer: Arc<StateWriter>,
        tx: mpsc::Sender<ScanEvent>,
        context: Option<String>,
        cancel_token: CancellationToken,
    ) -> Self {
        Self {
            scanner_type,
            provider,
            tool_registry,
            state_writer,
            tx,
            context,
            focus_context: None,
            incremental_scope: None,
            pack: None,
            cancel_token,
            security: SecurityContext::disabled(),
        }
    }

    pub fn new_with_contexts(
        scanner_type: ScannerType,
        provider: Arc<dyn LLMProvider>,
        tool_registry: Arc<ToolRegistry>,
        state_writer: Arc<StateWriter>,
        tx: mpsc::Sender<ScanEvent>,
        context: Option<String>,
        focus_context: Option<String>,
        cancel_token: CancellationToken,
    ) -> Self {
        Self {
            scanner_type,
            provider,
            tool_registry,
            state_writer,
            tx,
            context,
            focus_context,
            incremental_scope: None,
            pack: None,
            cancel_token,
            security: SecurityContext::disabled(),
        }
    }

    /// Attach the security envelope (audit log, tool gate, prompt guard).
    pub fn with_security(mut self, security: SecurityContext) -> Self {
        self.security = security;
        self
    }

    /// Restrict this scanner to only the given files (incremental rescans).
    /// `None` (the default) means no restriction — full-scan behavior.
    pub fn with_incremental_scope(mut self, scope: Option<Vec<String>>) -> Self {
        self.incremental_scope = scope;
        self
    }

    /// Open with the whole filtered repository instead of a navigation prompt.
    /// `Arc` because every scanner in the run shares one pack, and it is large.
    pub fn with_pack(mut self, pack: Option<Arc<String>>) -> Self {
        self.pack = pack;
        self
    }

    pub async fn run(self) -> Result<()> {
        let base_system = scanners::system_prompt(self.scanner_type);
        let mut effective_system: String = match &self.context {
            Some(ctx) => format!(
                "{}\n\n## Project Framework Context\n\n\
This context was produced by a prior framework analysis pass. Use it to avoid false positives. \
For example, do not flag SQL injection if the ORM listed here auto-parameterises all queries.\n\n{}",
                base_system, ctx
            ),
            None => base_system.to_string(),
        };
        if let Some(ctx) = &self.focus_context {
            effective_system.push_str("\n\n## Scan Focus Context\n\n");
            effective_system.push_str(ctx);
        }
        let system = effective_system.as_str();
        let all_tools = self.tool_registry.definitions();
        let allowed = scanners::allowed_tools(self.scanner_type);
        let tools: Vec<_> = all_tools
            .into_iter()
            .filter(|t| allowed.contains(&t.name.as_str()))
            .collect();
        let initial_prompt = initial_prompt_for(
            self.scanner_type,
            self.incremental_scope.as_deref(),
            self.pack.as_deref().map(String::as_str),
        );
        let mut messages: Vec<AgentMessage> = vec![AgentMessage::User(initial_prompt)];

        // Per-scanner security state.
        let mut gate = self.security.gate(self.scanner_type);
        let mut prompt_guard = self.security.prompt_guard();

        self.tx
            .send(ScanEvent::ScannerStarted(self.scanner_type))
            .await
            .ok();

        'react: for _iter in 0..MAX_ITERATIONS {
            // Guard: never send a request that would overflow the model's
            // context window. Compact oldest tool results to fit; if even the
            // minimal request is too large, abort this scanner visibly rather
            // than letting the provider 400 it into silent zero findings.
            let budget = context_budget::input_budget(self.provider.context_window(), 4096);
            if let Outcome::Irreducible { estimate, budget } =
                context_budget::compact_to_budget(&mut messages, system, &tools, budget)
            {
                let message = format!(
                    "context budget exceeded for model {} (need ~{estimate} tokens, budget {budget}) — skipping scanner",
                    self.provider.model_name()
                );
                crate::logging::error(
                    "scan",
                    format!("scanner={:?} {message}", self.scanner_type),
                );
                self.tx
                    .send(ScanEvent::Error { scanner: self.scanner_type, message: message.clone() })
                    .await
                    .ok();
                self.tx
                    .send(ScanEvent::ScannerCompleted(self.scanner_type))
                    .await
                    .ok();
                return Err(anyhow::anyhow!(message));
            }

            let resp = match self
                .provider
                .complete_with_tools(system, &messages, &tools, 4096, Some(&self.cancel_token))
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    // A cancelled request is user/system-initiated, not a failure
                    // worth recording — skip the crash log on cancellation.
                    if !self.cancel_token.is_cancelled() {
                        crate::logging::error(
                            "scan",
                            format!("scanner={:?} LLM request failed: {e}", self.scanner_type),
                        );
                    }
                    self.tx
                        .send(ScanEvent::Error {
                            scanner: self.scanner_type,
                            message: e.to_string(),
                        })
                        .await
                        .ok();
                    self.tx
                        .send(ScanEvent::ScannerCompleted(self.scanner_type))
                        .await
                        .ok();
                    return Err(e);
                }
            };

            self.tx
                .send(ScanEvent::TokensUsed {
                    input: resp.usage.input_tokens,
                    output: resp.usage.output_tokens,
                })
                .await
                .ok();

            if resp.tool_calls.is_empty() {
                // Agent signalled it's done (no more tool calls)
                break;
            }

            // Send activity event for the first tool call
            if let Some(tc) = resp.tool_calls.first() {
                let arg = tc
                    .arguments
                    .get("path")
                    .or_else(|| tc.arguments.get("dir"))
                    .or_else(|| tc.arguments.get("pattern"))
                    .or_else(|| tc.arguments.get("tool"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                self.tx
                    .send(ScanEvent::ToolCall {
                        scanner: self.scanner_type,
                        tool: tc.name.clone(),
                        arg,
                    })
                    .await
                    .ok();
            }

            // Append assistant message with tool calls to history
            messages.push(AgentMessage::Assistant {
                content: resp.content.clone(),
                tool_calls: resp.tool_calls.clone(),
            });

            // Execute each tool call (gated) and append results
            for tc in &resp.tool_calls {
                if self.cancel_token.is_cancelled() {
                    break 'react;
                }
                // Security gate: block disallowed/suspicious calls without
                // killing the scan — the LLM is told why and can adjust.
                if let Err(blocked) = gate.check(&tc.name, &tc.arguments) {
                    self.security.record(AuditEvent::SecurityViolation {
                        category: "tool_gate".to_string(),
                        detail: format!("{}: {}", tc.name, blocked),
                    });
                    messages.push(AgentMessage::ToolResult {
                        id: tc.id.clone(),
                        name: tc.name.clone(),
                        content: format!("[SECURITY GATE] Call blocked: {}", blocked),
                    });
                    continue;
                }

                if let Some(scope) = &self.incremental_scope {
                    if let Err(blocked) = check_incremental_scope(&tc.name, &tc.arguments, scope) {
                        messages.push(AgentMessage::ToolResult {
                            id: tc.id.clone(),
                            name: tc.name.clone(),
                            content: format!("[INCREMENTAL SCOPE] Call blocked: {}", blocked),
                        });
                        continue;
                    }
                }

                self.security.record(AuditEvent::ToolDispatched {
                    tool: tc.name.clone(),
                    arg_hash: sha256_json(&tc.arguments),
                });

                let result = tokio::select! {
                    biased;
                    _ = self.cancel_token.cancelled() => break 'react,
                    r = self.tool_registry.dispatch(
                        &tc.name,
                        &tc.arguments,
                        &self.state_writer,
                        &self.tx,
                        self.scanner_type,
                    ) => r,
                };

                self.security.record(AuditEvent::ToolResult {
                    tool: tc.name.clone(),
                    result_hash: sha256_str(&result),
                });

                // Coverage: report what this read actually produced. The outcome
                // comes from the registry's ledger, not from the result string,
                // so the TUI counter and .zentra/coverage.md always agree.
                if tc.name == "read_file" {
                    if let Some(path) = tc.arguments.get("path").and_then(|v| v.as_str()) {
                        if let Some(outcome) =
                            self.tool_registry.last_outcome_for(self.scanner_type, path)
                        {
                            self.tx
                                .send(ScanEvent::FileRead {
                                    scanner: self.scanner_type,
                                    path: path.to_string(),
                                    outcome,
                                })
                                .await
                                .ok();
                        }
                    }
                }

                // Tag external output and scan it for prompt-injection attempts.
                let (wrapped, injected) = prompt_guard.scan_and_wrap(&tc.name, &result);
                if injected {
                    self.security.record(AuditEvent::SecurityViolation {
                        category: "prompt_injection".to_string(),
                        detail: format!("injection pattern in {} output", tc.name),
                    });
                }

                messages.push(AgentMessage::ToolResult {
                    id: tc.id.clone(),
                    name: tc.name.clone(),
                    content: wrapped,
                });
            }

            // Optionally abort once injection attempts cross the threshold.
            if prompt_guard.is_session_aborted() && self.security.config.prompt_guard_abort {
                self.security.record(AuditEvent::SecurityViolation {
                    category: "prompt_injection".to_string(),
                    detail: "injection threshold exceeded — aborting scanner".to_string(),
                });
                crate::logging::warn(
                    "scan",
                    format!(
                        "scanner={:?} aborted: repeated prompt-injection attempts",
                        self.scanner_type
                    ),
                );
                self.tx
                    .send(ScanEvent::Error {
                        scanner: self.scanner_type,
                        message: "Scan aborted: repeated prompt-injection attempts detected"
                            .to_string(),
                    })
                    .await
                    .ok();
                break;
            }
        }

        self.tx
            .send(ScanEvent::ScannerCompleted(self.scanner_type))
            .await
            .ok();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_prompt_unchanged_for_full_scan() {
        assert_eq!(
            initial_prompt_for(ScannerType::Sast, None, None),
            "Begin your security scan. Start by listing the project files."
        );
    }

    #[test]
    fn initial_prompt_unchanged_for_framework_analysis_regardless_of_scope() {
        let scope = vec!["src/a.rs".to_string()];
        assert_eq!(
            initial_prompt_for(ScannerType::FrameworkAnalysis, None, None),
            initial_prompt_for(ScannerType::FrameworkAnalysis, Some(&scope), None),
        );
        assert!(initial_prompt_for(ScannerType::FrameworkAnalysis, Some(&scope), None)
            .contains("framework analysis"));
    }

    #[test]
    fn initial_prompt_lists_impact_files_for_incremental_scan() {
        let scope = vec!["src/a.rs".to_string(), "src/b.rs".to_string()];
        let prompt = initial_prompt_for(ScannerType::Sast, Some(&scope), None);
        assert!(prompt.contains("Incremental rescan"));
        assert!(prompt.contains("src/a.rs"));
        assert!(prompt.contains("src/b.rs"));
        assert!(!prompt.contains("Start by listing the project files"));
    }

    #[test]
    fn initial_prompt_handles_empty_scope() {
        let prompt = initial_prompt_for(ScannerType::Sast, Some(&[]), None);
        assert!(prompt.contains("none — no impacted files"));
    }

    #[test]
    fn scope_check_always_blocks_list_files() {
        let scope = vec!["src/a.rs".to_string()];
        let err = check_incremental_scope("list_files", &serde_json::json!({"dir": "."}), &scope)
            .unwrap_err();
        assert!(err.contains("Directory listing is disabled"));
        assert!(err.contains("src/a.rs"));
    }

    #[test]
    fn scope_check_allows_read_file_in_scope() {
        let scope = vec!["src/a.rs".to_string()];
        assert!(check_incremental_scope(
            "read_file",
            &serde_json::json!({"path": "src/a.rs"}),
            &scope
        )
        .is_ok());
    }

    #[test]
    fn scope_check_blocks_read_file_out_of_scope() {
        let scope = vec!["src/a.rs".to_string()];
        let err = check_incremental_scope(
            "read_file",
            &serde_json::json!({"path": "src/other.rs"}),
            &scope,
        )
        .unwrap_err();
        assert!(err.contains("src/other.rs"));
        assert!(err.contains("src/a.rs"));
    }

    #[test]
    fn scope_check_normalizes_backslash_paths() {
        let scope = vec!["src/a.rs".to_string()];
        assert!(check_incremental_scope(
            "read_file",
            &serde_json::json!({"path": "src\\a.rs"}),
            &scope
        )
        .is_ok());
    }

    #[test]
    fn scope_check_grep_requires_in_scope_path() {
        let scope = vec!["src/a.rs".to_string()];
        assert!(check_incremental_scope(
            "grep_code",
            &serde_json::json!({"pattern": "foo", "path": "src/a.rs"}),
            &scope
        )
        .is_ok());
        assert!(check_incremental_scope(
            "grep_code",
            &serde_json::json!({"pattern": "foo"}),
            &scope
        )
        .is_err());
        assert!(check_incremental_scope(
            "grep_code",
            &serde_json::json!({"pattern": "foo", "path": "src/other.rs"}),
            &scope
        )
        .is_err());
    }

    #[test]
    fn scope_check_never_blocks_other_tools() {
        let scope = vec!["src/a.rs".to_string()];
        for tool in [
            "write_finding",
            "write_report",
            "git_log",
            "git_diff",
            "git_blame",
            "git_status",
            "run_audit",
            "write_architecture",
        ] {
            assert!(
                check_incremental_scope(tool, &serde_json::json!({}), &scope).is_ok(),
                "{tool} must never be blocked by incremental scope"
            );
        }
    }
}
