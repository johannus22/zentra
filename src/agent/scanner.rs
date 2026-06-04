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
    ci_focus_context: Option<String>,
    cancel_token: CancellationToken,
    security: SecurityContext,
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
            ci_focus_context: None,
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
        ci_focus_context: Option<String>,
        cancel_token: CancellationToken,
    ) -> Self {
        Self {
            scanner_type,
            provider,
            tool_registry,
            state_writer,
            tx,
            context,
            ci_focus_context,
            cancel_token,
            security: SecurityContext::disabled(),
        }
    }

    /// Attach the security envelope (audit log, tool gate, prompt guard).
    pub fn with_security(mut self, security: SecurityContext) -> Self {
        self.security = security;
        self
    }

    pub async fn run(self) -> Result<()> {
        let base_system = scanners::system_prompt(self.scanner_type);
        let mut effective_system: String = match &self.context {
            Some(ctx) => format!(
                "{}\n\n## Project Framework Context\n\n\
This context was produced by a prior framework analysis pass. Use it to avoid false positives — \
for example, do not flag SQL injection if the ORM listed here auto-parameterises all queries.\n\n{}",
                base_system, ctx
            ),
            None => base_system.to_string(),
        };
        if let Some(ctx) = &self.ci_focus_context {
            effective_system.push_str("\n\n## CI PR/MR Focus Context\n\n");
            effective_system.push_str(ctx);
        }
        let system = effective_system.as_str();
        let all_tools = self.tool_registry.definitions();
        let allowed = scanners::allowed_tools(self.scanner_type);
        let tools: Vec<_> = all_tools
            .into_iter()
            .filter(|t| allowed.contains(&t.name.as_str()))
            .collect();
        let initial_prompt = if self.scanner_type == ScannerType::FrameworkAnalysis {
            "Begin the framework analysis. Start by listing the project files and reading the package manifest.".to_string()
        } else {
            "Begin your security scan. Start by listing the project files.".to_string()
        };
        let mut messages: Vec<AgentMessage> = vec![AgentMessage::User(initial_prompt)];

        // Per-scanner security state.
        let mut gate = self.security.gate(self.scanner_type);
        let mut prompt_guard = self.security.prompt_guard();

        self.tx
            .send(ScanEvent::ScannerStarted(self.scanner_type))
            .await
            .ok();

        for _iter in 0..MAX_ITERATIONS {
            let resp = match self
                .provider
                .complete_with_tools(system, &messages, &tools, 4096, Some(&self.cancel_token))
                .await
            {
                Ok(r) => r,
                Err(e) => {
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

                self.security.record(AuditEvent::ToolDispatched {
                    tool: tc.name.clone(),
                    arg_hash: sha256_json(&tc.arguments),
                });

                let result = self
                    .tool_registry
                    .dispatch(
                        &tc.name,
                        &tc.arguments,
                        &self.state_writer,
                        &self.tx,
                        self.scanner_type,
                    )
                    .await;

                self.security.record(AuditEvent::ToolResult {
                    tool: tc.name.clone(),
                    result_hash: sha256_str(&result),
                });

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
