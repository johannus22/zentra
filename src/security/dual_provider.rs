use crate::provider::{
    AgentMessage, CompletionRequest, CompletionResponse, LLMProvider, ToolCall, ToolDefinition,
};
use crate::security::audit_log::{AuditEvent, AuditLog};
use anyhow::Result;
use async_trait::async_trait;
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;

/// Sends each request to two independent providers and only surfaces tool calls
/// that both agree on. A compromised primary (rogue endpoint, MITM) will produce
/// tool calls the clean secondary does not, and those calls are dropped.
pub struct DualProvider {
    primary: Arc<dyn LLMProvider>,
    secondary: Arc<dyn LLMProvider>,
    /// When false, the secondary is audit-only: divergences are logged but the
    /// primary's calls still execute.
    agreement_required: bool,
    audit: Arc<Mutex<AuditLog>>,
}

impl DualProvider {
    pub fn new(
        primary: Arc<dyn LLMProvider>,
        secondary: Arc<dyn LLMProvider>,
        agreement_required: bool,
        audit: Arc<Mutex<AuditLog>>,
    ) -> Self {
        Self {
            primary,
            secondary,
            agreement_required,
            audit,
        }
    }

    fn record(&self, event: AuditEvent) {
        if let Ok(mut log) = self.audit.lock() {
            let _ = log.record(event);
        }
    }
}

/// Two tool calls match if they share a name and their arguments are equal.
fn calls_match(a: &ToolCall, b: &ToolCall) -> bool {
    a.name == b.name && a.arguments == b.arguments
}

#[async_trait]
impl LLMProvider for DualProvider {
    async fn complete(&self, req: CompletionRequest) -> Result<CompletionResponse> {
        // Non-agent completions are not consensus-checked.
        self.primary.complete(req).await
    }

    async fn complete_with_tools(
        &self,
        system: &str,
        messages: &[AgentMessage],
        tools: &[ToolDefinition],
        max_tokens: u32,
        cancel_token: Option<&CancellationToken>,
    ) -> Result<CompletionResponse> {
        let (primary_res, secondary_res) = tokio::join!(
            self.primary
                .complete_with_tools(system, messages, tools, max_tokens, cancel_token),
            self.secondary
                .complete_with_tools(system, messages, tools, max_tokens, cancel_token),
        );

        let mut primary = primary_res?;

        // If the secondary failed, degrade to primary-only and log it.
        let secondary = match secondary_res {
            Ok(s) => s,
            Err(e) => {
                self.record(AuditEvent::SecurityViolation {
                    category: "consensus_degraded".to_string(),
                    detail: format!("secondary provider failed: {}", e),
                });
                return Ok(primary);
            }
        };

        let agreed: Vec<ToolCall> = primary
            .tool_calls
            .iter()
            .filter(|pc| secondary.tool_calls.iter().any(|sc| calls_match(pc, sc)))
            .cloned()
            .collect();

        let dropped = primary.tool_calls.len() - agreed.len();
        if dropped > 0 {
            self.record(AuditEvent::SecurityViolation {
                category: "consensus_mismatch".to_string(),
                detail: format!(
                    "{} primary tool call(s) had no secondary agreement",
                    dropped
                ),
            });
            if self.agreement_required {
                primary.tool_calls = agreed;
            }
        }

        Ok(primary)
    }

    fn context_window(&self) -> u32 {
        self.primary.context_window()
    }

    fn model_name(&self) -> &str {
        self.primary.model_name()
    }
}
