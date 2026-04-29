use crate::agent::{ScanEvent, ScannerType};
use crate::provider::{AgentMessage, LLMProvider};
use crate::scanners;
use crate::state::StateWriter;
use crate::tools::ToolRegistry;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::mpsc;

const MAX_ITERATIONS: usize = 30;

pub struct ScannerAgent {
    scanner_type: ScannerType,
    provider: Arc<dyn LLMProvider>,
    tool_registry: Arc<ToolRegistry>,
    state_writer: Arc<StateWriter>,
    tx: mpsc::Sender<ScanEvent>,
}

impl ScannerAgent {
    pub fn new(
        scanner_type: ScannerType,
        provider: Arc<dyn LLMProvider>,
        tool_registry: Arc<ToolRegistry>,
        state_writer: Arc<StateWriter>,
        tx: mpsc::Sender<ScanEvent>,
    ) -> Self {
        Self { scanner_type, provider, tool_registry, state_writer, tx }
    }

    pub async fn run(self) -> Result<()> {
        let system = scanners::system_prompt(self.scanner_type);
        let tools = self.tool_registry.definitions();
        let mut messages: Vec<AgentMessage> = vec![
            AgentMessage::User(
                "Begin your security scan. Start by listing the project files.".to_string()
            ),
        ];

        self.tx.send(ScanEvent::ScannerStarted(self.scanner_type)).await.ok();

        for _iter in 0..MAX_ITERATIONS {
            let resp = self.provider.complete_with_tools(system, &messages, &tools, 4096).await?;

            if resp.tool_calls.is_empty() {
                // Agent signalled it's done (no more tool calls)
                break;
            }

            // Send activity event for the first tool call
            if let Some(tc) = resp.tool_calls.first() {
                let arg = tc.arguments.get("path")
                    .or_else(|| tc.arguments.get("dir"))
                    .or_else(|| tc.arguments.get("pattern"))
                    .or_else(|| tc.arguments.get("tool"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                self.tx.send(ScanEvent::ToolCall {
                    scanner: self.scanner_type,
                    tool: tc.name.clone(),
                    arg,
                }).await.ok();
            }

            // Append assistant message with tool calls to history
            messages.push(AgentMessage::Assistant {
                content: resp.content.clone(),
                tool_calls: resp.tool_calls.clone(),
            });

            // Execute each tool call and append results
            for tc in &resp.tool_calls {
                let result = self.tool_registry.dispatch(
                    &tc.name,
                    &tc.arguments,
                    &self.state_writer,
                    &self.tx,
                    self.scanner_type,
                ).await;
                messages.push(AgentMessage::ToolResult {
                    id: tc.id.clone(),
                    name: tc.name.clone(),
                    content: result,
                });
            }
        }

        self.tx.send(ScanEvent::ScannerCompleted(self.scanner_type)).await.ok();
        Ok(())
    }
}
