use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub mod anthropic;
pub mod openai_compat;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

#[derive(Debug)]
pub struct CompletionRequest {
    pub messages: Vec<Message>,
    pub tools: Vec<ToolDefinition>,
    pub max_tokens: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: serde_json::Value,
}

#[derive(Debug, Default)]
pub struct TokenUsage {
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub total_tokens: u32,
}

#[derive(Debug)]
pub struct CompletionResponse {
    pub content: String,
    pub tool_calls: Vec<ToolCall>,
    pub usage: TokenUsage,
}

/// Agent conversation turn used by the ReAct loop.
/// Each provider serializes these into its native wire format.
#[derive(Debug, Clone)]
pub enum AgentMessage {
    /// Initial user instruction to the agent.
    User(String),
    /// Assistant reply, optionally with tool call requests.
    Assistant { content: String, tool_calls: Vec<ToolCall> },
    /// Tool execution result to feed back to the assistant.
    ToolResult { id: String, name: String, content: String },
}

#[async_trait]
pub trait LLMProvider: Send + Sync {
    async fn complete(&self, req: CompletionRequest) -> Result<CompletionResponse>;

    /// Agent-mode completion with full tool call support.
    /// `system` is sent as the system prompt.
    /// `messages` are the conversation turns including prior tool calls/results.
    async fn complete_with_tools(
        &self,
        system: &str,
        messages: &[AgentMessage],
        tools: &[ToolDefinition],
        max_tokens: u32,
    ) -> Result<CompletionResponse>;

    fn context_window(&self) -> u32;
    fn model_name(&self) -> &str;
}
