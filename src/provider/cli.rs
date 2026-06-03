use super::*;
use anyhow::Result;
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone)]
pub enum CliKind {
    Claude,
    Codex,
}

pub struct CliProvider {
    kind: CliKind,
    binary: String,
    model: String,
}

impl CliProvider {
    pub fn new(kind: CliKind, binary: String, model: String) -> Self {
        Self { kind, binary, model }
    }
}

/// Serialize AgentMessage slice into the plain-text conversation format used
/// by both CLI providers. ToolResult content is CDATA-wrapped to prevent
/// injection of protocol tags from scanned file content.
pub fn serialize_messages(messages: &[AgentMessage]) -> String {
    let mut out = String::new();
    for msg in messages {
        match msg {
            AgentMessage::User(s) => {
                out.push_str(&format!("Human: {}\n\n", s));
            }
            AgentMessage::Assistant { content, tool_calls } => {
                out.push_str("Assistant: ");
                if !content.is_empty() {
                    out.push_str(content);
                }
                for tc in tool_calls {
                    let json = serde_json::json!({
                        "name": tc.name,
                        "id": tc.id,
                        "input": tc.arguments
                    });
                    out.push_str(&format!("\n<ztool_call>{}</ztool_call>", json));
                }
                out.push_str("\n\n");
            }
            AgentMessage::ToolResult { id, name, content } => {
                let escaped = escape_cdata(content);
                out.push_str(&format!(
                    "<ztool_result id=\"{}\" name=\"{}\"><![CDATA[{}]]></ztool_result>\n\n",
                    id, name, escaped
                ));
            }
        }
    }
    out
}

pub(crate) fn escape_cdata(s: &str) -> String {
    s.replace("]]>", "]]]]><![CDATA[>")
}

/// Extract <ztool_call>...</ztool_call> tags from the assistant response.
/// Only scans the top-level response — strips <ztool_result> blocks first
/// so injected content from scanned files cannot produce fake tool calls.
pub fn parse_ztool_calls(response: &str) -> Result<Vec<ToolCall>> {
    let stripped = strip_ztool_results(response);

    let mut calls = Vec::new();
    let mut remaining = stripped.as_str();
    while let Some(start) = remaining.find("<ztool_call>") {
        let after_open = &remaining[start + "<ztool_call>".len()..];
        let end = after_open
            .find("</ztool_call>")
            .ok_or_else(|| anyhow::anyhow!("Unclosed <ztool_call> tag"))?;
        let json_str = &after_open[..end];
        let v: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| anyhow::anyhow!("Malformed ztool_call JSON: {}", e))?;
        calls.push(ToolCall {
            id: v["id"].as_str().unwrap_or("").to_string(),
            name: v["name"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("ztool_call missing 'name'"))?
                .to_string(),
            arguments: v["input"].clone(),
        });
        remaining = &after_open[end + "</ztool_call>".len()..];
    }
    Ok(calls)
}

fn strip_ztool_results(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find("<ztool_result") {
        out.push_str(&rest[..start]);
        let end = rest[start..]
            .find("</ztool_result>")
            .map(|i| start + i + "</ztool_result>".len())
            .unwrap_or(rest.len());
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

#[async_trait]
impl LLMProvider for CliProvider {
    async fn complete(&self, _req: CompletionRequest) -> Result<CompletionResponse> {
        Err(anyhow::anyhow!(
            "CliProvider: use complete_with_tools — bare complete() is not supported"
        ))
    }

    async fn complete_with_tools(
        &self,
        system: &str,
        messages: &[AgentMessage],
        tools: &[ToolDefinition],
        max_tokens: u32,
        cancel_token: Option<&CancellationToken>,
    ) -> Result<CompletionResponse> {
        match self.kind {
            CliKind::Claude => {
                claude_complete_with_tools(
                    &self.binary, &self.model, system, messages, tools, max_tokens, cancel_token,
                )
                .await
            }
            CliKind::Codex => {
                codex_complete_with_tools(
                    &self.binary, &self.model, system, messages, tools, max_tokens, cancel_token,
                )
                .await
            }
        }
    }

    fn context_window(&self) -> u32 {
        match self.kind {
            CliKind::Claude => 200_000,
            CliKind::Codex => 128_000,
        }
    }

    fn model_name(&self) -> &str {
        &self.model
    }
}

async fn claude_complete_with_tools(
    _binary: &str,
    _model: &str,
    _system: &str,
    _messages: &[AgentMessage],
    _tools: &[ToolDefinition],
    _max_tokens: u32,
    _cancel_token: Option<&CancellationToken>,
) -> Result<CompletionResponse> {
    Err(anyhow::anyhow!("claude_cli: not yet implemented"))
}

async fn codex_complete_with_tools(
    _binary: &str,
    _model: &str,
    _system: &str,
    _messages: &[AgentMessage],
    _tools: &[ToolDefinition],
    _max_tokens: u32,
    _cancel_token: Option<&CancellationToken>,
) -> Result<CompletionResponse> {
    Err(anyhow::anyhow!("codex_cli: not yet implemented"))
}
