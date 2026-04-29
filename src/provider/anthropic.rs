use super::*;
use anyhow::{Context, Result};
use async_trait::async_trait;

pub struct AnthropicProvider {
    base_url: String,
    model: String,
    api_key: String,
    client: reqwest::Client,
}

impl AnthropicProvider {
    pub fn new(base_url: String, model: String, api_key: String) -> Self {
        Self { base_url, model, api_key, client: reqwest::Client::new() }
    }

    async fn post_messages(&self, body: serde_json::Value) -> Result<serde_json::Value> {
        let url = format!("{}/messages", self.base_url.trim_end_matches('/'));
        let resp = self.client.post(&url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send().await
            .context("HTTP request to Anthropic failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Anthropic returned {}: {}", status, text));
        }

        Ok(resp.json().await?)
    }
}

fn parse_anthropic_response(json: &serde_json::Value) -> Result<CompletionResponse> {
    let blocks = json["content"].as_array()
        .ok_or_else(|| anyhow::anyhow!("Anthropic response missing content array"))?;

    let content = blocks.iter()
        .find(|b| b["type"] == "text")
        .and_then(|b| b["text"].as_str())
        .unwrap_or("")
        .to_string();

    let tool_calls: Vec<ToolCall> = blocks.iter()
        .filter(|b| b["type"] == "tool_use")
        .filter_map(|b| {
            let id = b["id"].as_str()?.to_string();
            let name = b["name"].as_str()?.to_string();
            let arguments = b["input"].clone();
            Some(ToolCall { id, name, arguments })
        })
        .collect();

    let input = json["usage"]["input_tokens"].as_u64().unwrap_or(0) as u32;
    let output = json["usage"]["output_tokens"].as_u64().unwrap_or(0) as u32;
    Ok(CompletionResponse {
        content,
        tool_calls,
        usage: TokenUsage { input_tokens: input, output_tokens: output, total_tokens: input + output },
    })
}

#[async_trait]
impl LLMProvider for AnthropicProvider {
    async fn complete(&self, req: CompletionRequest) -> Result<CompletionResponse> {
        let body = serde_json::json!({
            "model": self.model,
            "messages": req.messages,
            "max_tokens": req.max_tokens.unwrap_or(4096),
        });

        let json = self.post_messages(body).await?;

        // Keep original error message for the existing test (which has a text block).
        // Use parse_anthropic_response but map the content-missing error to original message.
        let blocks = json["content"].as_array()
            .ok_or_else(|| anyhow::anyhow!("Anthropic response missing text content block"))?;

        let content = blocks.iter()
            .find(|b| b["type"] == "text")
            .and_then(|b| b["text"].as_str())
            .ok_or_else(|| anyhow::anyhow!("Anthropic response missing text content block"))?
            .to_string();

        let input = json["usage"]["input_tokens"].as_u64().unwrap_or(0) as u32;
        let output = json["usage"]["output_tokens"].as_u64().unwrap_or(0) as u32;
        Ok(CompletionResponse {
            content,
            tool_calls: vec![],
            usage: TokenUsage { input_tokens: input, output_tokens: output, total_tokens: input + output },
        })
    }

    async fn complete_with_tools(
        &self,
        system: &str,
        messages: &[AgentMessage],
        tools: &[ToolDefinition],
        max_tokens: u32,
    ) -> Result<CompletionResponse> {
        let mut wire_messages: Vec<serde_json::Value> = Vec::new();

        for msg in messages {
            let entry = match msg {
                AgentMessage::User(s) => serde_json::json!({"role": "user", "content": s}),
                AgentMessage::Assistant { content, tool_calls } => {
                    let mut blocks: Vec<serde_json::Value> = Vec::new();
                    if !content.is_empty() {
                        blocks.push(serde_json::json!({"type": "text", "text": content}));
                    }
                    for tc in tool_calls {
                        blocks.push(serde_json::json!({
                            "type": "tool_use",
                            "id": tc.id,
                            "name": tc.name,
                            "input": tc.arguments
                        }));
                    }
                    serde_json::json!({"role": "assistant", "content": blocks})
                }
                AgentMessage::ToolResult { id, content, .. } => {
                    serde_json::json!({
                        "role": "user",
                        "content": [{
                            "type": "tool_result",
                            "tool_use_id": id,
                            "content": content
                        }]
                    })
                }
            };
            wire_messages.push(entry);
        }

        let wire_tools: Vec<serde_json::Value> = tools.iter().map(|t| {
            serde_json::json!({
                "name": t.name,
                "description": t.description,
                "input_schema": t.parameters
            })
        }).collect();

        let body = serde_json::json!({
            "model": self.model,
            "system": system,
            "messages": wire_messages,
            "tools": wire_tools,
            "max_tokens": max_tokens,
        });

        let json = self.post_messages(body).await?;
        parse_anthropic_response(&json)
    }

    fn context_window(&self) -> u32 {
        let m = self.model.as_str();
        // Claude 4.x and Sonnet 4.6+ have 1M token windows
        if m.contains("opus-4") || m.contains("sonnet-4-6") || m.contains("claude-4") {
            1_000_000
        } else {
            200_000
        }
    }
    fn model_name(&self) -> &str { &self.model }
}
