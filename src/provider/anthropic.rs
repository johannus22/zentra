use super::*;
use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

pub struct AnthropicProvider {
    base_url: String,
    model: String,
    api_key: zeroize::Zeroizing<String>,
    client: reqwest::Client,
}

impl AnthropicProvider {
    pub fn new(base_url: String, model: String, api_key: String) -> Self {
        // Harden the transport: reject invalid certs explicitly and refuse to
        // negotiate below TLS 1.2. (HTTPS-vs-localhost enforcement already happens
        // at config-validation time, so we don't force https_only here and break
        // legitimate local proxies.) Falls back to the default client if the TLS
        // backend can't honor these, keeping behavior unchanged rather than failing.
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(false)
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .connect_timeout(std::time::Duration::from_secs(10))
            .read_timeout(std::time::Duration::from_secs(150))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            base_url,
            model,
            api_key: zeroize::Zeroizing::new(api_key),
            client,
        }
    }

    async fn post_messages(
        &self,
        body: serde_json::Value,
        cancel_token: Option<&CancellationToken>,
    ) -> Result<serde_json::Value> {
        let url = format!("{}/messages", self.base_url.trim_end_matches('/'));
        let request = self
            .client
            .post(&url)
            .header("x-api-key", self.api_key.as_str())
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .build()
            .context("Failed to build HTTP request")?;

        let resp = if let Some(token) = cancel_token {
            tokio::select! {
                biased;
                _ = token.cancelled() => {
                    return Err(anyhow::anyhow!("LLM request cancelled by user"));
                }
                resp = self.client.execute(request) => {
                    resp.context("HTTP request to Anthropic failed")?
                }
            }
        } else {
            self.client
                .execute(request)
                .await
                .context("HTTP request to Anthropic failed")?
        };

        if !resp.status().is_success() {
            let status = resp.status();
            let text = super::read_text_preview(resp, 64 * 1024).await;
            return Err(anyhow::anyhow!("Anthropic returned {}: {}", status, text));
        }

        let bytes = super::read_body_capped(resp, super::MAX_RESPONSE_BYTES).await?;
        Ok(serde_json::from_slice(&bytes).context("parsing Anthropic response")?)
    }
}

fn parse_anthropic_response(json: &serde_json::Value) -> Result<CompletionResponse> {
    let blocks = json["content"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Anthropic response missing content array"))?;

    let content = blocks
        .iter()
        .find(|b| b["type"] == "text")
        .and_then(|b| b["text"].as_str())
        .unwrap_or("")
        .to_string();

    let tool_calls: Vec<ToolCall> = blocks
        .iter()
        .filter(|b| b["type"] == "tool_use")
        .filter_map(|b| {
            let id = b["id"].as_str()?.to_string();
            let name = b["name"].as_str()?.to_string();
            let arguments = b["input"].clone();
            Some(ToolCall {
                id,
                name,
                arguments,
            })
        })
        .collect();

    let input = json["usage"]["input_tokens"].as_u64().unwrap_or(0) as u32;
    let output = json["usage"]["output_tokens"].as_u64().unwrap_or(0) as u32;
    Ok(CompletionResponse {
        content,
        tool_calls,
        usage: TokenUsage {
            input_tokens: input,
            output_tokens: output,
            // saturating: a hostile/buggy endpoint can send huge counts (F10).
            total_tokens: input.saturating_add(output),
        },
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

        let json = self.post_messages(body, None).await?;
        parse_anthropic_response(&json)
    }

    async fn complete_with_tools(
        &self,
        system: &str,
        messages: &[AgentMessage],
        tools: &[ToolDefinition],
        max_tokens: u32,
        cancel_token: Option<&CancellationToken>,
    ) -> Result<CompletionResponse> {
        let mut wire_messages: Vec<serde_json::Value> = Vec::new();

        for msg in messages {
            let entry = match msg {
                AgentMessage::User(s) => serde_json::json!({"role": "user", "content": s}),
                AgentMessage::Assistant {
                    content,
                    tool_calls,
                } => {
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
                    if blocks.is_empty() {
                        serde_json::json!({"role": "assistant", "content": ""})
                    } else {
                        serde_json::json!({"role": "assistant", "content": blocks})
                    }
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

        let wire_tools: Vec<serde_json::Value> = tools
            .iter()
            .map(|t| {
                serde_json::json!({
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.parameters
                })
            })
            .collect();

        let mut body = serde_json::json!({
            "model": self.model,
            "system": system,
            "messages": wire_messages,
            "max_tokens": max_tokens,
        });

        if !wire_tools.is_empty() {
            body["tools"] = serde_json::json!(wire_tools);
        }

        let json = self.post_messages(body, cancel_token).await?;
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
    fn model_name(&self) -> &str {
        &self.model
    }
}

#[cfg(test)]
mod overflow_tests {
    use super::*;

    // F10: a hostile/buggy endpoint can return huge token counts; `input + output`
    // overflowed u32 — panics in debug/test/CI builds, silent wrong total in release.
    #[test]
    fn huge_token_counts_do_not_overflow() {
        let json = serde_json::json!({
            "content": [{"type": "text", "text": "hi"}],
            "usage": {"input_tokens": 4_000_000_000u64, "output_tokens": 4_000_000_000u64}
        });
        let resp = parse_anthropic_response(&json).unwrap();
        assert_eq!(resp.usage.total_tokens, u32::MAX);
    }
}
