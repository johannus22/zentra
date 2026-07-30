use super::*;
use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

pub struct OpenAICompatProvider {
    base_url: String,
    model: String,
    api_key: zeroize::Zeroizing<String>,
    client: reqwest::Client,
    reasoning_effort: Option<String>,
    context_window_override: Option<u32>,
    temperature: f64,
}

impl OpenAICompatProvider {
    pub fn new(base_url: String, model: String, api_key: String) -> Self {
        Self {
            base_url,
            model,
            api_key: zeroize::Zeroizing::new(api_key),
            client: reqwest::Client::builder()
                .danger_accept_invalid_certs(false)
                .min_tls_version(reqwest::tls::Version::TLS_1_2)
                .connect_timeout(std::time::Duration::from_secs(10))
                .read_timeout(std::time::Duration::from_secs(150))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            reasoning_effort: None,
            context_window_override: None,
            temperature: crate::config::DEFAULT_TEMPERATURE,
        }
    }

    /// Builder: set the sampling temperature. `None` keeps
    /// [`crate::config::DEFAULT_TEMPERATURE`]. The value is clamped to 0.0..=2.0,
    /// so a hand-edited config cannot make the API reject the request.
    pub fn with_temperature(mut self, t: Option<f64>) -> Self {
        self.temperature = t
            .unwrap_or(crate::config::DEFAULT_TEMPERATURE)
            .clamp(0.0, 2.0);
        self
    }

    /// Builder: set the reasoning level forwarded as `reasoning_effort`.
    /// `None` (the default) omits the field from requests entirely.
    pub fn with_reasoning(mut self, effort: Option<String>) -> Self {
        self.reasoning_effort = effort;
        self
    }

    /// Builder: set the context window override.
    /// When set, `context_window()` returns this value; otherwise defaults based on model name.
    pub fn with_context_window(mut self, cw: Option<u32>) -> Self {
        self.context_window_override = cw;
        self
    }

    fn apply_reasoning(&self, body: &mut serde_json::Value) {
        if let Some(ref effort) = self.reasoning_effort {
            body["reasoning_effort"] = serde_json::json!(effort);
        }
    }

    /// Always sets the field. An omitted temperature means the endpoint picks
    /// its own default, which is the drift this exists to remove.
    fn apply_temperature(&self, body: &mut serde_json::Value) {
        body["temperature"] = serde_json::json!(self.temperature);
    }

    fn chat_completions_url(&self) -> String {
        chat_completions_url(&self.base_url)
    }

    async fn post_chat(
        &self,
        body: serde_json::Value,
        cancel_token: Option<&CancellationToken>,
    ) -> Result<serde_json::Value> {
        let url = self.chat_completions_url();
        let request = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key.as_str()))
            .header("Content-Type", "application/json")
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
                    resp.context("HTTP request failed")?
                }
            }
        } else {
            self.client
                .execute(request)
                .await
                .context("HTTP request failed")?
        };

        if !resp.status().is_success() {
            let status = resp.status();
            let text = super::read_text_preview(resp, 64 * 1024).await;
            return Err(anyhow::anyhow!("Provider returned {}: {}", status, text));
        }

        let bytes = super::read_body_capped(resp, super::MAX_RESPONSE_BYTES).await?;
        serde_json::from_slice(&bytes).context("parsing provider response")
    }
}

pub(crate) fn chat_completions_url(base_url: &str) -> String {
    let trimmed = base_url.trim().trim_end_matches('/');
    if trimmed.ends_with("/chat/completions") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/chat/completions")
    }
}

#[async_trait]
impl LLMProvider for OpenAICompatProvider {
    async fn complete(&self, req: CompletionRequest) -> Result<CompletionResponse> {
        let mut body = serde_json::json!({
            "model": self.model,
            "messages": req.messages,
            "max_tokens": req.max_tokens,
        });

        if !req.tools.is_empty() {
            body["tools"] =
                serde_json::to_value(&req.tools).context("Failed to serialize tools")?;
        }

        self.apply_reasoning(&mut body);
        self.apply_temperature(&mut body);
        let json = self.post_chat(body, None).await?;
        parse_openai_response(&json)
    }

    async fn complete_with_tools(
        &self,
        system: &str,
        messages: &[AgentMessage],
        tools: &[ToolDefinition],
        max_tokens: u32,
        cancel_token: Option<&CancellationToken>,
    ) -> Result<CompletionResponse> {
        let mut wire_messages: Vec<serde_json::Value> =
            vec![serde_json::json!({"role": "system", "content": system})];

        for msg in messages {
            let entry = match msg {
                AgentMessage::User(s) => serde_json::json!({"role": "user", "content": s}),
                AgentMessage::Assistant {
                    content,
                    tool_calls,
                } => {
                    if tool_calls.is_empty() {
                        serde_json::json!({"role": "assistant", "content": content})
                    } else {
                        let tc: Vec<serde_json::Value> = tool_calls
                            .iter()
                            .map(|tc| {
                                serde_json::json!({
                                    "id": tc.id,
                                    "type": "function",
                                    "function": {
                                        "name": tc.name,
                                        "arguments": tc.arguments.to_string()
                                    }
                                })
                            })
                            .collect();
                        serde_json::json!({
                            "role": "assistant",
                            "content": if content.is_empty() { serde_json::Value::Null } else { serde_json::json!(content) },
                            "tool_calls": tc
                        })
                    }
                }
                AgentMessage::ToolResult { id, name, content } => {
                    serde_json::json!({
                        "role": "tool",
                        "tool_call_id": id,
                        "name": name,
                        "content": content
                    })
                }
            };
            wire_messages.push(entry);
        }

        let wire_tools: Vec<serde_json::Value> = tools
            .iter()
            .map(|t| {
                serde_json::json!({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters
                    }
                })
            })
            .collect();

        let mut body = serde_json::json!({
            "model": self.model,
            "messages": wire_messages,
            "max_tokens": max_tokens,
        });

        if !wire_tools.is_empty() {
            body["tools"] = serde_json::json!(wire_tools);
            body["tool_choice"] = serde_json::json!("auto");
        }

        self.apply_reasoning(&mut body);
        self.apply_temperature(&mut body);
        let json = self.post_chat(body, cancel_token).await?;
        parse_openai_response(&json)
    }

    fn context_window(&self) -> u32 {
        if let Some(cw) = self.context_window_override {
            return cw;
        }
        match self.model.as_str() {
            m if m.contains("gpt-4o") || m.contains("o1") || m.contains("llama-3") => 128_000,
            m if m.contains("claude") => 200_000,
            _ => 128_000,
        }
    }

    fn model_name(&self) -> &str {
        &self.model
    }
}

fn parse_openai_response(json: &serde_json::Value) -> Result<CompletionResponse> {
    let message = json["choices"]
        .as_array()
        .and_then(|c| c.first())
        .ok_or_else(|| anyhow::anyhow!("API response missing choices array"))?
        .get("message")
        .ok_or_else(|| anyhow::anyhow!("API response missing message in choice"))?;
    let content = message["content"].as_str().unwrap_or("").to_string();
    let tool_calls = parse_tool_calls(&message["tool_calls"]);
    let usage_json = &json["usage"];
    let usage = TokenUsage {
        input_tokens: usage_json["prompt_tokens"].as_u64().unwrap_or(0) as u32,
        output_tokens: usage_json["completion_tokens"].as_u64().unwrap_or(0) as u32,
        total_tokens: usage_json["total_tokens"].as_u64().unwrap_or(0) as u32,
    };
    Ok(CompletionResponse {
        content,
        tool_calls,
        usage,
    })
}

fn parse_tool_calls(json: &serde_json::Value) -> Vec<ToolCall> {
    json.as_array()
        .map(|calls| {
            calls
                .iter()
                .filter_map(|c| {
                    let id = c["id"].as_str()?.to_string();
                    let name = c["function"]["name"].as_str()?.to_string();
                    let arguments = c["function"]["arguments"]
                        .as_str()
                        .and_then(|s| serde_json::from_str(s).ok())
                        .unwrap_or(serde_json::Value::Object(Default::default()));
                    Some(ToolCall {
                        id,
                        name,
                        arguments,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}
