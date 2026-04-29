use super::*;
use anyhow::{Context, Result};
use async_trait::async_trait;

pub struct OpenAICompatProvider {
    base_url: String,
    model: String,
    api_key: String,
    client: reqwest::Client,
}

impl OpenAICompatProvider {
    pub fn new(base_url: String, model: String, api_key: String) -> Self {
        Self { base_url, model, api_key, client: reqwest::Client::new() }
    }

    async fn post_chat(&self, body: serde_json::Value) -> Result<serde_json::Value> {
        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        let resp = self.client.post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send().await
            .context("HTTP request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Provider returned {}: {}", status, text));
        }

        Ok(resp.json().await?)
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
            body["tools"] = serde_json::to_value(&req.tools).context("Failed to serialize tools")?;
        }

        let json = self.post_chat(body).await?;
        parse_openai_response(&json)
    }

    async fn complete_with_tools(
        &self,
        system: &str,
        messages: &[AgentMessage],
        tools: &[ToolDefinition],
        max_tokens: u32,
    ) -> Result<CompletionResponse> {
        let mut wire_messages: Vec<serde_json::Value> = vec![
            serde_json::json!({"role": "system", "content": system}),
        ];

        for msg in messages {
            let entry = match msg {
                AgentMessage::User(s) => serde_json::json!({"role": "user", "content": s}),
                AgentMessage::Assistant { content, tool_calls } => {
                    if tool_calls.is_empty() {
                        serde_json::json!({"role": "assistant", "content": content})
                    } else {
                        let tc: Vec<serde_json::Value> = tool_calls.iter().map(|tc| {
                            serde_json::json!({
                                "id": tc.id,
                                "type": "function",
                                "function": {
                                    "name": tc.name,
                                    "arguments": tc.arguments.to_string()
                                }
                            })
                        }).collect();
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

        let wire_tools: Vec<serde_json::Value> = tools.iter().map(|t| {
            serde_json::json!({
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters
                }
            })
        }).collect();

        let mut body = serde_json::json!({
            "model": self.model,
            "messages": wire_messages,
            "max_tokens": max_tokens,
        });

        if !wire_tools.is_empty() {
            body["tools"] = serde_json::json!(wire_tools);
            body["tool_choice"] = serde_json::json!("auto");
        }

        let json = self.post_chat(body).await?;
        parse_openai_response(&json)
    }

    fn context_window(&self) -> u32 {
        match self.model.as_str() {
            m if m.contains("gpt-4o") || m.contains("o1") || m.contains("llama-3") => 128_000,
            m if m.contains("claude") => 200_000,
            _ => 32_000,
        }
    }

    fn model_name(&self) -> &str { &self.model }
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
    Ok(CompletionResponse { content, tool_calls, usage })
}

fn parse_tool_calls(json: &serde_json::Value) -> Vec<ToolCall> {
    json.as_array().map(|calls| {
        calls.iter().filter_map(|c| {
            let id = c["id"].as_str()?.to_string();
            let name = c["function"]["name"].as_str()?.to_string();
            let arguments = c["function"]["arguments"].as_str()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or(serde_json::Value::Object(Default::default()));
            Some(ToolCall { id, name, arguments })
        }).collect()
    }).unwrap_or_default()
}
