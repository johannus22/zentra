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
}

#[async_trait]
impl LLMProvider for OpenAICompatProvider {
    async fn complete(&self, req: CompletionRequest) -> Result<CompletionResponse> {
        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        let body = serde_json::json!({
            "model": self.model,
            "messages": req.messages,
            "tools": if req.tools.is_empty() { serde_json::Value::Null } else { serde_json::to_value(&req.tools).unwrap() },
            "max_tokens": req.max_tokens,
        });

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

        let json: serde_json::Value = resp.json().await?;
        let content = json["choices"][0]["message"]["content"]
            .as_str().unwrap_or("").to_string();
        let tool_calls = parse_tool_calls(&json["choices"][0]["message"]["tool_calls"]);
        let usage = TokenUsage {
            input_tokens: json["usage"]["prompt_tokens"].as_u64().unwrap_or(0) as u32,
            output_tokens: json["usage"]["completion_tokens"].as_u64().unwrap_or(0) as u32,
            total_tokens: json["usage"]["total_tokens"].as_u64().unwrap_or(0) as u32,
        };
        Ok(CompletionResponse { content, tool_calls, usage })
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
