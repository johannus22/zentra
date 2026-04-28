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
}

#[async_trait]
impl LLMProvider for AnthropicProvider {
    async fn complete(&self, req: CompletionRequest) -> Result<CompletionResponse> {
        let url = format!("{}/messages", self.base_url.trim_end_matches('/'));
        let body = serde_json::json!({
            "model": self.model,
            "messages": req.messages,
            "max_tokens": req.max_tokens.unwrap_or(4096),
        });

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

        let json: serde_json::Value = resp.json().await?;
        let content = json["content"].as_array()
            .and_then(|blocks| blocks.iter().find(|b| b["type"] == "text"))
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
