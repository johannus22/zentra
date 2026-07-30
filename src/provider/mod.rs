use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

pub mod anthropic;
pub mod openai_compat;
pub mod cli;
pub mod retry;

/// Max bytes to buffer from an LLM HTTP response. Bodies larger than this are
/// rejected rather than buffered, so a hostile or misconfigured endpoint (a
/// custom/self-hosted base_url) can't OOM the scanner with a giant/infinite
/// body (F5). Generous headroom for large JSON tool-call responses.
pub(crate) const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// True if appending `chunk_len` bytes to `current` would exceed `max`.
/// Overflow-safe (saturating).
fn body_cap_exceeded(current: usize, chunk_len: usize, max: usize) -> bool {
    current.saturating_add(chunk_len) > max
}

/// Read a response body into memory, refusing bodies larger than `max_bytes`.
/// Errors (rather than truncating) because callers parse the whole body as JSON.
pub(crate) async fn read_body_capped(
    mut resp: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    use anyhow::Context;
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp.chunk().await.context("reading response body")? {
        if body_cap_exceeded(buf.len(), chunk.len(), max_bytes) {
            anyhow::bail!(
                "response body exceeds {max_bytes} bytes — refusing to buffer \
                 (possible malicious or misconfigured endpoint)"
            );
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Read up to `max_bytes` of a response body as lossy UTF-8 for an error
/// message. Truncates instead of failing — used only on the non-2xx path.
pub(crate) async fn read_text_preview(mut resp: reqwest::Response, max_bytes: usize) -> String {
    let mut buf: Vec<u8> = Vec::new();
    while buf.len() < max_bytes {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let take = (max_bytes - buf.len()).min(chunk.len());
                buf.extend_from_slice(&chunk[..take]);
            }
            _ => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// POST `body` to `url`, retrying the transient failures, and return the parsed
/// JSON response.
///
/// Both HTTP providers route through here so the retry policy has one owner. The
/// request is rebuilt per attempt — cheap, and it avoids relying on a reqwest
/// body being cloneable.
///
/// `label` names the provider in log lines and errors. `decorate` adds the
/// provider's auth and version headers.
pub(crate) async fn post_json_with_retry<F>(
    client: &reqwest::Client,
    url: &str,
    body: &serde_json::Value,
    label: &str,
    decorate: F,
    cancel_token: Option<&CancellationToken>,
) -> Result<serde_json::Value>
where
    F: Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder,
{
    use anyhow::Context;

    let max_attempts = retry::max_attempts();
    let mut last_error = String::new();

    for attempt in 1..=max_attempts {
        let request = decorate(client.post(url))
            .json(body)
            .build()
            .context("Failed to build HTTP request")?;

        let outcome = if let Some(token) = cancel_token {
            tokio::select! {
                biased;
                _ = token.cancelled() => {
                    return Err(anyhow::anyhow!("LLM request cancelled by user"));
                }
                outcome = client.execute(request) => outcome,
            }
        } else {
            client.execute(request).await
        };

        let (retryable, retry_after, error_text) = match outcome {
            Ok(response) if response.status().is_success() => {
                let bytes = read_body_capped(response, MAX_RESPONSE_BYTES).await?;
                return serde_json::from_slice(&bytes)
                    .with_context(|| format!("parsing {label} response"));
            }
            Ok(response) => {
                let status = response.status();
                let retry_after = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| retry::parse_retry_after(v, chrono::Utc::now()));
                let text = read_text_preview(response, 64 * 1024).await;
                (
                    retry::is_retryable_status(status.as_u16()),
                    retry_after,
                    format!("{label} returned {status}: {text}"),
                )
            }
            Err(e) => (
                retry::is_retryable_transport_error(&e),
                None,
                format!("HTTP request to {label} failed: {e}"),
            ),
        };

        last_error = error_text;

        if !retryable {
            return Err(anyhow::anyhow!(last_error));
        }

        match retry::decide(attempt, max_attempts, retry_after) {
            retry::Decision::GiveUp => break,
            retry::Decision::RetryAfter(delay) => {
                crate::logging::warn(
                    "provider",
                    retry::retry_log_line(label, attempt, max_attempts, delay, &last_error),
                );
                retry::wait(delay, cancel_token).await?;
            }
        }
    }

    Err(anyhow::anyhow!(retry::exhausted_message(
        label,
        max_attempts,
        &last_error
    )))
}

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
    Assistant {
        content: String,
        tool_calls: Vec<ToolCall>,
    },
    /// Tool execution result to feed back to the assistant.
    ToolResult {
        id: String,
        name: String,
        content: String,
    },
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
        cancel_token: Option<&CancellationToken>,
    ) -> Result<CompletionResponse>;

    fn context_window(&self) -> u32;
    fn model_name(&self) -> &str;
}

#[cfg(test)]
mod body_cap_tests {
    use super::body_cap_exceeded;

    // F5: the accumulation guard that bounds how much of an LLM response body we
    // buffer, so a hostile/buggy endpoint can't OOM the scanner.
    #[test]
    fn rejects_when_next_chunk_would_exceed_cap() {
        assert!(body_cap_exceeded(0, 11, 10));
        assert!(body_cap_exceeded(6, 5, 10));
    }

    #[test]
    fn allows_up_to_cap() {
        assert!(!body_cap_exceeded(0, 10, 10));
        assert!(!body_cap_exceeded(5, 5, 10));
    }

    #[test]
    fn is_overflow_safe() {
        assert!(body_cap_exceeded(usize::MAX, 1, 100));
    }
}
