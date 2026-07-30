use tokio_util::sync::CancellationToken;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use zentra_cli::provider::anthropic::AnthropicProvider;
use zentra_cli::provider::openai_compat::OpenAICompatProvider;
use zentra_cli::provider::{AgentMessage, CompletionRequest, LLMProvider, Message, ToolDefinition};

#[tokio::test]
async fn openai_compat_calls_correct_endpoint_with_auth() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(header("authorization", "Bearer test-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{"message": {"role": "assistant", "content": "pong"}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        })))
        .mount(&server)
        .await;

    let provider =
        OpenAICompatProvider::new(server.uri(), "gpt-4o".to_string(), "test-key".to_string());
    let resp = provider
        .complete(CompletionRequest {
            messages: vec![Message {
                role: "user".to_string(),
                content: "ping".to_string(),
            }],
            tools: vec![],
            max_tokens: Some(10),
        })
        .await
        .unwrap();

    assert_eq!(resp.content, "pong");
    assert_eq!(resp.usage.total_tokens, 15);
}

#[tokio::test]
async fn openai_compat_returns_error_on_4xx() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
        .mount(&server)
        .await;

    let provider =
        OpenAICompatProvider::new(server.uri(), "gpt-4o".to_string(), "bad-key".to_string());
    let result = provider
        .complete(CompletionRequest {
            messages: vec![Message {
                role: "user".to_string(),
                content: "hi".to_string(),
            }],
            tools: vec![],
            max_tokens: None,
        })
        .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("401"));
}

#[tokio::test]
async fn anthropic_uses_native_headers_and_endpoint() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/messages"))
        .and(header("x-api-key", "test-key"))
        .and(header("anthropic-version", "2023-06-01"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "content": [{"type": "text", "text": "pong"}],
            "usage": {"input_tokens": 10, "output_tokens": 5}
        })))
        .mount(&server)
        .await;

    let provider = AnthropicProvider::new(
        server.uri(),
        "claude-opus-4-7".to_string(),
        "test-key".to_string(),
    );
    let resp = provider
        .complete(CompletionRequest {
            messages: vec![Message {
                role: "user".to_string(),
                content: "ping".to_string(),
            }],
            tools: vec![],
            max_tokens: Some(10),
        })
        .await
        .unwrap();

    assert_eq!(resp.content, "pong");
    assert_eq!(resp.usage.input_tokens, 10);
    assert_eq!(resp.usage.output_tokens, 5);
    assert_eq!(resp.usage.total_tokens, 15);
}

#[tokio::test]
async fn openai_compat_complete_with_tools_sends_tool_call_request() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "read_file",
                            "arguments": "{\"path\": \"src/main.rs\"}"
                        }
                    }]
                }
            }],
            "usage": {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30}
        })))
        .mount(&server)
        .await;

    let provider =
        OpenAICompatProvider::new(server.uri(), "gpt-4o".to_string(), "test-key".to_string());
    let tools = vec![ToolDefinition {
        name: "read_file".to_string(),
        description: "Read a file".to_string(),
        parameters: serde_json::json!({"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}),
    }];
    let resp = provider
        .complete_with_tools(
            "You are a security scanner.",
            &[AgentMessage::User("List files.".to_string())],
            &tools,
            256,
            None,
        )
        .await
        .unwrap();

    assert_eq!(resp.tool_calls.len(), 1);
    assert_eq!(resp.tool_calls[0].name, "read_file");
    assert_eq!(resp.tool_calls[0].arguments["path"], "src/main.rs");
}

#[tokio::test]
async fn anthropic_complete_with_tools_parses_tool_use_block() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "content": [
                {"type": "text", "text": "I'll read that file."},
                {"type": "tool_use", "id": "call_1", "name": "read_file", "input": {"path": "src/main.rs"}}
            ],
            "usage": {"input_tokens": 20, "output_tokens": 10}
        })))
        .mount(&server)
        .await;

    let provider = AnthropicProvider::new(
        server.uri(),
        "claude-opus-4-7".to_string(),
        "test-key".to_string(),
    );
    let tools = vec![ToolDefinition {
        name: "read_file".to_string(),
        description: "Read a file".to_string(),
        parameters: serde_json::json!({"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}),
    }];
    let resp = provider
        .complete_with_tools(
            "You are a security scanner.",
            &[AgentMessage::User("List files.".to_string())],
            &tools,
            256,
            None,
        )
        .await
        .unwrap();

    assert_eq!(resp.content, "I'll read that file.");
    assert_eq!(resp.tool_calls.len(), 1);
    assert_eq!(resp.tool_calls[0].name, "read_file");
    assert_eq!(resp.tool_calls[0].id, "call_1");
}

#[tokio::test]
async fn openai_compat_cancels_on_token() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "choices": [{"message": {"role": "assistant", "content": "pong"}}],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
                }))
                .set_delay(std::time::Duration::from_secs(5)),
        )
        .mount(&server)
        .await;

    let provider =
        OpenAICompatProvider::new(server.uri(), "gpt-4o".to_string(), "test-key".to_string());
    let token = CancellationToken::new();
    let token_clone = token.clone();

    let handle = tokio::spawn(async move {
        provider
            .complete_with_tools(
                "system",
                &[AgentMessage::User("hi".to_string())],
                &[],
                256,
                Some(&token_clone),
            )
            .await
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    token.cancel();

    let result = tokio::time::timeout(tokio::time::Duration::from_secs(2), handle).await;

    assert!(result.is_ok(), "should finish quickly after cancel");
    let inner = result.unwrap().unwrap();
    assert!(inner.is_err(), "should return error when cancelled");
    assert!(inner.unwrap_err().to_string().contains("cancelled"));
}

#[tokio::test]
async fn openai_compat_includes_reasoning_effort_when_set() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
        })))
        .mount(&server)
        .await;

    let provider = OpenAICompatProvider::new(server.uri(), "m".to_string(), "k".to_string())
        .with_reasoning(Some("high".to_string()));
    provider
        .complete_with_tools("sys", &[AgentMessage::User("hi".to_string())], &[], 100, None)
        .await
        .unwrap();

    let requests = server.received_requests().await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body["reasoning_effort"], serde_json::json!("high"));
}

#[tokio::test]
async fn openai_compat_omits_reasoning_effort_when_unset() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
        })))
        .mount(&server)
        .await;

    let provider = OpenAICompatProvider::new(server.uri(), "m".to_string(), "k".to_string());
    provider
        .complete_with_tools("sys", &[AgentMessage::User("hi".to_string())], &[], 100, None)
        .await
        .unwrap();

    let requests = server.received_requests().await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert!(body.get("reasoning_effort").is_none());
}

#[test]
fn openai_compat_honors_context_window_override() {
    let p = OpenAICompatProvider::new(
        "https://api.example.com".to_string(),
        "some-unknown-model".to_string(),
        "key".to_string(),
    )
    .with_context_window(Some(131_072));
    assert_eq!(p.context_window(), 131_072);

    let default = OpenAICompatProvider::new(
        "https://api.example.com".to_string(),
        "some-unknown-model".to_string(),
        "key".to_string(),
    );
    assert_eq!(default.context_window(), 128_000); // existing fallback unchanged
}

// --- Sampling temperature (determinism) ---
//
// Neither provider used to send `temperature`, so every scan ran at the provider
// default (1.0 on Anthropic). These tests pin the wire half of the contract:
// a value is always present, a profile value wins, and a bad value is clamped.

async fn body_of_first_request(server: &MockServer) -> serde_json::Value {
    let reqs = server.received_requests().await.unwrap();
    serde_json::from_slice(&reqs[0].body).unwrap()
}

fn anthropic_ok() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "content": [{"type": "text", "text": "ok"}],
        "usage": {"input_tokens": 1, "output_tokens": 1}
    }))
}

fn openai_ok() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "choices": [{"message": {"role": "assistant", "content": "ok"}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    }))
}

#[tokio::test]
async fn anthropic_sends_default_temperature() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(anthropic_ok())
        .mount(&server)
        .await;

    let provider =
        AnthropicProvider::new(server.uri(), "claude-opus-4-7".to_string(), "k".to_string());
    provider
        .complete_with_tools("sys", &[AgentMessage::User("hi".to_string())], &[] as &[ToolDefinition], 64, None)
        .await
        .unwrap();

    let body = body_of_first_request(&server).await;
    assert!(
        (body["temperature"].as_f64().unwrap() - 0.2).abs() < 1e-9,
        "got: {body}"
    );
}

#[tokio::test]
async fn anthropic_sends_configured_temperature() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(anthropic_ok())
        .mount(&server)
        .await;

    let provider =
        AnthropicProvider::new(server.uri(), "claude-opus-4-7".to_string(), "k".to_string())
            .with_temperature(Some(0.0));
    provider
        .complete_with_tools("sys", &[AgentMessage::User("hi".to_string())], &[] as &[ToolDefinition], 64, None)
        .await
        .unwrap();

    let body = body_of_first_request(&server).await;
    assert!(
        (body["temperature"].as_f64().unwrap() - 0.0).abs() < 1e-9,
        "got: {body}"
    );
}

#[tokio::test]
async fn anthropic_clamps_out_of_range_temperature() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(anthropic_ok())
        .mount(&server)
        .await;

    let provider =
        AnthropicProvider::new(server.uri(), "claude-opus-4-7".to_string(), "k".to_string())
            .with_temperature(Some(9.5));
    provider
        .complete_with_tools("sys", &[AgentMessage::User("hi".to_string())], &[] as &[ToolDefinition], 64, None)
        .await
        .unwrap();

    let body = body_of_first_request(&server).await;
    assert!(
        (body["temperature"].as_f64().unwrap() - 2.0).abs() < 1e-9,
        "got: {body}"
    );
}

#[tokio::test]
async fn anthropic_sends_temperature_on_the_plain_complete_path_too() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(anthropic_ok())
        .mount(&server)
        .await;

    let provider =
        AnthropicProvider::new(server.uri(), "claude-opus-4-7".to_string(), "k".to_string())
            .with_temperature(Some(0.0));
    provider
        .complete(CompletionRequest {
            messages: vec![Message {
                role: "user".to_string(),
                content: "hi".to_string(),
            }],
            tools: vec![],
            max_tokens: Some(16),
        })
        .await
        .unwrap();

    let body = body_of_first_request(&server).await;
    assert!(
        (body["temperature"].as_f64().unwrap() - 0.0).abs() < 1e-9,
        "got: {body}"
    );
}

#[tokio::test]
async fn openai_compat_sends_default_temperature() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(openai_ok())
        .mount(&server)
        .await;

    let provider = OpenAICompatProvider::new(server.uri(), "gpt-4o".to_string(), "k".to_string());
    provider
        .complete_with_tools("sys", &[AgentMessage::User("hi".to_string())], &[] as &[ToolDefinition], 64, None)
        .await
        .unwrap();

    let body = body_of_first_request(&server).await;
    assert!(
        (body["temperature"].as_f64().unwrap() - 0.2).abs() < 1e-9,
        "got: {body}"
    );
}

#[tokio::test]
async fn openai_compat_sends_configured_temperature() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(openai_ok())
        .mount(&server)
        .await;

    let provider = OpenAICompatProvider::new(server.uri(), "gpt-4o".to_string(), "k".to_string())
        .with_temperature(Some(0.0));
    provider
        .complete_with_tools("sys", &[AgentMessage::User("hi".to_string())], &[] as &[ToolDefinition], 64, None)
        .await
        .unwrap();

    let body = body_of_first_request(&server).await;
    assert!(
        (body["temperature"].as_f64().unwrap() - 0.0).abs() < 1e-9,
        "got: {body}"
    );
}

// --- Transient-failure retry ---
//
// A single 429 used to kill a scanner on its first call, so a rate-limited
// provider took out a whole scan and still printed a completion banner.

use wiremock::matchers::header_exists;

fn ok_openai() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "choices": [{"message": {"role": "assistant", "content": "ok"}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    }))
}

fn ok_anthropic() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "content": [{"type": "text", "text": "ok"}],
        "usage": {"input_tokens": 1, "output_tokens": 1}
    }))
}

#[tokio::test]
async fn retries_a_429_then_succeeds() {
    let server = MockServer::start().await;

    // First call is rate limited with a short Retry-After; the second succeeds.
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "0")
                .set_body_string("Too Many Requests"),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ok_openai())
        .mount(&server)
        .await;

    let provider = OpenAICompatProvider::new(server.uri(), "gpt-4o".to_string(), "k".to_string());
    let response = provider
        .complete_with_tools(
            "sys",
            &[AgentMessage::User("hi".to_string())],
            &[] as &[ToolDefinition],
            64,
            None,
        )
        .await
        .expect("a 429 followed by a 200 must succeed");

    assert_eq!(response.content, "ok");
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        2,
        "the call should have been retried exactly once"
    );
}

#[tokio::test]
async fn retries_a_500_then_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ok_openai())
        .mount(&server)
        .await;

    let provider = OpenAICompatProvider::new(server.uri(), "gpt-4o".to_string(), "k".to_string());
    let response = provider
        .complete_with_tools(
            "sys",
            &[AgentMessage::User("hi".to_string())],
            &[] as &[ToolDefinition],
            64,
            None,
        )
        .await
        .unwrap();

    assert_eq!(response.content, "ok");
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn does_not_retry_a_401() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
        .mount(&server)
        .await;

    let provider = OpenAICompatProvider::new(server.uri(), "gpt-4o".to_string(), "bad".to_string());
    let error = provider
        .complete_with_tools(
            "sys",
            &[AgentMessage::User("hi".to_string())],
            &[] as &[ToolDefinition],
            64,
            None,
        )
        .await
        .expect_err("a wrong key must fail immediately");

    assert!(error.to_string().contains("401"), "got: {error}");
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "a permanent error must not be retried — that only delays the real message"
    );
}

#[tokio::test]
async fn gives_up_after_the_attempt_budget_and_says_how_many() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "0")
                .set_body_string("Too Many Requests"),
        )
        .mount(&server)
        .await;

    let provider = OpenAICompatProvider::new(server.uri(), "gpt-4o".to_string(), "k".to_string());
    let error = provider
        .complete_with_tools(
            "sys",
            &[AgentMessage::User("hi".to_string())],
            &[] as &[ToolDefinition],
            64,
            None,
        )
        .await
        .expect_err("a sustained rate limit must still fail");

    let message = error.to_string();
    assert!(message.contains("attempt(s)"), "got: {message}");
    assert!(message.contains("429"), "got: {message}");
    assert!(
        message.contains("ZENTRA_PROVIDER_MAX_ATTEMPTS"),
        "the operator needs to know the knob exists: {message}"
    );
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        zentra_cli::provider::retry::MAX_ATTEMPTS as usize,
        "exactly the attempt budget, no more"
    );
}

#[tokio::test]
async fn refuses_a_retry_after_longer_than_it_will_wait() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "600")
                .set_body_string("Too Many Requests"),
        )
        .mount(&server)
        .await;

    let provider = OpenAICompatProvider::new(server.uri(), "gpt-4o".to_string(), "k".to_string());
    let error = provider
        .complete_with_tools(
            "sys",
            &[AgentMessage::User("hi".to_string())],
            &[] as &[ToolDefinition],
            64,
            None,
        )
        .await
        .expect_err("a ten-minute wait must be reported, not slept through");

    assert!(error.to_string().contains("429"), "got: {error}");
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "one attempt, then report — a scan must not stall for ten minutes"
    );
}

#[tokio::test]
async fn cancellation_beats_a_pending_retry() {
    let server = MockServer::start().await;
    // No Retry-After, so the backoff is at least a second — long enough that a
    // cancelled scan would visibly stall if `wait` ignored the token.
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(429).set_body_string("Too Many Requests"))
        .mount(&server)
        .await;

    let provider = OpenAICompatProvider::new(server.uri(), "gpt-4o".to_string(), "k".to_string());
    let token = CancellationToken::new();
    let cancel_handle = token.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        cancel_handle.cancel();
    });

    let started = std::time::Instant::now();
    let error = provider
        .complete_with_tools(
            "sys",
            &[AgentMessage::User("hi".to_string())],
            &[] as &[ToolDefinition],
            64,
            Some(&token),
        )
        .await
        .expect_err("a cancelled scan must not finish the backoff");

    assert!(
        started.elapsed() < std::time::Duration::from_secs(3),
        "cancellation should cut the backoff short, took {:?}",
        started.elapsed()
    );
    assert!(error.to_string().contains("cancelled"), "got: {error}");
}

#[tokio::test]
async fn anthropic_retries_too_and_keeps_its_headers() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/messages"))
        .and(header_exists("x-api-key"))
        .and(header_exists("anthropic-version"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "0")
                .set_body_string("Too Many Requests"),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/messages"))
        .and(header_exists("x-api-key"))
        .and(header_exists("anthropic-version"))
        .respond_with(ok_anthropic())
        .mount(&server)
        .await;

    let provider = AnthropicProvider::new(
        server.uri(),
        "claude-opus-4-7".to_string(),
        "k".to_string(),
    );
    let response = provider
        .complete_with_tools(
            "sys",
            &[AgentMessage::User("hi".to_string())],
            &[] as &[ToolDefinition],
            64,
            None,
        )
        .await
        .expect("the rebuilt retry request must carry the auth headers");

    assert_eq!(response.content, "ok");
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn a_retried_request_resends_the_same_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "0")
                .set_body_string("Too Many Requests"),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ok_openai())
        .mount(&server)
        .await;

    let provider = OpenAICompatProvider::new(server.uri(), "gpt-4o".to_string(), "k".to_string())
        .with_temperature(Some(0.0));
    provider
        .complete_with_tools(
            "sys",
            &[AgentMessage::User("distinctive-marker".to_string())],
            &[] as &[ToolDefinition],
            64,
            None,
        )
        .await
        .unwrap();

    // The request is rebuilt per attempt, so verify the second one is not empty
    // or truncated — a consumed body would silently send nothing.
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    for request in &requests {
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert!(
            body["messages"]
                .as_array()
                .unwrap()
                .iter()
                .any(|m| m["content"].as_str() == Some("distinctive-marker")),
            "every attempt must carry the full body, got: {body}"
        );
        assert!((body["temperature"].as_f64().unwrap() - 0.0).abs() < 1e-9);
    }
}
