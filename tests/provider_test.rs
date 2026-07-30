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
