use wiremock::{Mock, MockServer, ResponseTemplate};
use wiremock::matchers::{header, method, path};
use zentra_cli::provider::{CompletionRequest, LLMProvider, Message};
use zentra_cli::provider::openai_compat::OpenAICompatProvider;
use zentra_cli::provider::anthropic::AnthropicProvider;

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

    let provider = OpenAICompatProvider::new(
        server.uri(), "gpt-4o".to_string(), "test-key".to_string(),
    );
    let resp = provider.complete(CompletionRequest {
        messages: vec![Message { role: "user".to_string(), content: "ping".to_string() }],
        tools: vec![],
        max_tokens: Some(10),
    }).await.unwrap();

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

    let provider = OpenAICompatProvider::new(
        server.uri(), "gpt-4o".to_string(), "bad-key".to_string(),
    );
    let result = provider.complete(CompletionRequest {
        messages: vec![Message { role: "user".to_string(), content: "hi".to_string() }],
        tools: vec![],
        max_tokens: None,
    }).await;

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
        server.uri(), "claude-opus-4-7".to_string(), "test-key".to_string(),
    );
    let resp = provider.complete(CompletionRequest {
        messages: vec![Message { role: "user".to_string(), content: "ping".to_string() }],
        tools: vec![],
        max_tokens: Some(10),
    }).await.unwrap();

    assert_eq!(resp.content, "pong");
    assert_eq!(resp.usage.input_tokens, 10);
    assert_eq!(resp.usage.output_tokens, 5);
    assert_eq!(resp.usage.total_tokens, 15);
}
