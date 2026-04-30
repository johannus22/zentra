use zentra_cli::auth::OAuthTokens;

#[test]
fn oauth_tokens_not_expired_when_future() {
    let future = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64 + 3600;
    let t = OAuthTokens {
        access_token: "at".to_string(),
        refresh_token: "rt".to_string(),
        expires_at: future,
    };
    assert!(!t.is_expired());
}

#[test]
fn oauth_tokens_expired_when_past() {
    let past = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64 - 1;
    let t = OAuthTokens {
        access_token: "at".to_string(),
        refresh_token: "rt".to_string(),
        expires_at: past,
    };
    assert!(t.is_expired());
}

#[test]
fn oauth_tokens_expire_within_buffer() {
    // Tokens within 60s of expiry are treated as expired
    let soon = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64 + 30;
    let t = OAuthTokens {
        access_token: "at".to_string(),
        refresh_token: "rt".to_string(),
        expires_at: soon,
    };
    assert!(t.is_expired());
}

#[test]
fn auth_method_default_is_api_key() {
    use zentra_cli::config::GlobalConfig;
    let toml = r#"
        [profiles.test]
        kind = "openai_compat"
        base_url = "https://api.openai.com/v1"
        model = "gpt-4o"
    "#;
    let cfg: GlobalConfig = toml::from_str(toml).unwrap();
    let profile = cfg.profiles.get("test").unwrap();
    assert!(matches!(profile.auth_method, zentra_cli::config::AuthMethod::ApiKey));
}

use zentra_cli::auth::{build_auth_url, generate_pkce};
use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{method, path};
use zentra_cli::auth::{exchange_code_with_url, refresh_access_token_with_url, parse_token_response};

#[test]
fn pkce_verifier_and_challenge_differ() {
    let (verifier, challenge) = generate_pkce();
    assert_ne!(verifier, challenge);
    assert!(!verifier.is_empty());
    assert!(!challenge.is_empty());
}

#[test]
fn pkce_verifier_is_url_safe() {
    let (verifier, challenge) = generate_pkce();
    for ch in verifier.chars() {
        assert!(ch.is_alphanumeric() || ch == '-' || ch == '_',
            "verifier contains non-URL-safe char: {}", ch);
    }
    for ch in challenge.chars() {
        assert!(ch.is_alphanumeric() || ch == '-' || ch == '_',
            "challenge contains non-URL-safe char: {}", ch);
    }
}

#[test]
fn pkce_two_calls_produce_different_verifiers() {
    let (v1, _) = generate_pkce();
    let (v2, _) = generate_pkce();
    assert_ne!(v1, v2);
}

#[test]
fn build_auth_url_contains_required_params() {
    let url = build_auth_url("mychallenge", "mystate");
    assert!(url.contains("mychallenge"), "missing code_challenge");
    assert!(url.contains("mystate"), "missing state");
    assert!(url.contains("S256"), "missing code_challenge_method");
    assert!(url.contains("localhost"), "missing localhost redirect");
    assert!(url.contains("response_type=code"), "missing response_type");
}

#[tokio::test]
async fn exchange_code_parses_tokens() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "tok_abc",
            "refresh_token": "ref_xyz",
            "expires_in": 3600,
            "token_type": "Bearer"
        })))
        .mount(&server)
        .await;

    let tokens = exchange_code_with_url("mycode", "myverifier", &server.uri()).await.unwrap();
    assert_eq!(tokens.access_token, "tok_abc");
    assert_eq!(tokens.refresh_token, "ref_xyz");
    assert!(!tokens.is_expired());
}

#[tokio::test]
async fn exchange_code_returns_error_on_failure() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "invalid_grant"
        })))
        .mount(&server)
        .await;

    let result = exchange_code_with_url("bad_code", "verifier", &server.uri()).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn refresh_token_returns_new_tokens() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "new_tok",
            "refresh_token": "new_ref",
            "expires_in": 7200,
            "token_type": "Bearer"
        })))
        .mount(&server)
        .await;

    let tokens = refresh_access_token_with_url("old_refresh", &server.uri()).await.unwrap();
    assert_eq!(tokens.access_token, "new_tok");
}

#[test]
fn parse_token_response_sets_expires_at_from_expires_in() {
    let json = serde_json::json!({
        "access_token": "at",
        "refresh_token": "rt",
        "expires_in": 3600
    });
    let tokens = parse_token_response(&json).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(tokens.expires_at > now + 3500);
    assert!(tokens.expires_at <= now + 3601);
}

#[tokio::test]
async fn ensure_fresh_token_returns_error_when_no_tokens() {
    let result = zentra_cli::auth::ensure_fresh_token("__nonexistent_profile_xyz__").await;
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("No OAuth tokens"), "got: {}", msg);
}
