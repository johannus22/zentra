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
