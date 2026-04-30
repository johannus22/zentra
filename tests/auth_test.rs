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
