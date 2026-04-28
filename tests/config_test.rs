use std::collections::HashMap;
use tempfile::TempDir;
use zentra_cli::config::{GlobalConfig, ProviderProfile};

#[test]
fn global_config_roundtrip() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("config.toml");

    let mut profiles = HashMap::new();
    profiles.insert("openai".to_string(), ProviderProfile {
        kind: "openai_compat".to_string(),
        base_url: "https://api.openai.com/v1".to_string(),
        model: "gpt-4o".to_string(),
    });

    let config = GlobalConfig { profiles, default_profile: Some("openai".to_string()) };
    config.save_to(&path).unwrap();

    let loaded = GlobalConfig::load_from(&path).unwrap();
    assert_eq!(loaded.default_profile, Some("openai".to_string()));
    assert!(loaded.profiles.contains_key("openai"));
    assert_eq!(loaded.profiles["openai"].model, "gpt-4o");
}

#[test]
fn global_config_missing_file_returns_empty() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("nonexistent.toml");
    let config = GlobalConfig::load_from(&path).unwrap();
    assert!(config.profiles.is_empty());
    assert!(config.default_profile.is_none());
}

#[test]
fn keychain_service_name_is_scoped_per_profile() {
    assert_eq!(zentra_cli::config::keychain::service_name("openai"), "zentra/openai");
    assert_eq!(zentra_cli::config::keychain::service_name("work-litellm"), "zentra/work-litellm");
}

#[test]
fn masked_display_never_shows_key_chars() {
    let masked = zentra_cli::config::keychain::masked_display();
    assert!(!masked.contains("sk-"));
    assert!(masked.len() > 4);
}
