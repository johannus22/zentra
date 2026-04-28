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
