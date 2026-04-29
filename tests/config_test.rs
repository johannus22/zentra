use std::collections::HashMap;
use tempfile::TempDir;
use zentra_cli::config::{GlobalConfig, ProviderProfile, ProjectConfig};
use zentra_cli::wizard::provider_defaults;

#[test]
fn global_config_roundtrip() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("config.toml");

    let mut profiles = HashMap::new();
    profiles.insert("openai".to_string(), ProviderProfile {
        kind: "openai_compat".to_string(),
        base_url: "https://api.openai.com/v1".to_string(),
        model: "gpt-4o".to_string(),
        keyless: false,
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

#[test]
fn project_config_roundtrip() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join(".zentra").join("config.json");
    let config = ProjectConfig::new("rust", vec!["dist/".to_string()]);
    config.save_to(&path).unwrap();
    let loaded = ProjectConfig::load_from(&path).unwrap();
    assert_eq!(loaded.stack, "rust");
    assert_eq!(loaded.exclusions, vec!["dist/"]);
}

#[test]
fn detect_stack_rust() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("Cargo.toml"), "[package]").unwrap();
    assert_eq!(ProjectConfig::detect_stack(dir.path()), "rust");
}

#[test]
fn detect_stack_node() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("package.json"), "{}").unwrap();
    assert_eq!(ProjectConfig::detect_stack(dir.path()), "node");
}

#[test]
fn looks_like_codebase_true_for_src_dir() {
    let dir = TempDir::new().unwrap();
    std::fs::create_dir(dir.path().join("src")).unwrap();
    assert!(ProjectConfig::looks_like_codebase(dir.path()));
}

#[test]
fn looks_like_codebase_false_for_empty_dir() {
    let dir = TempDir::new().unwrap();
    assert!(!ProjectConfig::looks_like_codebase(dir.path()));
}

#[test]
fn init_adds_zentra_to_gitignore() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join(".gitignore"), "node_modules/\n").unwrap();
    zentra_cli::commands::init::update_gitignore_at(dir.path()).unwrap();
    let content = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
    assert!(content.contains(".zentra/"));
}

#[test]
fn init_does_not_duplicate_zentra_entry() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join(".gitignore"), ".zentra/\n").unwrap();
    zentra_cli::commands::init::update_gitignore_at(dir.path()).unwrap();
    let content = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
    assert_eq!(content.matches(".zentra/").count(), 1);
}

#[test]
fn init_creates_gitignore_if_missing() {
    let dir = TempDir::new().unwrap();
    zentra_cli::commands::init::update_gitignore_at(dir.path()).unwrap();
    assert!(dir.path().join(".gitignore").exists());
    let content = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
    assert!(content.contains(".zentra/"));
}

#[test]
fn provider_defaults_openai_prefills_url_and_models() {
    let d = provider_defaults("openai");
    assert_eq!(d.base_url, "https://api.openai.com/v1");
    assert!(d.models.contains(&"gpt-4o".to_string()));
    assert!(!d.keyless);
    assert_eq!(d.kind, "openai_compat");
}

#[test]
fn provider_defaults_anthropic_prefills_url() {
    let d = provider_defaults("anthropic");
    assert_eq!(d.base_url, "https://api.anthropic.com");
    assert!(d.models.contains(&"claude-opus-4-7".to_string()));
    assert_eq!(d.kind, "anthropic");
}

#[test]
fn provider_defaults_ollama_is_keyless() {
    let d = provider_defaults("ollama");
    assert_eq!(d.base_url, "http://localhost:11434/v1");
    assert!(d.keyless);
}

#[test]
fn provider_defaults_litellm_has_empty_base_url() {
    let d = provider_defaults("litellm");
    assert!(d.base_url.is_empty());
    assert!(!d.keyless);
}

#[test]
fn global_config_load_from_missing_path_is_empty() {
    let config = GlobalConfig::load_from(
        &std::path::PathBuf::from("/tmp/zentra-test-no-such-file-12345/config.toml")
    ).unwrap();
    assert!(config.profiles.is_empty());
    assert!(config.default_profile.is_none());
}
