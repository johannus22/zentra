use std::collections::HashMap;
use tempfile::TempDir;
use zentra_cli::config::validation::validate_provider_base_url;
use zentra_cli::config::{GlobalConfig, ProjectConfig, ProviderProfile};
use zentra_cli::wizard::provider_defaults;

#[test]
fn global_config_roundtrip() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("config.toml");

    let mut profiles = HashMap::new();
    profiles.insert(
        "openai".to_string(),
        ProviderProfile {
            kind: "openai_compat".to_string(),
            base_url: "https://api.openai.com/v1".to_string(),
            model: "gpt-4o".to_string(),
            keyless: false,
            auth_method: Default::default(),
            context_window: None,
            reasoning_effort: None,
        },
    );

    let config = GlobalConfig {
        profiles,
        default_profile: Some("openai".to_string()),
        output_dir: None,
        theme: None,
    };
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
    assert_eq!(
        zentra_cli::config::keychain::service_name("openai"),
        "zentra.openai"
    );
    assert_eq!(
        zentra_cli::config::keychain::service_name("work-litellm"),
        "zentra.work-litellm"
    );
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
    assert!(d.models.contains(&"gpt-5.5".to_string()));
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
    assert_eq!(d.base_url, "https://ollama.com/v1");
    assert!(d.keyless);
}

#[test]
fn provider_defaults_custom_prefills_https_scheme() {
    let d = provider_defaults("custom");
    assert_eq!(d.base_url, "https://");
    assert!(!d.keyless);
}

#[test]
fn global_config_load_from_missing_path_is_empty() {
    let config = GlobalConfig::load_from(&std::path::PathBuf::from(
        "/tmp/zentra-test-no-such-file-12345/config.toml",
    ))
    .unwrap();
    assert!(config.profiles.is_empty());
    assert!(config.default_profile.is_none());
}

#[test]
fn provider_profile_context_window_defaults_to_none() {
    use zentra_cli::config::GlobalConfig;
    let toml = r#"
        [profiles.test]
        kind = "openai_compat"
        base_url = "https://api.openai.com/v1"
        model = "gpt-4o"
    "#;
    let cfg: GlobalConfig = toml::from_str(toml).unwrap();
    let profile = cfg.profiles.get("test").unwrap();
    assert!(profile.context_window.is_none());
}

#[test]
fn provider_profile_auth_method_defaults_to_api_key() {
    use zentra_cli::config::{AuthMethod, GlobalConfig};
    let toml = r#"
        [profiles.openai]
        kind = "openai_compat"
        base_url = "https://api.openai.com/v1"
        model = "gpt-4o"
    "#;
    let cfg: GlobalConfig = toml::from_str(toml).unwrap();
    let profile = cfg.profiles.get("openai").unwrap();
    assert_eq!(profile.auth_method, AuthMethod::ApiKey);
}

#[test]
fn provider_profile_context_window_round_trips() {
    use zentra_cli::config::{GlobalConfig, ProviderProfile};
    let mut cfg = GlobalConfig::default();
    cfg.profiles.insert(
        "myprofile".to_string(),
        ProviderProfile {
            kind: "openai_compat".to_string(),
            base_url: "https://api.openai.com/v1".to_string(),
            model: "gpt-4o".to_string(),
            keyless: false,
            auth_method: Default::default(),
            context_window: Some(64_000),
            reasoning_effort: None,
        },
    );
    let serialized = toml::to_string_pretty(&cfg).unwrap();
    let deserialized: GlobalConfig = toml::from_str(&serialized).unwrap();
    assert_eq!(
        deserialized.profiles["myprofile"].context_window,
        Some(64_000)
    );
}

#[test]
fn model_context_window_returns_known_values() {
    use zentra_cli::wizard::model_context_window;
    assert_eq!(model_context_window("gpt-4o"), 128_000);
    assert_eq!(model_context_window("claude-opus-4-7"), 200_000);
    assert_eq!(model_context_window("glm-4-flash"), 128_000);
    assert_eq!(model_context_window("unknown-model"), 128_000);
}

#[test]
fn provider_base_url_validation_accepts_https_remote_url() {
    assert!(validate_provider_base_url("https://api.openai.com/v1").is_ok());
}

#[test]
fn provider_base_url_validation_rejects_missing_scheme() {
    assert!(validate_provider_base_url("api.openai.com/v1").is_err());
}

#[test]
fn provider_base_url_validation_allows_localhost_http() {
    assert!(validate_provider_base_url("http://localhost:11434/v1").is_ok());
    assert!(validate_provider_base_url("http://127.0.0.1:11434/v1").is_ok());
}

#[test]
fn provider_base_url_validation_rejects_http_remote_url() {
    assert!(validate_provider_base_url("http://api.openai.com/v1").is_err());
}

#[test]
fn provider_base_url_validation_rejects_http_ipv6_loopback_url() {
    assert!(validate_provider_base_url("http://[::1]:11434/v1").is_err());
}

#[test]
fn provider_base_url_validation_rejects_empty_or_whitespace_input() {
    assert!(validate_provider_base_url("").is_err());
    assert!(validate_provider_base_url("   \t\n").is_err());
}

#[test]
fn provider_base_url_validation_rejects_unsupported_scheme() {
    assert!(validate_provider_base_url("ftp://localhost:11434/v1").is_err());
}

// ── Custom Providers ────────────────────────────────────────────────────────

use zentra_cli::config::custom_providers::CustomProvidersFile;

#[test]
fn custom_providers_loads_valid_file() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("providers.toml");
    std::fs::write(
        &path,
        r#"
[[providers]]
name = "company-llm"
display_name = "Company LLM"
base_url = "https://llm.mycompany.com/v1"
default_model = "llama-3.3-70b"
kind = "openai_compat"
keyless = false
"#,
    )
    .unwrap();
    let file = CustomProvidersFile::load_from(&path);
    assert_eq!(file.providers.len(), 1);
    let cp = &file.providers[0];
    assert_eq!(cp.name, "company-llm");
    assert_eq!(cp.base_url, "https://llm.mycompany.com/v1");
    assert_eq!(cp.default_model, "llama-3.3-70b");
    assert_eq!(cp.kind, "openai_compat");
    assert!(!cp.keyless);
    assert_eq!(cp.display_name.as_deref(), Some("Company LLM"));
}

#[test]
fn custom_providers_missing_file_returns_empty() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("no-such-file.toml");
    let file = CustomProvidersFile::load_from(&path);
    assert!(file.providers.is_empty());
}

#[test]
fn custom_providers_malformed_toml_returns_empty() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("providers.toml");
    std::fs::write(&path, "this is [[[not valid toml").unwrap();
    let file = CustomProvidersFile::load_from(&path);
    assert!(file.providers.is_empty());
}

#[test]
fn custom_providers_skips_entry_missing_required_field() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("providers.toml");
    std::fs::write(
        &path,
        r#"
[[providers]]
name = "good"
base_url = "https://good.example.com/v1"
default_model = "gpt-4o"

[[providers]]
name = "bad-no-base-url"
default_model = "gpt-4o"
"#,
    )
    .unwrap();
    let file = CustomProvidersFile::load_from(&path);
    assert_eq!(file.providers.len(), 1);
    assert_eq!(file.providers[0].name, "good");
}

#[test]
fn custom_providers_display_name_defaults_to_name() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("providers.toml");
    std::fs::write(
        &path,
        r#"
[[providers]]
name = "my-provider"
base_url = "https://example.com/v1"
default_model = "gpt-4o"
"#,
    )
    .unwrap();
    let file = CustomProvidersFile::load_from(&path);
    assert_eq!(file.providers[0].effective_display_name(), "my-provider");
}

#[test]
fn custom_providers_kind_defaults_to_openai_compat() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("providers.toml");
    std::fs::write(
        &path,
        r#"
[[providers]]
name = "my-provider"
base_url = "https://example.com/v1"
default_model = "gpt-4o"
"#,
    )
    .unwrap();
    let file = CustomProvidersFile::load_from(&path);
    assert_eq!(file.providers[0].kind, "openai_compat");
}

#[test]
fn custom_providers_file_with_nameless_entry_keeps_valid_entries() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("providers.toml");
    std::fs::write(
        &path,
        r#"
[[providers]]
name = "good"
base_url = "https://good.example.com/v1"
default_model = "gpt-4o"

[[providers]]
base_url = "https://bad.example.com/v1"
default_model = "gpt-4o"
"#,
    )
    .unwrap();
    let file = CustomProvidersFile::load_from(&path);
    assert_eq!(
        file.providers.len(),
        1,
        "valid entry should be kept despite nameless sibling"
    );
    assert_eq!(file.providers[0].name, "good");
}

#[test]
fn custom_providers_display_name_empty_string_falls_back_to_name() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("providers.toml");
    std::fs::write(
        &path,
        r#"
[[providers]]
name = "my-provider"
display_name = ""
base_url = "https://example.com/v1"
default_model = "gpt-4o"
"#,
    )
    .unwrap();
    let file = CustomProvidersFile::load_from(&path);
    assert_eq!(file.providers[0].effective_display_name(), "my-provider");
}

#[test]
fn custom_providers_empty_kind_is_skipped() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("providers.toml");
    std::fs::write(
        &path,
        r#"
[[providers]]
name = "bad-kind"
base_url = "https://example.com/v1"
default_model = "gpt-4o"
kind = ""
"#,
    )
    .unwrap();
    let file = CustomProvidersFile::load_from(&path);
    assert!(file.providers.is_empty());
}

// ── Keychain File Fallback ─────────────────────────────────────────────────

use zentra_cli::config::keychain;

#[test]
fn output_base_dir_defaults_to_documents_zentra() {
    use zentra_cli::config::GlobalConfig;
    let cfg = GlobalConfig::default();
    let base = cfg.output_base_dir();
    assert!(
        base.ends_with("Zentra"),
        "default output base should end with Zentra, got {base:?}"
    );
    assert_eq!(base, GlobalConfig::default_output_base_dir());
}

#[test]
fn output_base_dir_uses_configured_override() {
    use zentra_cli::config::GlobalConfig;
    let cfg = GlobalConfig {
        output_dir: Some("/mnt/c/Users/me/Documents/Zentra".to_string()),
        ..Default::default()
    };
    assert_eq!(
        cfg.output_base_dir(),
        std::path::PathBuf::from("/mnt/c/Users/me/Documents/Zentra")
    );
}

#[test]
fn output_base_dir_blank_override_falls_back_to_default() {
    use zentra_cli::config::GlobalConfig;
    let cfg = GlobalConfig {
        output_dir: Some("   ".to_string()),
        ..Default::default()
    };
    assert_eq!(cfg.output_base_dir(), GlobalConfig::default_output_base_dir());
}

#[test]
fn output_base_dir_expands_leading_tilde() {
    use zentra_cli::config::GlobalConfig;
    let Some(home) = dirs::home_dir() else {
        return; // no home dir on this platform — skip
    };
    let cfg = GlobalConfig {
        output_dir: Some("~/scans/zentra".to_string()),
        ..Default::default()
    };
    assert_eq!(cfg.output_base_dir(), home.join("scans").join("zentra"));
}

#[test]
fn provider_profile_reasoning_effort_defaults_to_none() {
    use zentra_cli::config::GlobalConfig;
    let toml = r#"
        [profiles.test]
        kind = "openai_compat"
        base_url = "https://api.openai.com/v1"
        model = "gpt-4o"
    "#;
    let cfg: GlobalConfig = toml::from_str(toml).unwrap();
    let profile = cfg.profiles.get("test").unwrap();
    assert!(profile.reasoning_effort.is_none());
}

#[test]
fn provider_profile_reasoning_effort_round_trips() {
    use zentra_cli::config::{GlobalConfig, ProviderProfile};
    let mut cfg = GlobalConfig::default();
    cfg.profiles.insert(
        "r".to_string(),
        ProviderProfile {
            kind: "openai_compat".to_string(),
            base_url: "https://api.openai.com/v1".to_string(),
            model: "gpt-4o".to_string(),
            keyless: false,
            auth_method: Default::default(),
            context_window: None,
            reasoning_effort: Some("high".to_string()),
        },
    );
    let serialized = toml::to_string_pretty(&cfg).unwrap();
    let deserialized: GlobalConfig = toml::from_str(&serialized).unwrap();
    assert_eq!(
        deserialized.profiles["r"].reasoning_effort.as_deref(),
        Some("high")
    );
}

#[test]
fn global_config_theme_roundtrips() {
    use zentra_cli::config::GlobalConfig;
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("config.toml");

    let mut cfg = GlobalConfig::default();
    cfg.theme = Some("matrix".to_string());
    cfg.save_to(&path).unwrap();

    let loaded = GlobalConfig::load_from(&path).unwrap();
    assert_eq!(loaded.theme, Some("matrix".to_string()));
}

#[test]
fn set_key_writes_key_file_by_default() {
    let profile = "zentra-test-setkey-default";
    let path = keychain::key_file_path(profile).expect("home dir required");
    let _ = std::fs::remove_file(&path);

    let storage = keychain::set_key(profile, "sk-default-file-key").expect("set_key should succeed");
    assert!(
        matches!(storage, keychain::KeyStorage::File),
        "keys should be stored in a file by default, not the keychain"
    );
    assert!(
        path.exists(),
        "API key should be written to the .key file by default"
    );

    let result = keychain::get_key(profile).expect("get_key should not error");
    assert_eq!(result, Some("sk-default-file-key".to_string()));

    keychain::delete_key(profile).expect("cleanup should succeed");
    assert!(!path.exists(), "file should be gone after delete_key");
}

#[test]
fn keychain_file_fallback_get_reads_key_file() {
    let profile = "zentra-test-fb-read";
    let path = keychain::key_file_path(profile).expect("home dir required");
    // Clear any pre-existing keyring entry so the file fallback path is exercised
    let _ = keychain::delete_key(profile);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "test-api-key-value").unwrap();

    // keyring has no entry for this profile → falls through to file
    let result = keychain::get_key(profile).expect("get_key should not error");
    let _ = std::fs::remove_file(&path);
    assert_eq!(result, Some("test-api-key-value".to_string()));
}

#[test]
fn keychain_file_fallback_delete_removes_file() {
    let profile = "zentra-test-fb-del";
    let path = keychain::key_file_path(profile).expect("home dir required");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "dummy-key").unwrap();

    keychain::delete_key(profile).expect("delete_key should not error");

    assert!(!path.exists(), "file should be removed after delete_key");
}

#[test]
fn keychain_get_returns_none_when_both_absent() {
    // Profile name unlikely to exist in any real keychain or file
    let result = keychain::get_key("zentra-test-absent-zzzzz").expect("get_key should not error");
    assert_eq!(result, None);
}
