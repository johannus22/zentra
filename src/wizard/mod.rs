use crate::config::custom_providers::{CustomProvider, CustomProvidersFile};
use anyhow::Result;

pub const KNOWN_PROVIDER_NAMES: &[&str] = &[
    "anthropic",
    "openai",
    "cerebras",
    "custom",
    "ollama",
    "zhipu",
    "claude_cli",
    "codex_cli",
];

pub struct ProviderDefaults {
    pub base_url: String,
    pub models: Vec<String>,
    pub kind: String,
    pub keyless: bool,
}

pub fn model_context_window(model: &str) -> u32 {
    if model.contains("gpt-4o")
        || model.contains("o1")
        || model.contains("glm-4")
        || model.contains("llama-3")
    {
        128_000
    } else if model.contains("claude") {
        200_000
    } else if model.contains("gpt-3.5") {
        16_000
    } else {
        32_000
    }
}

pub fn provider_defaults(provider: &str) -> ProviderDefaults {
    match provider {
        "openai" => ProviderDefaults {
            base_url: "https://api.openai.com/v1".to_string(),
            models: vec![
                "gpt-5.5".to_string(),
                "gpt-5.4".to_string(),
                "gpt-5.4-mini".to_string(),
            ],
            kind: "openai_compat".to_string(),
            keyless: false,
        },
        "anthropic" => ProviderDefaults {
            base_url: "https://api.anthropic.com".to_string(),
            models: vec![
                "claude-opus-4-7".to_string(),
                "claude-sonnet-4-6".to_string(),
            ],
            kind: "anthropic".to_string(),
            keyless: false,
        },
        "cerebras" => ProviderDefaults {
            base_url: "https://api.cerebras.ai/v1".to_string(),
            models: vec!["llama-3.3-70b".to_string()],
            kind: "openai_compat".to_string(),
            keyless: false,
        },
        "custom" => ProviderDefaults {
            // Pre-fill the scheme so the user only has to type the host/path.
            base_url: "https://".to_string(),
            models: vec![],
            kind: "openai_compat".to_string(),
            keyless: false,
        },
        "ollama" => ProviderDefaults {
            base_url: "https://ollama.com/v1".to_string(),
            models: vec!["gemma3".to_string()],
            kind: "openai_compat".to_string(),
            keyless: true,
        },
        "zhipu" => ProviderDefaults {
            base_url: "https://open.bigmodel.cn/api/paas/v4".to_string(),
            models: vec![
                "glm-4-flash".to_string(),
                "glm-4-plus".to_string(),
                "glm-4-air".to_string(),
            ],
            kind: "openai_compat".to_string(),
            keyless: false,
        },
        "claude_cli" => ProviderDefaults {
            base_url: "claude".to_string(),
            models: vec!["claude-opus-4-8".to_string()],
            kind: "claude_cli".to_string(),
            keyless: true,
        },
        "codex_cli" => ProviderDefaults {
            base_url: "codex".to_string(),
            models: vec!["gpt-5.5".to_string()],
            kind: "codex_cli".to_string(),
            keyless: true,
        },
        _ => ProviderDefaults {
            base_url: String::new(),
            models: vec![],
            kind: "openai_compat".to_string(),
            keyless: false,
        },
    }
}

/// Returns (has_claude, has_codex) based on whether the binaries are on PATH.
fn detect_cli_binaries() -> (bool, bool) {
    let has_claude = which::which("claude").is_ok();
    let has_codex = which::which("codex").is_ok();
    (has_claude, has_codex)
}

impl From<&CustomProvider> for ProviderDefaults {
    fn from(cp: &CustomProvider) -> Self {
        ProviderDefaults {
            base_url: cp.base_url.clone(),
            models: vec![cp.default_model.clone()],
            kind: cp.kind.clone(),
            keyless: cp.keyless,
        }
    }
}

pub async fn run_setup(profile_name: Option<String>) -> Result<()> {
    use crate::{
        config::{keychain, AuthMethod, GlobalConfig, ProviderProfile},
        provider,
    };
    use std::io::{self, Write};

    let (has_claude, has_codex) = detect_cli_binaries();
    let mut providers: Vec<&str> = vec!["openai", "anthropic", "cerebras", "custom", "ollama", "zhipu"];
    if has_claude {
        providers.push("claude_cli");
    }
    if has_codex {
        providers.push("codex_cli");
    }
    let providers = providers; // freeze

    // Load user-defined provider presets from ~/.zentra/providers.toml
    let custom_file = CustomProvidersFile::load();
    let valid_customs: Vec<&CustomProvider> = custom_file
        .providers
        .iter()
        .filter(|cp| {
            if providers.iter().any(|s| s.eq_ignore_ascii_case(&cp.name)) {
                eprintln!(
                    "⚠ custom provider '{}' conflicts with built-in name — skipped",
                    cp.name
                );
                false
            } else {
                true
            }
        })
        .collect();

    println!("\n Zentra — Provider Setup\n");
    println!("Choose a provider:");
    for (i, p) in providers.iter().enumerate() {
        let label = match *p {
            "claude_cli" => "claude_cli  (uses Claude Code subscription — no API key needed)".to_string(),
            "codex_cli" => "codex_cli   (uses Codex subscription — communicates with `codex app-server` over MCP; experimental)".to_string(),
            other => other.to_string(),
        };
        println!("  {}. {}", i + 1, label);
    }
    if !valid_customs.is_empty() {
        println!("  ── Custom ──");
        for (i, cp) in valid_customs.iter().enumerate() {
            println!(
                "  {}. {}  ({})",
                providers.len() + i + 1,
                cp.effective_display_name(),
                cp.name
            );
        }
    }
    print!("Selection [1]: ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let idx = input.trim().parse::<usize>().unwrap_or(1).saturating_sub(1);

    let (defaults, default_profile_name) = if idx < providers.len() {
        let key = providers[idx];
        // "custom" is a generic provider — there's no sensible default name, so leave
        // it empty and require the user to choose one.
        let default_name = if key == "custom" {
            String::new()
        } else {
            key.to_string()
        };
        (provider_defaults(key), default_name)
    } else {
        match valid_customs.get(idx - providers.len()) {
            Some(cp) => (ProviderDefaults::from(*cp), cp.name.clone()),
            None => (provider_defaults("openai"), "openai".to_string()),
        }
    };

    let is_cli_provider = defaults.kind == "claude_cli" || defaults.kind == "codex_cli";

    let base_url = if is_cli_provider {
        // base_url holds the binary name; not user-configurable in the wizard
        defaults.base_url.clone()
    } else if defaults.base_url.is_empty() {
        print!("Base URL: ");
        io::stdout().flush()?;
        let mut url = String::new();
        io::stdin().read_line(&mut url)?;
        url.trim().to_string()
    } else {
        print!("Base URL [{}]: ", defaults.base_url);
        io::stdout().flush()?;
        let mut url = String::new();
        io::stdin().read_line(&mut url)?;
        let trimmed = url.trim();
        if trimmed.is_empty() {
            defaults.base_url.clone()
        } else {
            trimmed.to_string()
        }
    };

    if !is_cli_provider {
        crate::config::validation::validate_provider_base_url(&base_url)?;
    }

    let default_model = defaults.models.first().cloned().unwrap_or_default();
    print!("Model [{}]: ", default_model);
    io::stdout().flush()?;
    let mut model_input = String::new();
    io::stdin().read_line(&mut model_input)?;
    let model = if model_input.trim().is_empty() {
        default_model
    } else {
        model_input.trim().to_string()
    };

    let default_cw = model_context_window(&model);
    print!("Context window [{default_cw}] (leave blank for auto-detect): ");
    io::stdout().flush()?;
    let mut cw_input = String::new();
    io::stdin().read_line(&mut cw_input)?;
    let context_window: Option<u32> = cw_input.trim().parse().ok();

    print!("Reasoning effort [none|low|medium|high|max] (leave blank for default): ");
    io::stdout().flush()?;
    let mut reasoning_input = String::new();
    io::stdin().read_line(&mut reasoning_input)?;
    let reasoning_effort: Option<String> = {
        let t = reasoning_input.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    };

    let api_key_opt = if defaults.keyless {
        None
    } else {
        print!("API Key (hidden): ");
        io::stdout().flush()?;
        let key = rpassword::read_password()?;
        if key.is_empty() {
            println!("\n✗ API key cannot be empty for this provider.");
            println!("Aborted.");
            return Ok(());
        }
        Some(key)
    };
    let auth_method = AuthMethod::ApiKey;

    let name = match profile_name {
        Some(n) => n,
        None => {
            if default_profile_name.is_empty() {
                print!("Profile name: ");
            } else {
                print!("Profile name [{}]: ", default_profile_name);
            }
            io::stdout().flush()?;
            let mut name_input = String::new();
            io::stdin().read_line(&mut name_input)?;
            let trimmed = name_input.trim();
            if trimmed.is_empty() {
                if default_profile_name.is_empty() {
                    println!("\n✗ Profile name cannot be empty.");
                    println!("Aborted.");
                    return Ok(());
                }
                default_profile_name.clone()
            } else {
                trimmed.to_string()
            }
        }
    };
    let test_key = api_key_opt.clone().unwrap_or_default();

    let verified = if is_cli_provider {
        println!("\n✓ CLI provider detected — skipping connection test (uses local binary auth)");
        true
    } else {
        println!("\nTesting connection...");
        let test_provider: Box<dyn provider::LLMProvider> = if defaults.kind == "anthropic" {
            Box::new(provider::anthropic::AnthropicProvider::new(
                base_url.clone(),
                model.clone(),
                test_key,
            ))
        } else {
            Box::new(
                provider::openai_compat::OpenAICompatProvider::new(
                    base_url.clone(),
                    model.clone(),
                    test_key,
                )
                .with_reasoning(reasoning_effort.clone()),
            )
        };

        let test_req = provider::CompletionRequest {
            messages: vec![provider::Message {
                role: "user".to_string(),
                content: "Reply OK".to_string(),
            }],
            tools: vec![],
            max_tokens: Some(5),
        };

        match test_provider.complete(test_req).await {
            Ok(_) => {
                println!("✓ Connection verified");
                true
            }
            Err(e) => {
                println!("✗ Connection failed: {}", e);
                print!("Save anyway? [y/N]: ");
                io::stdout().flush()?;
                let mut yn = String::new();
                io::stdin().read_line(&mut yn)?;
                if !yn.trim().eq_ignore_ascii_case("y") {
                    println!("Aborted.");
                    return Ok(());
                }
                false
            }
        }
    };

    let mut global = GlobalConfig::load()?;
    if global.profiles.contains_key(&name) {
        print!("Profile '{}' already exists. Overwrite? [y/N]: ", name);
        io::stdout().flush()?;
        let mut yn = String::new();
        io::stdin().read_line(&mut yn)?;
        if !yn.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    global.profiles.insert(
        name.clone(),
        ProviderProfile {
            kind: defaults.kind.clone(),
            base_url,
            model,
            keyless: defaults.keyless,
            auth_method: auth_method.clone(),
            context_window,
            reasoning_effort: reasoning_effort.clone(),
        },
    );
    if global.default_profile.is_none() {
        global.default_profile = Some(name.clone());
    }

    if let Some(ref key) = api_key_opt {
        match keychain::set_key(&name, key)? {
            keychain::KeyStorage::Keychain => {
                println!("✓ API key saved to OS keychain");
            }
            keychain::KeyStorage::File => {
                println!("✓ API key saved to ~/.zentra/keys/{name}.key");
            }
        }
    }

    global.save()?;

    if verified {
        println!("✓ Profile '{}' saved", name);
    }
    if global.default_profile.as_deref() == Some(&name) {
        println!("  Set as default provider.");
    }
    println!("\nNext: run 'zentra init' in your project, then 'zentra scan'.");
    Ok(())
}
