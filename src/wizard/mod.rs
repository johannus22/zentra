use anyhow::Result;
use crate::config::custom_providers::{CustomProvider, CustomProvidersFile};

pub struct ProviderDefaults {
    pub base_url: String,
    pub models: Vec<String>,
    pub kind: String,
    pub keyless: bool,
}

pub fn model_context_window(model: &str) -> u32 {
    if model.contains("gpt-4o") || model.contains("o1") || model.contains("glm-4") || model.contains("llama-3") {
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
            models: vec!["gpt-4o".to_string(), "gpt-4o-mini".to_string(), "o1".to_string()],
            kind: "openai_compat".to_string(),
            keyless: false,
        },
        "anthropic" => ProviderDefaults {
            base_url: "https://api.anthropic.com".to_string(),
            models: vec!["claude-opus-4-7".to_string(), "claude-sonnet-4-6".to_string()],
            kind: "anthropic".to_string(),
            keyless: false,
        },
        "cerebras" => ProviderDefaults {
            base_url: "https://api.cerebras.ai/v1".to_string(),
            models: vec!["llama-3.3-70b".to_string()],
            kind: "openai_compat".to_string(),
            keyless: false,
        },
        "litellm" => ProviderDefaults {
            base_url: String::new(),
            models: vec![],
            kind: "openai_compat".to_string(),
            keyless: false,
        },
        "ollama" => ProviderDefaults {
            base_url: "http://localhost:11434/v1".to_string(),
            models: vec!["llama3.2".to_string()],
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
        _ => ProviderDefaults {
            base_url: String::new(),
            models: vec![],
            kind: "openai_compat".to_string(),
            keyless: false,
        },
    }
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
        auth,
        config::{keychain, AuthMethod, GlobalConfig, ProviderProfile},
        provider,
    };
    use std::io::{self, Write};

    const PROVIDERS: &[&str] = &["openai", "anthropic", "cerebras", "litellm", "ollama", "zhipu", "other"];

    // Load user-defined provider presets from ~/.zentra/providers.toml
    let custom_file = CustomProvidersFile::load();
    let valid_customs: Vec<&CustomProvider> = custom_file
        .providers
        .iter()
        .filter(|cp| {
            if PROVIDERS.contains(&cp.name.as_str()) {
                eprintln!("⚠ custom provider '{}' conflicts with built-in name — skipped", cp.name);
                false
            } else {
                true
            }
        })
        .collect();

    println!("\n Zentra — Provider Setup\n");
    println!("Choose a provider:");
    for (i, p) in PROVIDERS.iter().enumerate() {
        println!("  {}. {}", i + 1, p);
    }
    if !valid_customs.is_empty() {
        println!("  ── Custom ──");
        for (i, cp) in valid_customs.iter().enumerate() {
            println!("  {}. {}  ({})", PROVIDERS.len() + i + 1, cp.effective_display_name(), cp.name);
        }
    }
    print!("Selection [1]: ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let idx = input.trim().parse::<usize>().unwrap_or(1).saturating_sub(1);

    let (defaults, is_openai, default_profile_name) = if idx < PROVIDERS.len() {
        let key = PROVIDERS[idx];
        (provider_defaults(key), key == "openai", key.to_string())
    } else {
        match valid_customs.get(idx - PROVIDERS.len()) {
            Some(cp) => (ProviderDefaults::from(*cp), false, cp.name.clone()),
            None => (provider_defaults("openai"), false, "openai".to_string()),
        }
    };

    let base_url = if defaults.base_url.is_empty() {
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
        if trimmed.is_empty() { defaults.base_url.clone() } else { trimmed.to_string() }
    };

    let default_model = defaults.models.first().cloned().unwrap_or_default();
    print!("Model [{}]: ", default_model);
    io::stdout().flush()?;
    let mut model_input = String::new();
    io::stdin().read_line(&mut model_input)?;
    let model = if model_input.trim().is_empty() { default_model } else { model_input.trim().to_string() };

    let default_cw = model_context_window(&model);
    print!("Context window [{default_cw}] (leave blank for auto-detect): ");
    io::stdout().flush()?;
    let mut cw_input = String::new();
    io::stdin().read_line(&mut cw_input)?;
    let context_window: Option<u32> = cw_input.trim().parse().ok();

    // Auth method — only for OpenAI
    let (auth_method, api_key_opt) = if is_openai {
        println!("\nAuth method:");
        println!("  1. API Key");
        println!("  2. Login with browser (ChatGPT / OpenAI subscription)");
        print!("Selection [1]: ");
        io::stdout().flush()?;
        let mut am_input = String::new();
        io::stdin().read_line(&mut am_input)?;
        let am_idx = am_input.trim().parse::<usize>().unwrap_or(1);

        if am_idx == 2 {
            (AuthMethod::OAuth, None)
        } else {
            print!("API Key (hidden): ");
            io::stdout().flush()?;
            let key = rpassword::read_password()?;
            if key.is_empty() {
                println!("\n✗ API key cannot be empty.");
                println!("Aborted.");
                return Ok(());
            }
            (AuthMethod::ApiKey, Some(key))
        }
    } else if defaults.keyless {
        (AuthMethod::ApiKey, None)
    } else {
        print!("API Key (hidden): ");
        io::stdout().flush()?;
        let key = rpassword::read_password()?;
        if key.is_empty() {
            println!("\n✗ API key cannot be empty for this provider.");
            println!("Aborted.");
            return Ok(());
        }
        (AuthMethod::ApiKey, Some(key))
    };

    let name = profile_name.unwrap_or(default_profile_name);

    // For OAuth: run browser flow now, before saving profile
    let oauth_tokens = if auth_method == AuthMethod::OAuth {
        Some(auth::run_oauth_flow().await?)
    } else {
        None
    };

    // Connection test using resolved credential
    let test_key = match (&oauth_tokens, &api_key_opt) {
        (Some(t), _) => t.access_token.clone(),
        (_, Some(k)) => k.clone(),
        _ => String::new(),
    };

    println!("\nTesting connection...");
    let test_provider: Box<dyn provider::LLMProvider> = if defaults.kind == "anthropic" {
        Box::new(provider::anthropic::AnthropicProvider::new(
            base_url.clone(), model.clone(), test_key,
        ))
    } else {
        Box::new(provider::openai_compat::OpenAICompatProvider::new(
            base_url.clone(), model.clone(), test_key,
        ))
    };

    let test_req = provider::CompletionRequest {
        messages: vec![provider::Message { role: "user".to_string(), content: "Reply OK".to_string() }],
        tools: vec![],
        max_tokens: Some(5),
    };

    let verified = match test_provider.complete(test_req).await {
        Ok(_) => { println!("✓ Connection verified"); true }
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

    global.profiles.insert(name.clone(), ProviderProfile {
        kind: defaults.kind.clone(),
        base_url,
        model,
        keyless: defaults.keyless,
        auth_method: auth_method.clone(),
        context_window,
    });
    if global.default_profile.is_none() {
        global.default_profile = Some(name.clone());
    }

    if let Some(ref tokens) = oauth_tokens {
        keychain::set_oauth_tokens(&name, tokens)?;
        println!("✓ OAuth tokens saved to OS keychain");
    } else if let Some(ref key) = api_key_opt {
        keychain::set_key(&name, key)?;
        println!("✓ API key saved to OS keychain (never written to disk)");
    }

    global.save()?;

    if verified { println!("✓ Profile '{}' saved", name); }
    if global.default_profile.as_deref() == Some(&name) {
        println!("  Set as default provider.");
    }
    println!("\nNext: run 'zentra init' in your project, then 'zentra scan'.");
    Ok(())
}
