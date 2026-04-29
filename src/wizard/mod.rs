use anyhow::Result;

pub struct ProviderDefaults {
    pub base_url: String,
    pub models: Vec<String>,
    pub kind: String,
    pub keyless: bool,
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
        _ => ProviderDefaults {
            base_url: String::new(),
            models: vec![],
            kind: "openai_compat".to_string(),
            keyless: false,
        },
    }
}

pub async fn run_setup(profile_name: Option<String>) -> Result<()> {
    use crate::{config::{keychain, GlobalConfig, ProviderProfile}, provider};
    use std::io::{self, Write};

    println!("\n Zentra — Provider Setup\n");
    println!("Choose a provider:");
    let providers = ["openai", "anthropic", "cerebras", "litellm", "ollama", "other"];
    for (i, p) in providers.iter().enumerate() {
        println!("  {}. {}", i + 1, p);
    }
    print!("Selection [1]: ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let idx = input.trim().parse::<usize>().unwrap_or(1).saturating_sub(1);
    let provider_key = providers.get(idx).copied().unwrap_or("openai");
    let defaults = provider_defaults(provider_key);

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

    let api_key = if defaults.keyless {
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

    println!("\nTesting connection...");
    let test_provider: Box<dyn provider::LLMProvider> = if defaults.kind == "anthropic" {
        Box::new(provider::anthropic::AnthropicProvider::new(
            base_url.clone(), model.clone(), api_key.clone().unwrap_or_default(),
        ))
    } else {
        Box::new(provider::openai_compat::OpenAICompatProvider::new(
            base_url.clone(), model.clone(), api_key.clone().unwrap_or_default(),
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

    let name = profile_name.unwrap_or_else(|| provider_key.to_string());
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
    });
    if global.default_profile.is_none() {
        global.default_profile = Some(name.clone());
    }

    if let Some(ref key) = api_key {
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
