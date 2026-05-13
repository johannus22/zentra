use crate::config::{keychain, GlobalConfig};
use anyhow::Result;
use std::path::Path;

fn remove_profile_from<FKey, FOAuth>(
    config_path: &Path,
    name: &str,
    delete_key: FKey,
    delete_oauth_tokens: FOAuth,
) -> Result<()>
where
    FKey: FnOnce(&str) -> Result<()>,
    FOAuth: FnOnce(&str) -> Result<()>,
{
    let mut global = GlobalConfig::load_from(config_path)?;
    anyhow::ensure!(
        global.profiles.contains_key(name),
        "Profile '{}' not found",
        name
    );
    global.profiles.remove(name);
    if global.default_profile.as_deref() == Some(name) {
        global.default_profile = global.profiles.keys().next().cloned();
    }
    global.save_to(config_path)?;
    delete_key(name)?;
    delete_oauth_tokens(name)?;
    Ok(())
}

pub fn remove_profile(name: &str) -> Result<()> {
    remove_profile_from(
        &GlobalConfig::default_path()?,
        name,
        keychain::delete_key,
        keychain::delete_oauth_tokens,
    )
}

pub async fn list() -> Result<()> {
    let global = GlobalConfig::load()?;
    if global.profiles.is_empty() {
        println!("No providers configured. Run: zentra config setup");
        return Ok(());
    }
    for (name, profile) in &global.profiles {
        let marker = if global.default_profile.as_deref() == Some(name) {
            "✓"
        } else {
            "○"
        };
        let active = if global.default_profile.as_deref() == Some(name) {
            " [active]"
        } else {
            ""
        };
        let key_display = match keychain::get_key(name)? {
            Some(_) => format!("key: {}", keychain::masked_display()),
            None => "key: not required".to_string(),
        };
        println!(
            "  {} {}  │  {}  │  {}  │  {}{}",
            marker, name, profile.model, profile.base_url, key_display, active
        );
    }
    Ok(())
}

pub async fn use_profile(name: &str) -> Result<()> {
    let mut global = GlobalConfig::load()?;
    anyhow::ensure!(
        global.profiles.contains_key(name),
        "Profile '{}' not found. Run: zentra config list",
        name
    );
    global.default_profile = Some(name.to_string());
    global.save()?;
    println!("✓ Default provider set to '{}'", name);
    Ok(())
}

pub async fn show() -> Result<()> {
    let global = GlobalConfig::load()?;
    let name = global
        .default_profile
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("No default profile set. Run: zentra config setup"))?;
    let profile = global
        .profiles
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("Profile '{}' not found", name))?;
    println!("Active profile : {}", name);
    println!("  model        : {}", profile.model);
    println!("  base_url     : {}", profile.base_url);
    println!("  kind         : {}", profile.kind);
    let key_display = match keychain::get_key(name)? {
        Some(_) => keychain::masked_display().to_string(),
        None => "not set".to_string(),
    };
    println!("  api_key      : {}", key_display);
    Ok(())
}

pub async fn remove(name: &str) -> Result<()> {
    remove_profile(name)?;
    println!("✓ Profile '{}' removed", name);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::remove_profile_from;
    use crate::config::{AuthMethod, GlobalConfig, ProviderProfile};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    #[test]
    fn remove_profile_cleans_up_oauth_tokens() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("config.toml");
        let mut profiles = HashMap::new();
        profiles.insert(
            "oauth".to_string(),
            ProviderProfile {
                kind: "openai_compat".to_string(),
                base_url: "https://api.openai.com/v1".to_string(),
                model: "gpt-4o".to_string(),
                keyless: false,
                auth_method: AuthMethod::OAuth,
                context_window: None,
            },
        );
        GlobalConfig {
            profiles,
            default_profile: Some("oauth".to_string()),
        }
        .save_to(&path)
        .unwrap();

        let deleted_key = Arc::new(Mutex::new(Vec::new()));
        let deleted_oauth = Arc::new(Mutex::new(Vec::new()));
        let deleted_key_capture = Arc::clone(&deleted_key);
        let deleted_oauth_capture = Arc::clone(&deleted_oauth);

        remove_profile_from(
            &path,
            "oauth",
            move |name| {
                deleted_key_capture.lock().unwrap().push(name.to_string());
                Ok(())
            },
            move |name| {
                deleted_oauth_capture.lock().unwrap().push(name.to_string());
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(deleted_key.lock().unwrap().as_slice(), ["oauth"]);
        assert_eq!(deleted_oauth.lock().unwrap().as_slice(), ["oauth"]);

        let saved = GlobalConfig::load_from(&path).unwrap();
        assert!(!saved.profiles.contains_key("oauth"));
        assert!(saved.default_profile.is_none());
    }
}
