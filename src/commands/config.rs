use crate::config::{keychain, GlobalConfig};
use anyhow::Result;

pub async fn list() -> Result<()> {
    let global = GlobalConfig::load()?;
    if global.profiles.is_empty() {
        println!("No providers configured. Run: zentra config setup");
        return Ok(());
    }
    for (name, profile) in &global.profiles {
        let marker = if global.default_profile.as_deref() == Some(name) { "✓" } else { "○" };
        let active = if global.default_profile.as_deref() == Some(name) { " [active]" } else { "" };
        let key_display = match keychain::get_key(name)? {
            Some(_) => format!("key: {}", keychain::masked_display()),
            None => "key: not required".to_string(),
        };
        println!("  {} {}  │  {}  │  {}  │  {}{}", marker, name, profile.model, profile.base_url, key_display, active);
    }
    Ok(())
}

pub async fn use_profile(name: &str) -> Result<()> {
    let mut global = GlobalConfig::load()?;
    anyhow::ensure!(global.profiles.contains_key(name), "Profile '{}' not found. Run: zentra config list", name);
    global.default_profile = Some(name.to_string());
    global.save()?;
    println!("✓ Default provider set to '{}'", name);
    Ok(())
}

pub async fn show() -> Result<()> {
    let global = GlobalConfig::load()?;
    let name = global.default_profile.as_deref()
        .ok_or_else(|| anyhow::anyhow!("No default profile set. Run: zentra config setup"))?;
    let profile = global.profiles.get(name)
        .ok_or_else(|| anyhow::anyhow!("Profile '{}' not found", name))?;
    println!("Active profile : {}", name);
    println!("  model        : {}", profile.model);
    println!("  base_url     : {}", profile.base_url);
    println!("  kind         : {}", profile.kind);
    println!("  api_key      : {}", keychain::masked_display());
    Ok(())
}

pub async fn remove(name: &str) -> Result<()> {
    let mut global = GlobalConfig::load()?;
    anyhow::ensure!(global.profiles.contains_key(name), "Profile '{}' not found", name);
    global.profiles.remove(name);
    if global.default_profile.as_deref() == Some(name) {
        global.default_profile = global.profiles.keys().next().cloned();
    }
    global.save()?;
    keychain::delete_key(name)?;
    println!("✓ Profile '{}' removed", name);
    Ok(())
}
