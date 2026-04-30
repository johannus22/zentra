use anyhow::{Context, Result};

pub fn service_name(profile: &str) -> String {
    format!("zentra/{}", profile)
}

pub fn masked_display() -> &'static str {
    "••••••••••••"
}

pub fn set_key(profile: &str, api_key: &str) -> Result<()> {
    let entry = keyring::Entry::new(&service_name(profile), "api_key")
        .context("Failed to access OS keychain")?;
    entry.set_password(api_key)
        .context("Failed to store API key in keychain")?;
    Ok(())
}

pub fn get_key(profile: &str) -> Result<Option<String>> {
    let entry = keyring::Entry::new(&service_name(profile), "api_key")
        .context("Failed to access OS keychain")?;
    match entry.get_password() {
        Ok(key) => Ok(Some(key)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(anyhow::anyhow!("Keychain read failed: {}", e)),
    }
}

pub fn delete_key(profile: &str) -> Result<()> {
    let entry = keyring::Entry::new(&service_name(profile), "api_key")
        .context("Failed to access OS keychain")?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(anyhow::anyhow!("Keychain delete failed: {}", e)),
    }
}

pub fn set_oauth_tokens(profile: &str, tokens: &crate::auth::OAuthTokens) -> Result<()> {
    let json = serde_json::to_string(tokens)?;
    let entry = keyring::Entry::new(&service_name(profile), "oauth_tokens")
        .context("Failed to access OS keychain")?;
    entry.set_password(&json)
        .context("Failed to store OAuth tokens in keychain")?;
    Ok(())
}

pub fn get_oauth_tokens(profile: &str) -> Result<Option<crate::auth::OAuthTokens>> {
    let entry = keyring::Entry::new(&service_name(profile), "oauth_tokens")
        .context("Failed to access OS keychain")?;
    match entry.get_password() {
        Ok(json) => Ok(Some(serde_json::from_str(&json)?)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(anyhow::anyhow!("Keychain read failed: {}", e)),
    }
}

pub fn delete_oauth_tokens(profile: &str) -> Result<()> {
    let entry = keyring::Entry::new(&service_name(profile), "oauth_tokens")
        .context("Failed to access OS keychain")?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(anyhow::anyhow!("Keychain delete failed: {}", e)),
    }
}
