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
