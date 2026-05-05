use anyhow::{Context, Result};
use std::path::PathBuf;

pub fn service_name(profile: &str) -> String {
    format!("zentra.{}", profile)
}

pub fn masked_display() -> &'static str {
    "••••••••••••"
}

pub fn key_file_path(profile: &str) -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".zentra").join("keys").join(format!("{}.key", profile)))
}

pub enum KeyStorage {
    Keychain,
    File,
}

pub fn set_key(profile: &str, api_key: &str) -> Result<KeyStorage> {
    let entry = keyring::Entry::new(&service_name(profile), "api_key")
        .context("Failed to access OS keychain")?;

    let keyring_ok = match entry.set_password(api_key) {
        Ok(()) => entry.get_password().map(|s| s == api_key).unwrap_or(false),
        Err(_) => false,
    };

    if keyring_ok {
        return Ok(KeyStorage::Keychain);
    }

    let path = key_file_path(profile)
        .ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("Failed to create ~/.zentra/keys/")?;
    }
    std::fs::write(&path, api_key).context("Failed to write API key to file")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .context("Failed to set file permissions")?;
    }
    Ok(KeyStorage::File)
}

pub fn get_key(profile: &str) -> Result<Option<String>> {
    let entry = keyring::Entry::new(&service_name(profile), "api_key")
        .context("Failed to access OS keychain")?;
    match entry.get_password() {
        Ok(key) => return Ok(Some(key)),
        Err(keyring::Error::NoEntry) => {}
        Err(e) => return Err(anyhow::anyhow!("Keychain read failed: {}", e)),
    }
    if let Some(path) = key_file_path(profile) {
        if path.exists() {
            let key = std::fs::read_to_string(&path)
                .context("Failed to read API key from file")?;
            return Ok(Some(key));
        }
    }
    Ok(None)
}

pub fn delete_key(profile: &str) -> Result<()> {
    let entry = keyring::Entry::new(&service_name(profile), "api_key")
        .context("Failed to access OS keychain")?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => {}
        Err(e) => return Err(anyhow::anyhow!("Keychain delete failed: {}", e)),
    }
    if let Some(path) = key_file_path(profile) {
        if path.exists() {
            std::fs::remove_file(&path).ok();
        }
    }
    Ok(())
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
