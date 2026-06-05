use anyhow::{Context, Result};
use std::path::PathBuf;

pub fn service_name(profile: &str) -> String {
    format!("zentra.{}", profile)
}

pub fn masked_display() -> &'static str {
    "••••••••••••"
}

pub fn key_file_path(profile: &str) -> Option<PathBuf> {
    dirs::home_dir().map(|h| {
        h.join(".zentra")
            .join("keys")
            .join(format!("{}.key", profile))
    })
}

#[derive(Debug)]
pub enum KeyStorage {
    Keychain,
    File,
}

pub fn set_key(profile: &str, api_key: &str) -> Result<KeyStorage> {
    // Store the key in a plaintext file under ~/.zentra/keys/ by default.
    // The OS keychain proved unreliable — Windows Credential Manager could return Ok
    // on set_password (and even pass an in-process read-back) yet fail to persist
    // across process restarts, leaving later `zentra scan` runs unable to find the key.
    let path =
        key_file_path(profile).context("Could not determine key file path (no home directory)")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("Failed to create ~/.zentra/keys directory")?;
    }
    std::fs::write(&path, api_key).context("Failed to write API key file")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    // Best-effort: drop any stale keychain entry left by an older version so it can't
    // linger in the OS credential store or confuse `config list`. Ignore all errors.
    if let Ok(entry) = keyring::Entry::new(&service_name(profile), "api_key") {
        let _ = entry.delete_credential();
    }

    Ok(KeyStorage::File)
}

pub fn get_key(profile: &str) -> Result<Option<String>> {
    // Prefer the plaintext key file — the default storage location.
    if let Some(path) = key_file_path(profile) {
        if path.exists() {
            let key = std::fs::read_to_string(&path).context("Failed to read API key from file")?;
            return Ok(Some(key.trim().to_string()));
        }
    }
    // Backward compatibility: fall back to any key previously stored in the OS keychain.
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
        Ok(()) | Err(keyring::Error::NoEntry) => {}
        Err(e) => return Err(anyhow::anyhow!("Keychain delete failed: {}", e)),
    }
    if let Some(path) = key_file_path(profile) {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(anyhow::anyhow!("Failed to remove key file: {}", e)),
        }
    }
    Ok(())
}

pub fn set_oauth_tokens(profile: &str, tokens: &crate::auth::OAuthTokens) -> Result<()> {
    let json = serde_json::to_string(tokens)?;
    let entry = keyring::Entry::new(&service_name(profile), "oauth_tokens")
        .context("Failed to access OS keychain")?;
    entry
        .set_password(&json)
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
