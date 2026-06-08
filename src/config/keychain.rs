use crate::config::secret_store;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

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

pub fn oauth_file_path(profile: &str) -> Option<PathBuf> {
    dirs::home_dir().map(|h| {
        h.join(".zentra")
            .join("keys")
            .join(format!("{}.oauth", profile))
    })
}

#[derive(Debug)]
pub enum KeyStorage {
    Keychain,
    File,
}

pub fn set_key(profile: &str, api_key: &str) -> Result<KeyStorage> {
    // Store the key in a file under ~/.zentra/keys/ by default, encrypted at
    // rest via secret_store (DPAPI on Windows, 0o600 plaintext on Unix).
    // The OS keychain proved unreliable — Windows Credential Manager could return Ok
    // on set_password (and even pass an in-process read-back) yet fail to persist
    // across process restarts, leaving later `zentra scan` runs unable to find the key.
    let path =
        key_file_path(profile).context("Could not determine key file path (no home directory)")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("Failed to create ~/.zentra/keys directory")?;
    }
    secret_store::write_secret(&path, api_key.as_bytes())
        .context("Failed to write API key file")?;

    // Best-effort: drop any stale keychain entry left by an older version so it can't
    // linger in the OS credential store or confuse `config list`. Ignore all errors.
    if let Ok(entry) = keyring::Entry::new(&service_name(profile), "api_key") {
        let _ = entry.delete_credential();
    }

    Ok(KeyStorage::File)
}

pub fn get_key(profile: &str) -> Result<Option<String>> {
    // Prefer the key file — the default storage location.
    if let Some(path) = key_file_path(profile) {
        if path.exists() {
            let bytes = secret_store::read_secret(&path)?;
            let key = String::from_utf8_lossy(&bytes).trim().to_string();
            return Ok(Some(key));
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

fn set_oauth_tokens_at(path: &Path, tokens: &crate::auth::OAuthTokens) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("Failed to create ~/.zentra/keys directory")?;
    }
    let json = serde_json::to_vec(tokens)?;
    secret_store::write_secret(path, &json).context("Failed to write OAuth tokens file")?;
    Ok(())
}

fn get_oauth_tokens_at(path: &Path) -> Result<Option<crate::auth::OAuthTokens>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = secret_store::read_secret(path)?;
    Ok(Some(serde_json::from_slice(&bytes)?))
}

pub fn set_oauth_tokens(profile: &str, tokens: &crate::auth::OAuthTokens) -> Result<()> {
    let path = oauth_file_path(profile)
        .context("Could not determine OAuth token file path (no home directory)")?;
    set_oauth_tokens_at(&path, tokens)?;
    // Best-effort: drop any stale keychain entry from an older version.
    if let Ok(entry) = keyring::Entry::new(&service_name(profile), "oauth_tokens") {
        let _ = entry.delete_credential();
    }
    Ok(())
}

pub fn get_oauth_tokens(profile: &str) -> Result<Option<crate::auth::OAuthTokens>> {
    if let Some(path) = oauth_file_path(profile) {
        if let Some(tokens) = get_oauth_tokens_at(&path)? {
            return Ok(Some(tokens));
        }
    }
    // Backward compatibility: fall back to tokens previously stored in the keychain.
    let entry = keyring::Entry::new(&service_name(profile), "oauth_tokens")
        .context("Failed to access OS keychain")?;
    match entry.get_password() {
        Ok(json) => Ok(Some(serde_json::from_str(&json)?)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(anyhow::anyhow!("Keychain read failed: {}", e)),
    }
}

pub fn delete_oauth_tokens(profile: &str) -> Result<()> {
    if let Some(path) = oauth_file_path(profile) {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(anyhow::anyhow!("Failed to remove OAuth token file: {}", e)),
        }
    }
    let entry = keyring::Entry::new(&service_name(profile), "oauth_tokens")
        .context("Failed to access OS keychain")?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(anyhow::anyhow!("Keychain delete failed: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::OAuthTokens;
    use tempfile::TempDir;

    #[test]
    fn oauth_tokens_file_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.oauth");
        let tokens = OAuthTokens {
            access_token: "access-123".to_string(),
            refresh_token: "refresh-456".to_string(),
            expires_at: 1_900_000_000,
        };
        set_oauth_tokens_at(&path, &tokens).unwrap();
        let got = get_oauth_tokens_at(&path).unwrap().unwrap();
        assert_eq!(got.access_token, "access-123");
        assert_eq!(got.refresh_token, "refresh-456");
        assert_eq!(got.expires_at, 1_900_000_000);
    }

    #[test]
    fn get_oauth_tokens_at_missing_file_returns_none() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nope.oauth");
        assert!(get_oauth_tokens_at(&path).unwrap().is_none());
    }
}
