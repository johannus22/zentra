use crate::config::secret_store;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub fn service_name(profile: &str) -> String {
    format!("zentra.{}", profile)
}

/// A profile name is interpolated into `~/.zentra/keys/<name>.key`, so it must
/// be a safe single filename component. Allow only `[A-Za-z0-9_-]` (mirroring
/// the TUI form) — this rejects path separators and `..`, closing the
/// traversal-write path for non-TUI callers such as the wizard (F13).
pub fn is_valid_profile_name(profile: &str) -> bool {
    !profile.is_empty()
        && profile.len() <= 64
        && profile
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn ensure_valid_profile_name(profile: &str) -> Result<()> {
    if is_valid_profile_name(profile) {
        Ok(())
    } else {
        anyhow::bail!(
            "invalid profile name {profile:?}: use only letters, digits, '-' and '_' \
             (max 64 chars)"
        )
    }
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
    ensure_valid_profile_name(profile)?;
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
            let key = String::from_utf8(bytes)
                .context("API key file contains invalid UTF-8 — the file may be corrupt")?;
            return Ok(Some(key.trim().to_string()));
        }
    }
    // Backward compatibility: best-effort read of a key left in the OS keychain by an
    // older version. The file above is the source of truth; the keychain is unreliable
    // and may be entirely unavailable (headless Linux with no secret-service daemon,
    // locked keyring), so any failure degrades to "no key" rather than erroring.
    if let Ok(entry) = keyring::Entry::new(&service_name(profile), "api_key") {
        if let Ok(key) = entry.get_password() {
            return Ok(Some(key));
        }
    }
    Ok(None)
}

pub fn delete_key(profile: &str) -> Result<()> {
    // Best-effort: drop any stale keychain entry from an older version. The keychain
    // may be unavailable (headless Linux with no secret-service, locked keyring), so
    // ignore errors — removing the key file below is the authoritative operation.
    if let Ok(entry) = keyring::Entry::new(&service_name(profile), "api_key") {
        let _ = entry.delete_credential();
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
    // Backward compatibility: best-effort read of tokens left in the OS keychain by an
    // older version. The keychain is unreliable (the reason tokens moved to files), so
    // any failure here degrades to "no tokens" rather than failing the whole operation.
    if let Ok(entry) = keyring::Entry::new(&service_name(profile), "oauth_tokens") {
        if let Ok(json) = entry.get_password() {
            if let Ok(tokens) = serde_json::from_str(&json) {
                return Ok(Some(tokens));
            }
        }
    }
    Ok(None)
}

pub fn delete_oauth_tokens(profile: &str) -> Result<()> {
    if let Some(path) = oauth_file_path(profile) {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(anyhow::anyhow!("Failed to remove OAuth token file: {}", e)),
        }
    }
    // Best-effort stale-entry cleanup, same rationale as delete_key: the keychain
    // may be unavailable, and the file removal above is the authoritative operation.
    if let Ok(entry) = keyring::Entry::new(&service_name(profile), "oauth_tokens") {
        let _ = entry.delete_credential();
    }
    Ok(())
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
