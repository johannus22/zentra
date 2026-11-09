//! Platform credential storage.
//!
//! On Windows, secrets are encrypted at rest with DPAPI (user scope).
//!
//! On Unix (Linux/macOS), secrets are sealed with AES-256-GCM under a random
//! data-encryption key (DEK) that lives in the OS secret store (Secret Service
//! on Linux, Keychain on macOS) via explicit keyring stores — envelope encryption
//! that mirrors DPAPI: the file on disk is useless without the local OS store.
//! When the OS store is unavailable (headless/SSH/CI, locked keyring) we fall
//! back to writing plaintext, still guarded by 0o600 file permissions.
//!
//! Both platforms transparently read pre-existing (legacy/fallback) plaintext
//! files, distinguished by a magic prefix, so old key files keep working.

use anyhow::{Context, Result};
use std::path::Path;

/// Encrypt (Windows) or pass through (Unix) and write `plaintext` to `path`.
pub fn write_secret(path: &Path, plaintext: &[u8]) -> Result<()> {
    let bytes = encrypt(plaintext)?;
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;
        // Create with 0o600 from the start — no world-readable TOCTOU window.
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .context("Failed to create secret file")?;
        f.write_all(&bytes).context("Failed to write secret file")?;
        // Backstop for a pre-existing file whose mode predates this write.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .context("Failed to set 0o600 permissions on secret file")?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, &bytes).context("Failed to write secret file")?;
    }
    Ok(())
}

/// Read and decrypt (Windows) or pass through (Unix) the secret at `path`.
pub fn read_secret(path: &Path) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path).context("Failed to read secret file")?;
    decrypt(bytes)
}

/// When set, skip the OS secret store entirely and use the 0o600-plaintext
/// fallback — identical to when the store is genuinely unavailable. Intended for
/// CI and headless environments where the OS keychain hangs (macOS shows an
/// interactive "allow access" prompt with no GUI to answer) or is absent (Linux
/// without a secret-service daemon).
#[cfg(not(windows))]
fn os_secret_store_disabled() -> bool {
    std::env::var_os("ZENTRA_NO_OS_KEYCHAIN").is_some()
}

#[cfg(not(windows))]
fn encrypt(plaintext: &[u8]) -> Result<Vec<u8>> {
    // Envelope-encrypt under a DEK held in the OS secret store. If the store is
    // unavailable (headless/SSH/CI, locked keyring) — or explicitly disabled via
    // ZENTRA_NO_OS_KEYCHAIN — fall back to plaintext; write_secret still applies
    // 0o600. Mirrors the Windows DPAPI design.
    if os_secret_store_disabled() {
        return Ok(plaintext.to_vec());
    }
    match envelope::load_or_create_dek() {
        Ok(key) => envelope::seal(&key, plaintext),
        Err(_) => Ok(plaintext.to_vec()),
    }
}

#[cfg(not(windows))]
fn decrypt(bytes: Vec<u8>) -> Result<Vec<u8>> {
    if envelope::looks_like_envelope(&bytes) {
        if os_secret_store_disabled() {
            anyhow::bail!(
                "Secret is envelope-encrypted but ZENTRA_NO_OS_KEYCHAIN is set — unset it to read \
                 this key from the OS secret store, or re-run setup to rewrite it as plaintext"
            );
        }
        let key = envelope::load_dek()?.ok_or_else(|| {
            anyhow::anyhow!(
                "Secret is envelope-encrypted but its data key is missing from the OS secret \
                 store — it may have been cleared, or written under a different login session"
            )
        })?;
        envelope::open(&key, &bytes)
    } else {
        // Not an envelope blob — a legacy/fallback plaintext file. Return as-is
        // for transparent migration (mirror of the Windows legacy path).
        Ok(bytes)
    }
}

/// AES-256-GCM envelope encryption with a data key held in the OS secret store.
///
/// The crypto core (`seal`/`open`/`looks_like_envelope`) is compiled on all
/// platforms so it can be unit-tested anywhere; only the Unix `encrypt`/`decrypt`
/// above actually call it (Windows uses DPAPI), hence `dead_code` on Windows.
#[allow(dead_code)]
mod envelope {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use anyhow::{Context, Result};
    use base64::Engine;
    use rand::RngCore;

    /// Marks a file written by this module. Bytes without it are legacy plaintext.
    const MAGIC: &[u8; 4] = b"ZSE1";
    const NONCE_LEN: usize = 12;
    const KEY_LEN: usize = 32;
    const KEYRING_SERVICE: &str = "zentra";
    const KEYRING_USER: &str = "secret-store-key-v1";

    pub(super) fn looks_like_envelope(bytes: &[u8]) -> bool {
        bytes.len() >= MAGIC.len() && &bytes[..MAGIC.len()] == MAGIC
    }

    /// Seal `plaintext` under `key` → `MAGIC || nonce || ciphertext+tag`.
    pub(super) fn seal(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
            .map_err(|e| anyhow::anyhow!("AES-GCM encryption failed: {e}"))?;
        let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ct.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Reverse `seal`. Errors on a malformed blob or failed authentication.
    pub(super) fn open(key: &[u8; KEY_LEN], blob: &[u8]) -> Result<Vec<u8>> {
        let header = MAGIC.len() + NONCE_LEN;
        if blob.len() < header {
            anyhow::bail!("secret envelope is truncated");
        }
        let nonce = Nonce::from_slice(&blob[MAGIC.len()..header]);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        cipher
            .decrypt(nonce, &blob[header..])
            .map_err(|e| anyhow::anyhow!("Failed to decrypt secret (wrong key or corrupted): {e}"))
    }

    fn dek_entry() -> Result<crate::config::credential_store::Entry> {
        crate::config::credential_store::Entry::new(KEYRING_SERVICE, KEYRING_USER)
            .context("Failed to access OS secret store for the data key")
    }

    /// Fetch the existing DEK, or generate and store a new one. Errors only if the
    /// OS secret store is unavailable (callers treat that as "fall back to plaintext").
    pub(super) fn load_or_create_dek() -> Result<[u8; KEY_LEN]> {
        load_or_create_dek_with(load_dek, |encoded| {
            dek_entry()?
                .set_password(encoded)
                .context("Failed to store data key in OS secret store")
        })
    }

    pub(super) fn load_or_create_dek_with(
        load: impl FnOnce() -> Result<Option<[u8; KEY_LEN]>>,
        store: impl FnOnce(&str) -> Result<()>,
    ) -> Result<[u8; KEY_LEN]> {
        if let Some(key) = load()? {
            return Ok(key);
        }
        let mut key = [0u8; KEY_LEN];
        rand::thread_rng().fill_bytes(&mut key);
        store(&base64::engine::general_purpose::STANDARD.encode(key))?;
        Ok(key)
    }

    /// Fetch the DEK. `Ok(None)` if it was never created; `Err` if the store is
    /// unavailable or the stored value is malformed.
    pub(super) fn load_dek() -> Result<Option<[u8; KEY_LEN]>> {
        decode_dek(dek_entry()?.get_password())
    }

    pub(super) fn decode_dek(
        result: keyring_core::Result<String>,
    ) -> Result<Option<[u8; KEY_LEN]>> {
        match result {
            Ok(encoded) => {
                let raw = base64::engine::general_purpose::STANDARD
                    .decode(encoded.trim())
                    .context("Stored data key is not valid base64")?;
                let key: [u8; KEY_LEN] = raw
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Stored data key has the wrong length"))?;
                Ok(Some(key))
            }
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("OS secret store read failed: {e}")),
        }
    }
}

#[cfg(windows)]
fn encrypt(plaintext: &[u8]) -> Result<Vec<u8>> {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{CryptProtectData, CRYPT_INTEGER_BLOB};
    // SAFETY:
    // - `pbData` is read-only per the DPAPI contract, so casting the immutable
    //   `plaintext` slice's pointer to `*mut u8` is never written through (no aliasing UB).
    // - `plaintext` outlives the call (borrowed for the full scope of this fn).
    // - On success `output.pbData` is valid for `output.cbData` bytes; we copy it into
    //   an owned Vec before freeing it exactly once via LocalFree.
    unsafe {
        let input = CRYPT_INTEGER_BLOB {
            cbData: plaintext.len() as u32,
            pbData: plaintext.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB::default();
        CryptProtectData(&input, None, None, None, None, 0, &mut output)
            .context("CryptProtectData failed")?;
        let out = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(HLOCAL(output.pbData as *mut _));
        Ok(out)
    }
}

#[cfg(windows)]
fn decrypt(bytes: Vec<u8>) -> Result<Vec<u8>> {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};
    // SAFETY:
    // - `pbData` is read-only per the DPAPI contract, so casting the immutable
    //   `bytes` slice's pointer to `*mut u8` is never written through (no aliasing UB).
    // - `bytes` outlives the call (owned for the full scope of this fn).
    // - On success `output.pbData` is valid for `output.cbData` bytes; we copy it into
    //   an owned Vec before freeing it exactly once via LocalFree.
    unsafe {
        let input = CRYPT_INTEGER_BLOB {
            cbData: bytes.len() as u32,
            pbData: bytes.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB::default();
        match CryptUnprotectData(&input, None, None, None, None, 0, &mut output) {
            Ok(()) => {
                let out =
                    std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
                let _ = LocalFree(HLOCAL(output.pbData as *mut _));
                Ok(out)
            }
            Err(e) => {
                if looks_like_dpapi(&bytes) {
                    Err(anyhow::anyhow!(
                        "Failed to decrypt DPAPI-protected secret (corrupted, or written by a different user): {e}"
                    ))
                } else {
                    // Not a DPAPI blob — a legacy unencrypted file from before
                    // encryption was added. Return it as-is for transparent migration.
                    Ok(bytes)
                }
            }
        }
    }
}

#[cfg(windows)]
fn looks_like_dpapi(bytes: &[u8]) -> bool {
    // DPAPI blobs start with dwVersion (0x00000001 LE) followed by the default
    // provider GUID {df9d8cd0-1115-11d1-8c7a-00c04fc297eb}.
    const DPAPI_MAGIC: [u8; 20] = [
        0x01, 0x00, 0x00, 0x00, 0xd0, 0x8c, 0x9d, 0xdf, 0x01, 0x15, 0xd1, 0x11, 0x8c, 0x7a, 0x00,
        0xc0, 0x4f, 0xc2, 0x97, 0xeb,
    ];
    bytes.len() >= DPAPI_MAGIC.len() && bytes[..DPAPI_MAGIC.len()] == DPAPI_MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn dek_errors_and_malformed_values_are_not_absence() {
        use super::envelope::decode_dek;
        assert!(decode_dek(Err(keyring_core::Error::NoEntry))
            .unwrap()
            .is_none());
        assert!(decode_dek(Err(keyring_core::Error::Ambiguous(Vec::new()))).is_err());
        assert!(decode_dek(Ok("not base64!".into())).is_err());
        assert!(decode_dek(Ok("YQ==".into())).is_err());
    }

    #[test]
    fn existing_dek_is_reused_and_errors_never_create_a_replacement() {
        use super::envelope::load_or_create_dek_with;
        assert_eq!(
            load_or_create_dek_with(|| Ok(Some([7; 32])), |_| panic!("must reuse")).unwrap(),
            [7; 32]
        );
        assert!(load_or_create_dek_with(
            || anyhow::bail!("locked or malformed"),
            |_| panic!("must not overwrite")
        )
        .is_err());
        assert!(load_or_create_dek_with(|| Ok(None), |_| anyhow::bail!("write failed")).is_err());
        let key = load_or_create_dek_with(
            || Ok(None),
            |encoded| {
                assert!(super::envelope::decode_dek(Ok(encoded.to_owned()))?.is_some());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(key.len(), 32);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    #[ignore = "run scripts/test-keyring-compat.sh with an isolated synthetic Secret Service"]
    fn v3_credentials_remain_usable() {
        use crate::config::credential_store::Entry;
        use std::process::Command;
        assert_eq!(
            std::env::var("ZENTRA_ISOLATED_CREDENTIAL_TEST").unwrap(),
            "1"
        );
        #[cfg(target_os = "macos")]
        {
            #[link(name = "Security", kind = "framework")]
            extern "C" {
                fn SecKeychainSetUserInteractionAllowed(state: u8) -> i32;
            }
            // Test-only public API: unexpected authorization must fail, not prompt.
            assert_eq!(unsafe { SecKeychainSetUserInteractionAllowed(0) }, 0);
        }
        let service = std::env::var("ZENTRA_CREDENTIAL_TEST_SERVICE").unwrap();
        assert!(service.starts_with("zentra-test-"));
        let fixture = std::env::var("ZENTRA_KEYRING_V3_FIXTURE").unwrap();
        let dir = TempDir::new().unwrap();
        struct Cleanup<'a>(&'a str, &'a str, &'a Path);
        impl Drop for Cleanup<'_> {
            fn drop(&mut self) {
                let _ = Command::new(self.0)
                    .arg("cleanup")
                    .arg(self.1)
                    .arg(self.2)
                    .status();
            }
        }
        let _cleanup = Cleanup(&fixture, &service, dir.path());
        let run_old = |command| {
            assert!(Command::new(&fixture)
                .arg(command)
                .arg(&service)
                .arg(dir.path())
                .status()
                .unwrap()
                .success());
        };
        run_old("seed");
        let dek = Entry::new(&service, "secret-store-key-v1").unwrap();
        let key = super::envelope::decode_dek(dek.get_password())
            .unwrap()
            .unwrap();
        assert_eq!(key, [7; 32]);
        let old_blob = std::fs::read(dir.path().join("old.key")).unwrap();
        assert_eq!(
            super::envelope::open(&key, &old_blob).unwrap(),
            b"old-envelope-secret"
        );
        let reused = super::envelope::load_or_create_dek_with(
            || super::envelope::decode_dek(dek.get_password()),
            |_| panic!("existing DEK must not be replaced"),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("new.key"),
            super::envelope::seal(&reused, b"new-envelope-secret").unwrap(),
        )
        .unwrap();
        let api = Entry::new(&service, "api_key").unwrap();
        assert_eq!(api.get_password().unwrap(), "old-api-key");
        api.set_password("new-api-key").unwrap();
        let oauth = Entry::new(&service, "oauth_tokens").unwrap();
        assert_eq!(oauth.get_password().unwrap(), "old-oauth-tokens");
        oauth.delete_credential().unwrap();
        assert!(matches!(
            oauth.get_password(),
            Err(keyring_core::Error::NoEntry)
        ));
        let legacy = Entry::new(&format!("{service}-legacy"), "api_key").unwrap();
        assert_eq!(legacy.get_password().unwrap(), "old-targetless-key");
        legacy.set_password("new-targetless-key").unwrap();
        Entry::new(&service, "new_user")
            .unwrap()
            .set_password("new-credential")
            .unwrap();
        let fresh = Entry::new(&service, "new-only-user").unwrap();
        assert!(matches!(
            fresh.get_password(),
            Err(keyring_core::Error::NoEntry)
        ));
        fresh.set_password("new-only-credential").unwrap();
        assert_eq!(fresh.get_password().unwrap(), "new-only-credential");
        fresh.delete_credential().unwrap();
        run_old("verify");
        legacy.delete_credential().unwrap();
        assert!(matches!(
            legacy.get_password(),
            Err(keyring_core::Error::NoEntry)
        ));
        #[cfg(target_os = "linux")]
        {
            use dbus_secret_service::{EncryptionType, SecretService};
            use std::collections::HashMap;
            let ss = SecretService::connect(EncryptionType::Dh).unwrap();
            let collection = ss.get_default_collection().unwrap();
            // Ambiguity must not broaden lookup, overwrite a DEK, or delete
            // arbitrary items. Exercise both primary and legacy lookup paths.
            for modern in [false, true] {
                let user = if modern {
                    "ambiguous-modern"
                } else {
                    "ambiguous-legacy"
                };
                let mut attributes =
                    HashMap::from([("service", service.as_str()), ("username", user)]);
                if modern {
                    attributes.insert("target", "default");
                }
                let first = collection
                    .create_item(
                        "first synthetic item",
                        attributes.clone(),
                        b"first",
                        false,
                        "text/plain",
                    )
                    .unwrap();
                let second = collection
                    .create_item(
                        "second synthetic item",
                        attributes,
                        b"second",
                        false,
                        "text/plain",
                    )
                    .unwrap();
                let entry = Entry::new(&service, user).unwrap();
                assert!(entry.get_password().is_err());
                assert!(entry.set_password("must-not-overwrite").is_err());
                assert!(entry.delete_credential().is_err());
                assert_eq!(first.get_secret().unwrap(), b"first");
                assert_eq!(second.get_secret().unwrap(), b"second");
                first.delete().unwrap();
                second.delete().unwrap();
            }
        }
    }

    #[test]
    fn write_then_read_roundtrips() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("secret.bin");
        let secret = b"sk-test-abc123";
        write_secret(&path, secret).unwrap();
        let got = read_secret(&path).unwrap();
        assert_eq!(got, secret);
    }

    #[test]
    fn envelope_seal_open_roundtrips() {
        let key = [7u8; 32];
        let plaintext = b"sk-secret-value-xyz";
        let blob = super::envelope::seal(&key, plaintext).unwrap();
        assert!(super::envelope::looks_like_envelope(&blob));
        assert_ne!(
            blob.as_slice(),
            plaintext.as_slice(),
            "sealed blob must not be plaintext"
        );
        assert_eq!(super::envelope::open(&key, &blob).unwrap(), plaintext);
    }

    #[test]
    fn envelope_open_rejects_corrupted_blob() {
        let key = [7u8; 32];
        let mut blob = super::envelope::seal(&key, b"a-real-secret").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        assert!(
            super::envelope::open(&key, &blob).is_err(),
            "corrupted tag must fail auth"
        );
    }

    #[test]
    fn envelope_open_rejects_wrong_key() {
        let blob = super::envelope::seal(&[1u8; 32], b"x").unwrap();
        assert!(
            super::envelope::open(&[2u8; 32], &blob).is_err(),
            "wrong key must fail auth"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn read_falls_back_to_plaintext_for_legacy_files_on_unix() {
        // A pre-existing unencrypted key file (no magic prefix) must still be readable.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("legacy.key");
        std::fs::write(&path, b"sk-legacy-plaintext").unwrap();
        assert_eq!(read_secret(&path).unwrap(), b"sk-legacy-plaintext");
    }

    #[cfg(unix)]
    #[test]
    fn write_sets_owner_only_permissions_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("secret.bin");
        write_secret(&path, b"x").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[cfg(windows)]
    #[test]
    fn read_falls_back_to_plaintext_for_legacy_files() {
        // A pre-existing unencrypted key file must still be readable.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("legacy.key");
        std::fs::write(&path, b"sk-legacy-plaintext").unwrap();
        let got = read_secret(&path).unwrap();
        assert_eq!(got, b"sk-legacy-plaintext");
    }

    #[cfg(windows)]
    #[test]
    fn read_errors_on_corrupted_dpapi_blob() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("corrupt.bin");
        write_secret(&path, b"a-real-secret").unwrap();
        // Corrupt a byte in the ciphertext body (past the 20-byte header) so it
        // still looks like a DPAPI blob but fails to decrypt.
        let mut bytes = std::fs::read(&path).unwrap();
        let i = bytes.len() - 5;
        bytes[i] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();
        assert!(
            read_secret(&path).is_err(),
            "corrupted DPAPI blob must error, not return garbage"
        );
    }

    #[cfg(windows)]
    #[test]
    fn encrypted_file_is_not_plaintext_on_disk() {
        // Sanity: on Windows the bytes on disk must differ from the plaintext.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("enc.bin");
        let secret = b"super-secret-value-1234567890";
        write_secret(&path, secret).unwrap();
        let on_disk = std::fs::read(&path).unwrap();
        assert_ne!(on_disk, secret, "DPAPI ciphertext must not equal plaintext");
        assert_eq!(read_secret(&path).unwrap(), secret);
    }
}
