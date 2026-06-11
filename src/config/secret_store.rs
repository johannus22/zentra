//! Platform credential storage.
//!
//! On Windows, secrets are encrypted at rest with DPAPI (user scope).
//!
//! On Unix (Linux/macOS), secrets are sealed with AES-256-GCM under a random
//! data-encryption key (DEK) that lives in the OS secret store (Secret Service
//! on Linux, Keychain on macOS) via the `keyring` crate — envelope encryption
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
        use std::os::unix::fs::PermissionsExt; // for Permissions::from_mode
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

#[cfg(not(windows))]
fn encrypt(plaintext: &[u8]) -> Result<Vec<u8>> {
    // Envelope-encrypt under a DEK held in the OS secret store. If the store is
    // unavailable (headless/SSH/CI, locked keyring), fall back to plaintext —
    // write_secret still applies 0o600. Mirrors the Windows DPAPI design.
    match envelope::load_or_create_dek() {
        Ok(key) => envelope::seal(&key, plaintext),
        Err(_) => Ok(plaintext.to_vec()),
    }
}

#[cfg(not(windows))]
fn decrypt(bytes: Vec<u8>) -> Result<Vec<u8>> {
    if envelope::looks_like_envelope(&bytes) {
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

    fn dek_entry() -> Result<keyring::Entry> {
        keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
            .context("Failed to access OS secret store for the data key")
    }

    /// Fetch the existing DEK, or generate and store a new one. Errors only if the
    /// OS secret store is unavailable (callers treat that as "fall back to plaintext").
    pub(super) fn load_or_create_dek() -> Result<[u8; KEY_LEN]> {
        if let Some(key) = load_dek()? {
            return Ok(key);
        }
        let mut key = [0u8; KEY_LEN];
        rand::thread_rng().fill_bytes(&mut key);
        dek_entry()?
            .set_password(&base64::engine::general_purpose::STANDARD.encode(key))
            .context("Failed to store data key in OS secret store")?;
        Ok(key)
    }

    /// Fetch the DEK. `Ok(None)` if it was never created; `Err` if the store is
    /// unavailable or the stored value is malformed.
    pub(super) fn load_dek() -> Result<Option<[u8; KEY_LEN]>> {
        match dek_entry()?.get_password() {
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
            Err(keyring::Error::NoEntry) => Ok(None),
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
        0x01, 0x00, 0x00, 0x00, 0xd0, 0x8c, 0x9d, 0xdf, 0x01, 0x15, 0xd1, 0x11, 0x8c, 0x7a,
        0x00, 0xc0, 0x4f, 0xc2, 0x97, 0xeb,
    ];
    bytes.len() >= DPAPI_MAGIC.len() && bytes[..DPAPI_MAGIC.len()] == DPAPI_MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

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
        assert_ne!(blob.as_slice(), plaintext.as_slice(), "sealed blob must not be plaintext");
        assert_eq!(super::envelope::open(&key, &blob).unwrap(), plaintext);
    }

    #[test]
    fn envelope_open_rejects_corrupted_blob() {
        let key = [7u8; 32];
        let mut blob = super::envelope::seal(&key, b"a-real-secret").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        assert!(super::envelope::open(&key, &blob).is_err(), "corrupted tag must fail auth");
    }

    #[test]
    fn envelope_open_rejects_wrong_key() {
        let blob = super::envelope::seal(&[1u8; 32], b"x").unwrap();
        assert!(super::envelope::open(&[2u8; 32], &blob).is_err(), "wrong key must fail auth");
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
        assert!(read_secret(&path).is_err(), "corrupted DPAPI blob must error, not return garbage");
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
