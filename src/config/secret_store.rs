//! Platform credential storage. On Windows, secrets are encrypted at rest with
//! DPAPI (user scope). On Unix, secrets are written as plaintext with 0o600
//! permissions (the home directory already restricts access).

use anyhow::{Context, Result};
use std::path::Path;

/// Encrypt (Windows) or pass through (Unix) and write `plaintext` to `path`.
pub fn write_secret(path: &Path, plaintext: &[u8]) -> Result<()> {
    let bytes = encrypt(plaintext)?;
    std::fs::write(path, &bytes).context("Failed to write secret file")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .context("Failed to set 0o600 permissions on secret file")?;
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
    Ok(plaintext.to_vec())
}

#[cfg(not(windows))]
fn decrypt(bytes: Vec<u8>) -> Result<Vec<u8>> {
    Ok(bytes)
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
