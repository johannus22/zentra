//! Standalone compatibility fixture, built only in a temporary project by
//! scripts/test-keyring-compat.sh. Never connect this old dependency to the app.
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::Engine;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (command, service, dir) = (&args[1], &args[2], std::path::Path::new(&args[3]));
    assert!(
        service.starts_with("zentra-test-"),
        "synthetic identities only"
    );
    let entry = |user: &str| keyring::Entry::new(service, user).unwrap();
    let legacy_service = format!("{service}-legacy");
    #[cfg(target_os = "linux")]
    let legacy = keyring::Entry::new_with_credential(Box::new(
        keyring::secret_service::SsCredential::new_with_no_target(&legacy_service, "api_key")
            .unwrap(),
    ));
    #[cfg(target_os = "macos")]
    let legacy = keyring::Entry::new(&legacy_service, "api_key").unwrap();
    match command.as_str() {
        "seed" => {
            let key = [7u8; 32];
            let encoded = base64::engine::general_purpose::STANDARD.encode(key);
            entry("secret-store-key-v1").set_password(&encoded).unwrap();
            entry("api_key").set_password("old-api-key").unwrap();
            entry("oauth_tokens")
                .set_password("old-oauth-tokens")
                .unwrap();
            #[cfg(target_os = "linux")]
            {
                use dbus_secret_service::{EncryptionType, SecretService};
                let ss = SecretService::connect(EncryptionType::Dh).unwrap();
                ss.get_default_collection()
                    .unwrap()
                    .create_item(
                        "synthetic legacy credential",
                        std::collections::HashMap::from([
                            ("service", legacy_service.as_str()),
                            ("username", "api_key"),
                        ]),
                        b"old-targetless-key",
                        false,
                        "text/plain",
                    )
                    .unwrap();
            }
            #[cfg(target_os = "macos")]
            legacy.set_password("old-targetless-key").unwrap();
            // Frozen v0.15.4 format: MAGIC || 12-byte nonce || AES-256-GCM ciphertext+tag.
            let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
            let nonce = [0u8; 12];
            let ct = cipher
                .encrypt(Nonce::from_slice(&nonce), b"old-envelope-secret".as_ref())
                .unwrap();
            let mut blob = b"ZSE1".to_vec();
            blob.extend_from_slice(&nonce);
            blob.extend_from_slice(&ct);
            std::fs::write(dir.join("old.key"), blob).unwrap();
        }
        "verify" => {
            assert_eq!(
                entry("secret-store-key-v1").get_password().unwrap(),
                base64::engine::general_purpose::STANDARD.encode([7u8; 32])
            );
            assert_eq!(entry("api_key").get_password().unwrap(), "new-api-key");
            assert_eq!(entry("new_user").get_password().unwrap(), "new-credential");
            assert!(matches!(
                entry("oauth_tokens").get_password(),
                Err(keyring::Error::NoEntry)
            ));
            assert_eq!(legacy.get_password().unwrap(), "new-targetless-key");
            let blob = std::fs::read(dir.join("new.key")).unwrap();
            assert_eq!(&blob[..4], b"ZSE1");
            let cipher = Aes256Gcm::new_from_slice(&[7u8; 32]).unwrap();
            assert_eq!(
                cipher
                    .decrypt(Nonce::from_slice(&blob[4..16]), &blob[16..])
                    .unwrap(),
                b"new-envelope-secret"
            );
        }
        "cleanup" => {
            for user in ["secret-store-key-v1", "api_key", "oauth_tokens", "new_user"] {
                let _ = entry(user).delete_credential();
            }
            let _ = legacy.delete_credential();
        }
        _ => panic!("unknown fixture operation"),
    }
}
