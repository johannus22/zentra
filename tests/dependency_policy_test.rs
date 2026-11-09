//! Guard the intentional feature wiring for the existing Linux keyring backend.

#[test]
fn linux_keyring_keeps_encrypted_transport_without_the_unused_async_backend() {
    let manifest: toml::Value = toml::from_str(include_str!("../Cargo.toml")).unwrap();
    let linux = &manifest["target"]["cfg(target_os = \"linux\")"]["dependencies"];
    let keyring_features = linux["keyring"]["features"].as_array().unwrap();
    assert!(keyring_features
        .iter()
        .any(|f| f.as_str() == Some("sync-secret-service")));
    assert!(
        !keyring_features.iter().any(|f| {
            matches!(
                f.as_str(),
                Some("crypto-rust" | "crypto-openssl" | "async-secret-service")
            )
        }),
        "keyring's crypto forwarding retains the unused async dependency chain"
    );

    // This direct dependency is intentional: Cargo unifies these features with
    // keyring's backend, preserving encrypted Secret Service transport.
    let backend_features = linux["dbus-secret-service"]["features"].as_array().unwrap();
    assert!(backend_features
        .iter()
        .any(|f| f.as_str() == Some("crypto-rust")));
}

#[test]
fn lockfile_excludes_the_unmaintained_optional_keyring_chain() {
    let lockfile: toml::Value = toml::from_str(include_str!("../Cargo.lock")).unwrap();
    let packages = lockfile["package"].as_array().unwrap();
    for name in [
        "secret-service",
        "zbus_names",
        "zvariant",
        "zvariant_derive",
    ] {
        assert!(
            packages.iter().all(|p| p["name"].as_str() != Some(name)),
            "{name} reintroduced the unused async chain; review issues #94–#96"
        );
    }
}
