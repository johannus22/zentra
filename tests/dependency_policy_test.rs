//! The application must not regain keyring v3's unused, unmaintained async chain.
#[test]
fn credential_dependencies_exclude_the_unmaintained_async_chain() {
    let lockfile: toml::Value = toml::from_str(include_str!("../Cargo.lock")).unwrap();
    let packages = lockfile["package"].as_array().unwrap();
    for name in [
        "keyring",
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
