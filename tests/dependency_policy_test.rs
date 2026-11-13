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

#[test]
fn release_dependencies_keep_security_patch_floors() {
    let lockfile: toml::Value = toml::from_str(include_str!("../Cargo.lock")).unwrap();
    let packages = lockfile["package"].as_array().unwrap();
    for (name, floor) in [("openssl", (0, 10, 80)), ("rustix", (1, 1, 6))] {
        for package in packages.iter().filter(|p| p["name"].as_str() == Some(name)) {
            let parts: Vec<u64> = package["version"]
                .as_str()
                .unwrap()
                .split('.')
                .map(|part| part.parse().unwrap())
                .collect();
            // rustix 0.38 has no affected Buffer API; the floor applies to 1.x.
            if name == "rustix" && parts[0] == 0 {
                continue;
            }
            assert!(
                (parts[0], parts[1], parts[2]) >= floor,
                "{name} is below its security patch floor"
            );
        }
    }
}
