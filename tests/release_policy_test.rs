#[test]
fn binary_archives_preserve_third_party_attribution() {
    let config: toml::Value = toml::from_str(include_str!("../dist-workspace.toml")).unwrap();
    let includes = config["dist"]["include"].as_array().unwrap();
    for required in ["NOTICE", "LICENSES"] {
        assert!(includes
            .iter()
            .any(|value| value.as_str() == Some(required)));
    }
    let notice = include_str!("../NOTICE");
    let license = include_str!("../LICENSES/cloudflare-security-audit-skill-MIT.txt");
    assert!(notice.contains("Cloudflare"));
    assert!(license.contains("Copyright (c) 2025-2026 Cloudflare, Inc."));
    assert!(license.contains("Permission is hereby granted"));
}

#[test]
fn container_distribution_preserves_notices() {
    let dockerfile = include_str!("../Dockerfile");
    assert!(dockerfile.contains("COPY LICENSE NOTICE /usr/local/share/doc/zentra/"));
    assert!(dockerfile.contains("COPY LICENSES/ /usr/local/share/doc/zentra/LICENSES/"));
}
