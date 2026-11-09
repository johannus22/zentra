//! Opt-in installed-tool smoke test: needs cargo-audit and GitHub network access.
use serde_json::Value;

#[test]
#[ignore = "requires installed cargo-audit and access to the public advisory database"]
fn installed_cargo_audit_ignores_project_config_and_preserves_report() {
    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir(project.path().join(".cargo")).unwrap();
    // Both would fail parsing if the scanner consulted the target's config.
    for name in ["config.toml", "audit.toml"] {
        std::fs::write(project.path().join(".cargo").join(name), "[invalid TOML").unwrap();
    }
    let lock = "version = 3\n\n[[package]]\nname = \"time\"\nversion = \"0.1.45\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
    std::fs::write(project.path().join("Cargo.lock"), lock).unwrap();
    let output = zentra_cli::tools::audit::run_cargo_audit_at(project.path());
    let report: Value = serde_json::from_str(&output).expect(&output);
    assert_eq!(report["status"], "complete", "{output}");
    let artifacts: Vec<_> = std::fs::read_dir(project.path().join(".zentra/reports"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(artifacts.len(), 1, "{artifacts:?}");
    let artifact = std::fs::read_to_string(&artifacts[0]).unwrap();
    let _: Value = serde_json::from_str(&artifact).unwrap();
    assert!(artifact.contains("vulnerabilities"), "{artifact}");
    assert_eq!(
        std::fs::read_to_string(project.path().join("Cargo.lock")).unwrap(),
        lock
    );
    assert!(!project.path().join("Cargo.toml").exists());
}
