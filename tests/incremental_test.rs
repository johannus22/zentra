use std::process::Command;
use tempfile::TempDir;
use zentra_cli::incremental::{
    compute_change_set, decide_mode, Baseline, ModeInputs, ScanManifest, ScanMode,
};

fn git(dir: &std::path::Path, args: &[&str]) {
    assert!(
        Command::new("git")
            .args(args)
            .current_dir(dir)
            .status()
            .unwrap()
            .success(),
        "git {:?} failed",
        args
    );
}

#[test]
fn manifest_baseline_then_incremental_changeset() {
    let dir = TempDir::new().unwrap();
    git(dir.path(), &["init", "-q"]);
    git(dir.path(), &["config", "user.email", "t@t.dev"]);
    git(dir.path(), &["config", "user.name", "t"]);
    std::fs::write(dir.path().join("a.rs"), "1").unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "-qm", "c1"]);
    let base = String::from_utf8(
        Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(dir.path())
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_string();

    let zentra = dir.path().join(".zentra");
    std::fs::create_dir_all(&zentra).unwrap();
    let manifest = ScanManifest {
        last_scan_commit: Some(base.clone()),
        was_dirty: false,
        scanned_at: "t".into(),
        scanner_set: vec![],
        engine_version: env!("CARGO_PKG_VERSION").into(),
        model_id: "claude · default".into(),
        mode: "full".into(),
        file_hashes: None,
    };
    manifest.save(&zentra).unwrap();

    // change a file in a new commit
    std::fs::write(dir.path().join("b.rs"), "2").unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "-qm", "c2"]);

    let prior = ScanManifest::load(&zentra).unwrap();
    let decision = decide_mode(ModeInputs {
        forced_full: false,
        is_git_repo: true,
        current_engine_version: env!("CARGO_PKG_VERSION"),
        current_model_id: "claude · default",
        prior: Some(&prior),
    });
    assert_eq!(decision.mode, ScanMode::Incremental);

    let cs = compute_change_set(dir.path(), &decision.baseline, 200).unwrap();
    assert!(
        cs.changed.contains(&"b.rs".to_string()),
        "b.rs should appear in changed: {:?}",
        cs.changed
    );
    assert!(
        !cs.changed.contains(&"a.rs".to_string()),
        "a.rs should not appear in changed: {:?}",
        cs.changed
    );
}

#[test]
fn forced_full_ignores_prior_manifest() {
    let dir = TempDir::new().unwrap();
    let zentra = dir.path().join(".zentra");
    std::fs::create_dir_all(&zentra).unwrap();
    let manifest = ScanManifest {
        last_scan_commit: Some("abc123".into()),
        was_dirty: false,
        scanned_at: "t".into(),
        scanner_set: vec![],
        engine_version: env!("CARGO_PKG_VERSION").into(),
        model_id: "claude · default".into(),
        mode: "full".into(),
        file_hashes: None,
    };
    manifest.save(&zentra).unwrap();

    let prior = ScanManifest::load(&zentra).unwrap();
    let decision = decide_mode(ModeInputs {
        forced_full: true,
        is_git_repo: true,
        current_engine_version: env!("CARGO_PKG_VERSION"),
        current_model_id: "claude · default",
        prior: Some(&prior),
    });
    assert_eq!(decision.mode, ScanMode::Full);
    assert!(decision.reason.contains("full") || decision.reason.contains("--full"));
}

#[test]
fn manifest_save_then_load_roundtrip() {
    let dir = TempDir::new().unwrap();
    let zentra = dir.path().join(".zentra");
    std::fs::create_dir_all(&zentra).unwrap();

    let manifest = ScanManifest {
        last_scan_commit: Some("deadbeef".into()),
        was_dirty: true,
        scanned_at: "2026-06-29T00:00:00Z".into(),
        scanner_set: vec!["sast".into(), "report".into()],
        engine_version: env!("CARGO_PKG_VERSION").into(),
        model_id: "claude · default".into(),
        mode: "incremental".into(),
        file_hashes: None,
    };
    manifest.save(&zentra).unwrap();

    let loaded = ScanManifest::load(&zentra).expect("manifest must load");
    assert_eq!(loaded.last_scan_commit.as_deref(), Some("deadbeef"));
    assert!(loaded.was_dirty);
    assert_eq!(loaded.mode, "incremental");
    assert_eq!(loaded.scanner_set, vec!["sast", "report"]);
}

#[test]
fn no_prior_manifest_means_full_scan() {
    let dir = TempDir::new().unwrap();
    let zentra = dir.path().join(".zentra");
    std::fs::create_dir_all(&zentra).unwrap();

    // No manifest written — load returns None.
    let decision = decide_mode(ModeInputs {
        forced_full: false,
        is_git_repo: true,
        current_engine_version: env!("CARGO_PKG_VERSION"),
        current_model_id: "claude · default",
        prior: None,
    });
    assert_eq!(decision.mode, ScanMode::Full);
    assert!(decision.reason.contains("no prior scan"));
}

#[test]
fn non_git_hash_baseline_incremental() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("a.rs"), "old content").unwrap();

    // Build a hash baseline from the current tree state.
    let hashes = zentra_cli::incremental::detect::hash_tree(dir.path()).unwrap();
    let baseline = Baseline {
        commit: None,
        file_hashes: Some(hashes),
    };

    // Modify the file so the hash differs.
    std::fs::write(dir.path().join("a.rs"), "new content").unwrap();

    let cs = compute_change_set(dir.path(), &baseline, 200).unwrap();
    assert!(
        cs.changed.contains(&"a.rs".to_string()),
        "modified file must appear in changed: {:?}",
        cs.changed
    );
}
