use tokio_util::sync::CancellationToken;
use std::process::Command;
use tempfile::TempDir;
use zentra_cli::scanners::secrets::{
    allowlist::Allowlist, git_history, patterns, validator::ContextValidator, HistoryDepth,
    SecretScanner,
};
use zentra_cli::state::StateWriter;

fn init_git_repo(dir: &TempDir) {
    Command::new("git").args(["init"]).current_dir(dir.path()).output().unwrap();
    Command::new("git")
        .args(["config", "user.email", "test@test.com"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    Command::new("git")
        .args(["config", "user.name", "Test"])
        .current_dir(dir.path())
        .output()
        .unwrap();
}

#[tokio::test]
async fn git_history_detects_planted_secret_in_past_commit() {
    let dir = TempDir::new().unwrap();
    init_git_repo(&dir);

    std::fs::write(dir.path().join("config.rs"), r#"let key = "AKIAIOSFODNN7EXAMPLE";"#).unwrap();
    Command::new("git").args(["add", "."]).current_dir(dir.path()).output().unwrap();
    Command::new("git")
        .args(["commit", "-m", "add config"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    std::fs::write(
        dir.path().join("config.rs"),
        r#"let key = std::env::var("AWS_KEY").unwrap();"#,
    )
    .unwrap();
    Command::new("git").args(["add", "."]).current_dir(dir.path()).output().unwrap();
    Command::new("git")
        .args(["commit", "-m", "remove secret"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let al = Allowlist::load(dir.path());
    let validator = ContextValidator::new(&al);
    let pats = patterns::all_patterns();

    let hits = git_history::scan_history(dir.path(), &HistoryDepth::All, pats, &validator, &tokio_util::sync::CancellationToken::new())
        .await
        .unwrap();

    assert!(
        hits.iter().any(|h| h.detector == "aws_access_key" && h.commit.is_some()),
        "expected aws_access_key hit in git history, got: {:?}",
        hits.iter().map(|h| &h.detector).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn git_history_depth_zero_returns_empty() {
    let dir = TempDir::new().unwrap();
    init_git_repo(&dir);

    let al = Allowlist::load(dir.path());
    let validator = ContextValidator::new(&al);
    let pats = patterns::all_patterns();

    let hits = git_history::scan_history(dir.path(), &HistoryDepth::Last(0), pats, &validator, &tokio_util::sync::CancellationToken::new())
        .await
        .unwrap();

    assert!(hits.is_empty(), "depth=0 should return no hits");
}

#[tokio::test]
async fn git_not_available_returns_empty_gracefully() {
    let dir = TempDir::new().unwrap();
    let al = Allowlist::load(dir.path());
    let validator = ContextValidator::new(&al);
    let pats = patterns::all_patterns();

    let result =
        git_history::scan_history(dir.path(), &HistoryDepth::Last(10), pats, &validator, &tokio_util::sync::CancellationToken::new()).await;

    assert!(result.is_ok(), "expected Ok([]) when git is unavailable, got {:?}", result);
    assert!(result.unwrap().is_empty());
}

// ---- Engine integration tests ----

#[tokio::test]
async fn engine_detects_secret_in_working_tree() {
    let dir = TempDir::new().unwrap();

    std::fs::write(dir.path().join("config.rs"), r#"let key = "AKIAIOSFODNN7EXAMPLE";"#).unwrap();
    std::fs::create_dir_all(dir.path().join(".zentra")).unwrap();

    let (tx, _rx) = tokio::sync::mpsc::channel(128);
    let writer = StateWriter::new(dir.path()).unwrap();

    let cancel_token = tokio_util::sync::CancellationToken::new();
    let scanner = SecretScanner::new(
        dir.path().to_path_buf(),
        HistoryDepth::Last(0),
        tx,
        cancel_token,
    );

    let matches = scanner.run(&writer).await.unwrap();

    assert!(
        matches.iter().any(|m| m.detector == "aws_access_key" && !m.suppressed),
        "expected active aws_access_key hit in working tree, got: {:?}",
        matches
    );
}

#[tokio::test]
async fn engine_suppresses_secrets_in_test_dir() {
    let dir = TempDir::new().unwrap();
    std::fs::create_dir_all(dir.path().join("tests")).unwrap();
    std::fs::write(
        dir.path().join("tests").join("fixtures.rs"),
        r#"let key = "AKIAIOSFODNN7EXAMPLE";"#,
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join(".zentra")).unwrap();

    let (tx, _rx) = tokio::sync::mpsc::channel(128);
    let writer = StateWriter::new(dir.path()).unwrap();
    let scanner = SecretScanner::new(dir.path().to_path_buf(), HistoryDepth::Last(0), tx, CancellationToken::new());
    let matches = scanner.run(&writer).await.unwrap();

    let active: Vec<_> = matches.iter().filter(|m| !m.suppressed).collect();
    assert!(
        active.is_empty(),
        "secrets in tests/ should be suppressed, but got active: {:?}",
        active
    );
}

#[tokio::test]
async fn engine_writes_report_files() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("config.rs"), r#"let key = "AKIAIOSFODNN7EXAMPLE";"#).unwrap();
    std::fs::create_dir_all(dir.path().join(".zentra")).unwrap();

    let (tx, _rx) = tokio::sync::mpsc::channel(128);
    let writer = StateWriter::new(dir.path()).unwrap();
    let scanner = SecretScanner::new(dir.path().to_path_buf(), HistoryDepth::Last(0), tx, CancellationToken::new());
    scanner.run(&writer).await.unwrap();

    assert!(
        dir.path().join(".zentra/secrets-report.md").exists(),
        "secrets-report.md should be written"
    );
    assert!(
        dir.path().join(".zentra/secrets-findings.json").exists(),
        "secrets-findings.json should be written"
    );
}

#[tokio::test]
async fn engine_skips_node_modules_and_target() {
    let dir = TempDir::new().unwrap();
    std::fs::create_dir_all(dir.path().join("node_modules")).unwrap();
    std::fs::write(
        dir.path().join("node_modules").join("secret.js"),
        r#"let key = "AKIAIOSFODNN7EXAMPLE";"#,
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join("target")).unwrap();
    std::fs::write(
        dir.path().join("target").join("secret.rs"),
        r#"let key = "AKIAIOSFODNN7EXAMPLE";"#,
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join("src")).unwrap();
    std::fs::write(
        dir.path().join("src").join("main.rs"),
        r#"let key = "AKIAIOSFODNN7EXAMPLE";"#,
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join(".zentra")).unwrap();

    let (tx, _rx) = tokio::sync::mpsc::channel(128);
    let writer = StateWriter::new(dir.path()).unwrap();
    let scanner = SecretScanner::new(dir.path().to_path_buf(), HistoryDepth::Last(0), tx, CancellationToken::new());
    let matches = scanner.run(&writer).await.unwrap();

    assert!(
        matches.iter().any(|m| m.detector == "aws_access_key" && m.file == "src/main.rs"),
        "should find secret in src/"
    );
    assert!(
        !matches.iter().any(|m| m.file.starts_with("node_modules") || m.file.starts_with("target")),
        "should skip node_modules and target"
    );
}
