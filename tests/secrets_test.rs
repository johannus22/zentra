use std::process::Command;
use tempfile::TempDir;
use zentra_cli::scanners::secrets::{
    allowlist::Allowlist, git_history, patterns, validator::ContextValidator, HistoryDepth,
};

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

    let hits = git_history::scan_history(dir.path(), &HistoryDepth::All, pats, &validator)
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

    std::fs::write(dir.path().join("config.rs"), r#"let key = "AKIAIOSFODNN7EXAMPLE";"#).unwrap();
    Command::new("git").args(["add", "."]).current_dir(dir.path()).output().unwrap();
    Command::new("git")
        .args(["commit", "-m", "add config"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let al = Allowlist::load(dir.path());
    let validator = ContextValidator::new(&al);
    let pats = patterns::all_patterns();

    let hits = git_history::scan_history(dir.path(), &HistoryDepth::Last(0), pats, &validator)
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
        git_history::scan_history(dir.path(), &HistoryDepth::Last(10), pats, &validator).await;

    assert!(result.is_ok(), "expected Ok([]) when git is unavailable, got {:?}", result);
    assert!(result.unwrap().is_empty());
}
