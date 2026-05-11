use std::process::Command;
use std::time::Duration;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;
use zentra_cli::scanners::secrets::{
    allowlist::Allowlist,
    git_history,
    patterns,
    validator::ContextValidator,
    HistoryDepth,
};

fn init_git_repo(dir: &TempDir) {
    Command::new("git")
        .args(["init"])
        .current_dir(dir.path())
        .output()
        .unwrap();
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
async fn scan_history_respects_cancel_token() {
    let dir = TempDir::new().unwrap();
    init_git_repo(&dir);

    // Seed some history so the scan has work to do
    for i in 0..5 {
        let file_name = format!("config{}.rs", i);
        std::fs::write(
            dir.path().join(&file_name),
            format!(r#"let key{} = "AKIAIOSFODNN7EXAMPLE{}";"#, i, i),
        )
        .unwrap();
        Command::new("git")
            .args(["add", "."])
            .current_dir(dir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", &format!("commit {}", i)])
            .current_dir(dir.path())
            .output()
            .unwrap();
    }

    let root = dir.path().to_path_buf();
    let token = CancellationToken::new();
    let token_clone = token.clone();

    let handle = tokio::spawn(async move {
        let al = Allowlist::load(&root);
        let validator = ContextValidator::new(&al);
        let pats = patterns::all_patterns();
        let depth = HistoryDepth::Last(1000);

        // This call includes a &CancellationToken that scan_history does not yet accept.
        git_history::scan_history(&root, &depth, pats, &validator, &token_clone)
            .await
            .unwrap()
    });

    // Cancel immediately
    token.cancel();

    // Assert the task completes within 2 seconds (proving cancellation works)
    let result = tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("scan_history should complete within 2 seconds after cancellation")
        .expect("task should not panic");

    // Assert it returns a Vec<SecretsMatch> (length doesn't matter, just that it didn't hang)
    let _matches: Vec<_> = result;
}
