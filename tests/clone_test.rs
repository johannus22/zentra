use zentra_cli::commands::clone::{derive_audit_name, derive_repo_name, validate_repo_url};

use std::path::Path;
use std::process::Command;
use tempfile::TempDir;
use zentra_cli::commands::clone::{clone_repo, copy_dir_recursive, CwdGuard};

fn git(args: &[&str], dir: &Path) {
    let status = Command::new("git")
        .args(args)
        .current_dir(dir)
        .status()
        .expect("git should be installed");
    assert!(status.success(), "git {:?} failed", args);
}

#[test]
fn clone_repo_clones_a_local_source_repo() {
    // Build a source repo with one commit.
    let src = TempDir::new().unwrap();
    git(&["init", "-q"], src.path());
    git(&["config", "user.email", "t@test.test"], src.path());
    git(&["config", "user.name", "t"], src.path());
    std::fs::write(src.path().join("README.md"), "hello").unwrap();
    git(&["add", "."], src.path());
    git(&["commit", "-qm", "init"], src.path());

    let dest_parent = TempDir::new().unwrap();
    let dest = dest_parent.path().join("clone");
    let url = format!("file://{}", src.path().display());

    clone_repo(&url, &dest).unwrap();
    assert!(dest.join("README.md").exists());
}

#[test]
fn clone_repo_errors_on_missing_source() {
    let dest_parent = TempDir::new().unwrap();
    let dest = dest_parent.path().join("clone");
    let err = clone_repo("https://invalid.invalid/nope.git", &dest).unwrap_err();
    assert!(err.to_string().contains("git clone failed"), "got: {err}");
}

#[test]
fn copy_dir_recursive_copies_nested_files() {
    let src = TempDir::new().unwrap();
    std::fs::create_dir_all(src.path().join("reports")).unwrap();
    std::fs::write(src.path().join("detailed-findings.md"), "f").unwrap();
    std::fs::write(src.path().join("reports/r.json"), "{}").unwrap();

    let dst_parent = TempDir::new().unwrap();
    let dst = dst_parent.path().join("audits/bar");
    copy_dir_recursive(src.path(), &dst).unwrap();

    assert!(dst.join("detailed-findings.md").exists());
    assert!(dst.join("reports/r.json").exists());
}

#[test]
fn cwd_guard_restores_original_directory_on_drop() {
    let _lock = clone_cwd_lock().lock().unwrap_or_else(|e| e.into_inner());
    let original = std::env::current_dir().unwrap();
    let target = TempDir::new().unwrap();
    {
        let _guard = CwdGuard::change_to(target.path()).unwrap();
        // canonicalize both sides to neutralize macOS /private symlinking
        assert_eq!(
            std::env::current_dir().unwrap().canonicalize().unwrap(),
            target.path().canonicalize().unwrap()
        );
    }
    assert_eq!(std::env::current_dir().unwrap(), original);
}

// Local lock so cwd-mutating tests in this file don't race each other.
static CLONE_CWD_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
fn clone_cwd_lock() -> &'static std::sync::Mutex<()> {
    CLONE_CWD_LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

#[test]
fn validates_accepted_url_schemes() {
    assert!(validate_repo_url("https://github.com/foo/bar.git").is_ok());
    assert!(validate_repo_url("http://example.com/x.git").is_ok());
    assert!(validate_repo_url("git://example.com/x.git").is_ok());
    assert!(validate_repo_url("ssh://git@example.com/x.git").is_ok());
    assert!(validate_repo_url("git@github.com:foo/bar.git").is_ok());
}

#[test]
fn rejects_empty_and_unknown_schemes() {
    assert!(validate_repo_url("").is_err());
    assert!(validate_repo_url("   ").is_err());
    assert!(validate_repo_url("file:///etc/passwd").is_err());
    assert!(validate_repo_url("not a url").is_err());
}

// Iter-3 LOW: a `-`-leading authority (ssh option-injection on older git) must be
// rejected; a well-formed host with an ssh user must still pass.
#[test]
fn rejects_option_injection_authority() {
    assert!(validate_repo_url("ssh://-oProxyCommand=calc/x.git").is_err());
    assert!(validate_repo_url("ssh://user@-evil/x.git").is_err());
    assert!(validate_repo_url("https://-oEvil/x.git").is_err());
    // Legitimate URLs still accepted.
    assert!(validate_repo_url("ssh://git@example.com/x.git").is_ok());
    assert!(validate_repo_url("https://github.com/foo/bar.git").is_ok());
}

#[test]
fn derives_repo_name_from_url() {
    assert_eq!(derive_repo_name("https://github.com/foo/bar.git"), "bar");
    assert_eq!(derive_repo_name("https://github.com/foo/bar"), "bar");
    assert_eq!(derive_repo_name("git@github.com:foo/baz.git"), "baz");
    assert_eq!(derive_repo_name("https://example.com/a/b/c/"), "c");
}

#[test]
fn derives_safe_fallback_for_weird_input() {
    // No path segment -> non-empty, filesystem-safe fallback
    let name = derive_repo_name("https://");
    assert!(!name.is_empty());
    assert!(name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_'));
}

#[test]
fn derives_owner_namespaced_audit_name() {
    assert_eq!(
        derive_audit_name("https://github.com/octocat/Hello-World.git"),
        "octocat-Hello-World"
    );
    assert_eq!(derive_audit_name("git@github.com:foo/bar.git"), "foo-bar");
}

#[test]
fn audit_name_falls_back_to_repo_when_owner_is_host_or_absent() {
    // Single path segment -> owner candidate is the host (dotted) -> skipped.
    assert_eq!(derive_audit_name("https://host.example/repo.git"), "repo");
}
