use zentra_cli::commands::clone::{derive_repo_name, validate_repo_url};

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
