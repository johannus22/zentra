// tests/agent_test.rs
use zentra_cli::{agent, state, tools};
use zentra_cli::tools::fs_tools::{grep_code, list_files, read_file};
use zentra_cli::tools::git_tools::{git_log, git_status};

#[test]
fn modules_exist() {
    // compile-time verification that all new modules are declared
    let _ = std::any::type_name::<agent::ScannerType>();
    let _ = std::any::type_name::<state::Finding>();
    let _ = std::any::type_name::<tools::ToolRegistry>();
}

use zentra_cli::state::{Finding, Severity, StateWriter};
use tempfile::TempDir;

#[test]
fn state_writer_creates_findings_file() {
    let dir = TempDir::new().unwrap();
    let writer = StateWriter::new(dir.path()).unwrap();

    writer.write_finding(&Finding {
        scanner: "sast".to_string(),
        severity: Severity::Critical,
        title: "SQL Injection".to_string(),
        description: "User input concatenated into SQL".to_string(),
        location: Some("src/db.rs:42".to_string()),
        recommendation: "Use parameterized queries.".to_string(),
    }).unwrap();

    let findings_path = dir.path().join(".zentra").join("detailed-findings.md");
    assert!(findings_path.exists(), "detailed-findings.md should exist");

    let content = std::fs::read_to_string(&findings_path).unwrap();
    assert!(content.contains("SQL Injection"), "should contain finding title");
    assert!(content.contains("CRITICAL"), "should contain severity");
    assert!(content.contains("src/db.rs:42"), "should contain location");
}

#[test]
fn state_writer_appends_multiple_findings() {
    let dir = TempDir::new().unwrap();
    let writer = StateWriter::new(dir.path()).unwrap();

    for i in 0..3 {
        writer.write_finding(&Finding {
            scanner: "sast".to_string(),
            severity: Severity::High,
            title: format!("Finding {}", i),
            description: "desc".to_string(),
            location: None,
            recommendation: "fix it".to_string(),
        }).unwrap();
    }

    let content = std::fs::read_to_string(dir.path().join(".zentra").join("detailed-findings.md")).unwrap();
    assert!(content.contains("Finding 0"));
    assert!(content.contains("Finding 1"));
    assert!(content.contains("Finding 2"));
}

#[test]
fn state_writer_writes_report() {
    let dir = TempDir::new().unwrap();
    let writer = StateWriter::new(dir.path()).unwrap();
    writer.write_report("# Executive Summary\n\nAll clear.").unwrap();

    let reports_dir = dir.path().join(".zentra").join("reports");
    let entries: Vec<_> = std::fs::read_dir(&reports_dir).unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(entries.len(), 1, "should have one report file");

    let filename = entries[0].file_name();
    let name = filename.to_string_lossy();
    assert!(name.ends_with("-report.md"), "filename should end with -report.md, got: {}", name);

    let content = std::fs::read_to_string(entries[0].path()).unwrap();
    assert!(content.contains("Executive Summary"), "report should contain written content");
}

#[test]
fn read_findings_raw_returns_empty_when_no_findings() {
    let dir = TempDir::new().unwrap();
    let writer = StateWriter::new(dir.path()).unwrap();
    let result = writer.read_findings_raw().unwrap();
    assert!(result.is_empty(), "should return empty string when no findings written");
}

#[test]
fn read_findings_raw_returns_written_findings() {
    let dir = TempDir::new().unwrap();
    let writer = StateWriter::new(dir.path()).unwrap();
    writer.write_finding(&Finding {
        scanner: "sast".to_string(),
        severity: Severity::Low,
        title: "Test".to_string(),
        description: "desc".to_string(),
        location: None,
        recommendation: "fix".to_string(),
    }).unwrap();

    let content = writer.read_findings_raw().unwrap();
    assert!(content.contains("Test"), "should contain the written finding title");
}

#[test]
fn read_file_returns_content() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    std::fs::write(&file, "hello world").unwrap();

    let content = read_file(file.to_str().unwrap());
    assert_eq!(content, "hello world");
}

#[test]
fn read_file_returns_error_message_for_missing_file() {
    let content = read_file("/nonexistent/path/to/file.txt");
    assert!(content.starts_with("Error:"), "should return error message, got: {}", content);
}

#[test]
fn read_file_blocks_path_traversal() {
    let content = read_file("../../etc/passwd");
    assert!(content.contains("path traversal not allowed"));
}

#[test]
fn list_files_finds_files_in_dir() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("a.rs"), "").unwrap();
    std::fs::write(dir.path().join("b.rs"), "").unwrap();

    let result = list_files(dir.path().to_str().unwrap(), None);
    assert!(result.contains("a.rs"), "should list a.rs");
    assert!(result.contains("b.rs"), "should list b.rs");
}

#[test]
fn list_files_filters_by_pattern() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("main.rs"), "").unwrap();
    std::fs::write(dir.path().join("config.toml"), "").unwrap();

    let result = list_files(dir.path().to_str().unwrap(), Some(".rs"));
    assert!(result.contains("main.rs"), "should include .rs files");
    assert!(!result.contains("config.toml"), "should exclude .toml files");
}

#[test]
fn grep_code_finds_pattern() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("main.rs"), "fn main() {\n    let secret = \"abc\";\n}\n").unwrap();

    let result = grep_code("secret", Some(dir.path().to_str().unwrap()));
    assert!(result.contains("secret"), "should find 'secret'");
    assert!(result.contains("main.rs"), "should reference the file");
}

#[test]
fn grep_code_returns_no_matches_message() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("a.rs"), "fn main() {}").unwrap();

    let result = grep_code("VERY_UNLIKELY_PATTERN_XYZ123", Some(dir.path().to_str().unwrap()));
    assert!(result.contains("No matches"), "should say no matches");
}

use zentra_cli::tools::audit::run_audit;

#[test]
fn run_audit_returns_string_when_tool_not_installed() {
    // Run in a temp dir where audit tools are unlikely to be configured
    // The function must not panic — it returns a graceful message
    let _guard = cwd_lock().lock().unwrap();
    let dir = TempDir::new().unwrap();
    let original = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();

    let result = run_audit("npm");

    std::env::set_current_dir(original).unwrap();
    // Either actual audit JSON or a "not found / no lockfile" message
    assert!(!result.is_empty());
}

#[test]
fn run_audit_rejects_unknown_tool() {
    let result = run_audit("unknown_tool_xyz");
    assert!(result.contains("Unknown audit tool"));
}

/// Serialize tests that mutate the process-global current directory so they
/// don't race when cargo runs tests in parallel.
static CWD_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();

fn cwd_lock() -> &'static std::sync::Mutex<()> {
    CWD_LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

#[test]
fn git_log_returns_string_outside_git_repo() {
    // Run from a temp dir with no .git — should not panic, just return graceful message
    let _guard = cwd_lock().lock().unwrap();
    let dir = TempDir::new().unwrap();
    let original = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();

    let result = git_log(5);

    std::env::set_current_dir(&original).unwrap();
    // Either returns commits or a graceful "not a git repo" message — must not panic
    assert!(!result.is_empty());
}

#[test]
fn git_status_returns_string_outside_git_repo() {
    let _guard = cwd_lock().lock().unwrap();
    let dir = TempDir::new().unwrap();
    let original = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();

    let result = git_status();

    std::env::set_current_dir(&original).unwrap();
    assert!(!result.is_empty());
}
