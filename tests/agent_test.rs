// tests/agent_test.rs
use zentra_cli::{agent, state, tools};
use zentra_cli::tools::fs_tools::{grep_code, list_files, read_file};

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
