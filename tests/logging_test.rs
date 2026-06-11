//! Integration tests for the global crash/error log (`src/logging`).
//! Uses the public `CrashLog` API against a `TempDir` so nothing touches
//! `~/.zentra`.

use std::sync::Arc;
use zentra_cli::logging::CrashLog;

#[test]
fn error_entry_is_written_with_level_and_component() {
    let tmp = tempfile::tempdir().unwrap();
    let log = CrashLog::new(tmp.path(), true);
    log.error(
        "pentest",
        "stage 'Network Recon' failed: nmap not found on PATH",
    );

    let content = std::fs::read_to_string(log.path()).unwrap();
    assert!(content.contains("ERROR [pentest]"), "got: {content}");
    assert!(content.contains("nmap not found on PATH"), "got: {content}");
}

#[test]
fn warn_and_error_levels_are_distinguished() {
    let tmp = tempfile::tempdir().unwrap();
    let log = CrashLog::new(tmp.path(), true);
    log.warn("scan", "browser unavailable, skipping screenshots");
    log.error("scan", "scanner task failed");

    let content = std::fs::read_to_string(log.path()).unwrap();
    assert!(content.contains("WARN [scan]"), "got: {content}");
    assert!(content.contains("ERROR [scan]"), "got: {content}");
}

#[test]
fn secrets_are_redacted_before_disk() {
    let tmp = tempfile::tempdir().unwrap();
    let log = CrashLog::new(tmp.path(), true);
    log.error(
        "scan",
        "auth failed key=sk-ant-SUPERSECRET12345 password=hunter2 token in url ?access_token=abc123",
    );

    let content = std::fs::read_to_string(log.path()).unwrap();
    assert!(
        !content.contains("SUPERSECRET12345"),
        "leaked api key: {content}"
    );
    assert!(!content.contains("hunter2"), "leaked password: {content}");
    assert!(!content.contains("abc123"), "leaked token: {content}");
    assert!(
        content.contains("***"),
        "expected redaction marker: {content}"
    );
}

#[test]
fn disabled_log_creates_no_file() {
    let tmp = tempfile::tempdir().unwrap();
    let log = CrashLog::new(tmp.path(), false);
    log.error("scan", "this should not be written");
    assert!(!tmp.path().join("zentra.log").exists());
}

#[test]
fn concurrent_writes_do_not_panic_and_all_land() {
    let tmp = tempfile::tempdir().unwrap();
    let log = Arc::new(CrashLog::new(tmp.path(), true));

    let mut handles = Vec::new();
    for t in 0..8 {
        let log = Arc::clone(&log);
        handles.push(std::thread::spawn(move || {
            for i in 0..10 {
                log.error("scan", &format!("thread {t} entry {i}"));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let content = std::fs::read_to_string(log.path()).unwrap();
    let lines = content
        .lines()
        .filter(|l| l.contains("ERROR [scan]"))
        .count();
    assert_eq!(lines, 80, "expected 80 entries, got {lines}");
}
