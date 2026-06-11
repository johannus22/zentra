//! Global crash/error log — human-readable debug telemetry written to
//! `~/.zentra/logs/zentra.log`.
//!
//! This is intentionally distinct from [`crate::security::audit_log`], which
//! SHA-256-hashes every argument for tamper-evidence and is therefore useless
//! for debugging. Here we record *failures* (errors, warnings, panics) in
//! plain text so a maintainer can read what actually went wrong — while
//! scrubbing secrets via [`redact`] before anything touches disk.
//!
//! Design rules:
//! - On by default; opt out with `ZENTRA_NO_ERROR_LOG` (mirrors
//!   `ZENTRA_NO_OS_KEYCHAIN`).
//! - Best-effort: any IO error silently disables the writer. Logging must
//!   never crash, block, or change program behavior.
//! - Only ever log error/warn/panic text — never request bodies, tool
//!   results, credentials, or successful-operation data.

use chrono::Utc;
use regex::Regex;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

const LOG_FILE: &str = "zentra.log";
const BACKUP_FILE: &str = "zentra.log.1";
/// Rotate once the active log passes this size, keeping a single backup.
const DEFAULT_MAX_BYTES: u64 = 5 * 1024 * 1024;

static LOG: OnceLock<CrashLog> = OnceLock::new();

/// Severity tag printed at the head of each entry.
#[derive(Clone, Copy)]
enum Level {
    Error,
    Warn,
    Panic,
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Level::Error => "ERROR",
            Level::Warn => "WARN",
            Level::Panic => "PANIC",
        }
    }
}

/// Append-only, size-rotated plaintext log. Holds its file handle behind a
/// `Mutex` so it can be shared immutably (e.g. via a global `OnceLock`) while
/// still writing.
pub struct CrashLog {
    path: PathBuf,
    backup_path: PathBuf,
    max_bytes: u64,
    /// `None` when disabled or when the file could not be opened.
    writer: Mutex<Option<File>>,
}

impl CrashLog {
    /// Create a log writing to `<logs_dir>/zentra.log`. When `enabled` is
    /// false, or the directory/file can't be opened, the log is a silent no-op.
    pub fn new(logs_dir: &Path, enabled: bool) -> Self {
        Self::with_max_bytes(logs_dir, enabled, DEFAULT_MAX_BYTES)
    }

    fn with_max_bytes(logs_dir: &Path, enabled: bool, max_bytes: u64) -> Self {
        let path = logs_dir.join(LOG_FILE);
        let backup_path = logs_dir.join(BACKUP_FILE);
        let writer = if enabled {
            open_log_file(logs_dir, &path)
        } else {
            None
        };
        Self {
            path,
            backup_path,
            max_bytes,
            writer: Mutex::new(writer),
        }
    }

    /// Record a failure.
    pub fn error(&self, component: &str, msg: &str) {
        self.write_entry(Level::Error, component, msg);
    }

    /// Record a recoverable warning (degraded mode, skipped step, etc.).
    pub fn warn(&self, component: &str, msg: &str) {
        self.write_entry(Level::Warn, component, msg);
    }

    /// Path of the active log file (useful for tests and diagnostics).
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn write_entry(&self, level: Level, component: &str, msg: &str) {
        let Ok(mut guard) = self.writer.lock() else {
            return;
        };
        if guard.is_none() {
            return;
        }

        let ts = Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
        let redacted = redact(msg);
        let mut lines = redacted.lines();
        let first = lines.next().unwrap_or("");
        let mut buf = format!("{ts} {} [{component}] {first}\n", level.as_str());
        for line in lines {
            buf.push_str("  ");
            buf.push_str(line);
            buf.push('\n');
        }

        // Write + flush in a scope so the `&mut File` borrow ends before we may
        // need `&mut guard` to rotate.
        let over_limit = {
            let Some(file) = guard.as_mut() else {
                return;
            };
            if file.write_all(buf.as_bytes()).is_err() {
                return;
            }
            let _ = file.flush();
            file.metadata()
                .map(|m| m.len() >= self.max_bytes)
                .unwrap_or(false)
        };

        if over_limit {
            self.rotate(&mut guard);
        }
    }

    fn rotate(&self, guard: &mut Option<File>) {
        // Drop the current handle so the rename can proceed (Windows can't
        // rename an open file), then reopen a fresh empty log.
        *guard = None;
        let _ = fs::rename(&self.path, &self.backup_path);
        if let Some(parent) = self.path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        *guard = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .ok();
    }
}

fn open_log_file(logs_dir: &Path, path: &Path) -> Option<File> {
    fs::create_dir_all(logs_dir).ok()?;
    OpenOptions::new().create(true).append(true).open(path).ok()
}

/// Initialize the process-global crash log under `<zentra_dir>/logs/`. Safe to
/// call once; subsequent calls are ignored.
pub fn init(zentra_dir: &Path, enabled: bool) {
    let logs_dir = zentra_dir.join("logs");
    let _ = LOG.set(CrashLog::new(&logs_dir, enabled));
}

/// Record a failure to the global log (no-op if uninitialized/disabled).
pub fn error(component: &str, msg: impl AsRef<str>) {
    if let Some(log) = LOG.get() {
        log.error(component, msg.as_ref());
    }
}

/// Record a warning to the global log (no-op if uninitialized/disabled).
pub fn warn(component: &str, msg: impl AsRef<str>) {
    if let Some(log) = LOG.get() {
        log.warn(component, msg.as_ref());
    }
}

/// Install a panic hook that records panic location + message to the global
/// log, then chains to the previously installed hook so terminal output is
/// unchanged. Call after [`init`].
pub fn install_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "unknown location".to_string());
        let payload = if let Some(s) = info.payload().downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "<non-string panic payload>".to_string()
        };
        let thread = std::thread::current()
            .name()
            .unwrap_or("unnamed")
            .to_string();
        if let Some(log) = LOG.get() {
            log.write_entry(
                Level::Panic,
                &thread,
                &format!("thread panicked at {location}\n{payload}"),
            );
        }
        prev(info);
    }));
}

/// Scrub secrets from a string before it is written to disk. This is the
/// safety net; the primary guarantee is that we only log failure text. Keeps
/// key names where possible (helpful for debugging), replacing only the value.
fn redact(input: &str) -> String {
    let mut out = input.to_string();
    for (re, replacement) in redaction_rules() {
        out = re.replace_all(&out, *replacement).into_owned();
    }
    out
}

/// Compiled-once redaction rules (project rule: never bare `Regex::new` in hot
/// paths — see CLAUDE.md "Regex patterns use OnceLock").
fn redaction_rules() -> &'static [(Regex, &'static str)] {
    static RULES: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    RULES.get_or_init(|| {
        vec![
            // Anthropic-style keys, then generic long `sk-` keys.
            (Regex::new(r"sk-ant-[A-Za-z0-9_\-]+").unwrap(), "***"),
            (Regex::new(r"sk-[A-Za-z0-9]{20,}").unwrap(), "***"),
            // Bearer / Authorization tokens.
            (Regex::new(r"(?i)bearer\s+[A-Za-z0-9._\-]+").unwrap(), "Bearer ***"),
            // key=value / key: value for sensitive keys (keep the key name).
            (
                Regex::new(
                    r"(?i)(\b(?:api[_-]?key|token|secret|password|passwd|pwd|cookie|session)\b\s*[=:]\s*)(\S+)",
                )
                .unwrap(),
                "${1}***",
            ),
            // Sensitive URL query params (keep the param name).
            (
                Regex::new(r"(?i)([?&](?:token|key|password|session|code|access_token)=)([^&\s]+)")
                    .unwrap(),
                "${1}***",
            ),
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_strips_provider_keys() {
        let out = redact("auth failed for sk-ant-SUPERSECRET123 retrying");
        assert!(!out.contains("SUPERSECRET123"), "leaked: {out}");
        assert!(out.contains("***"));
    }

    #[test]
    fn redact_strips_key_value_pairs_but_keeps_key() {
        let out = redact("login failed password=hunter2 user=bob");
        assert!(!out.contains("hunter2"), "leaked: {out}");
        assert!(out.contains("password=***"), "got: {out}");
        // Non-sensitive context is preserved.
        assert!(out.contains("user=bob"), "over-redacted: {out}");
    }

    #[test]
    fn redact_strips_bearer_and_url_params() {
        let out = redact("GET /cb?code=abc123&x=1 with Authorization: Bearer eyJ.aaa.bbb");
        assert!(!out.contains("abc123"), "leaked code: {out}");
        assert!(!out.contains("eyJ.aaa.bbb"), "leaked token: {out}");
        assert!(out.contains("x=1"), "over-redacted: {out}");
    }

    #[test]
    fn redact_leaves_benign_text_untouched() {
        let msg = "stage 'Network Recon' failed: nmap binary not found on PATH";
        assert_eq!(redact(msg), msg);
    }

    #[test]
    fn entry_has_timestamp_level_component_and_message() {
        let tmp = tempfile::tempdir().unwrap();
        let log = CrashLog::new(tmp.path(), true);
        log.error("pentest", "stage 'Network Recon' failed: nmap not found");
        let content = fs::read_to_string(log.path()).unwrap();
        assert!(content.contains("ERROR [pentest]"), "got: {content}");
        assert!(content.contains("nmap not found"), "got: {content}");
        assert!(
            content.contains('T') && content.contains('Z'),
            "no timestamp: {content}"
        );
    }

    #[test]
    fn disabled_log_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let log = CrashLog::new(tmp.path(), false);
        log.error("scan", "boom");
        assert!(!tmp.path().join(LOG_FILE).exists());
    }

    #[test]
    fn multiline_message_is_indented() {
        let tmp = tempfile::tempdir().unwrap();
        let log = CrashLog::new(tmp.path(), true);
        log.error("pentest", "target=https://app.test\nstage failed: timeout");
        let content = fs::read_to_string(log.path()).unwrap();
        assert!(
            content.contains("[pentest] target=https://app.test"),
            "got: {content}"
        );
        assert!(
            content.contains("\n  stage failed: timeout"),
            "got: {content}"
        );
    }

    #[test]
    fn rotation_creates_backup_and_fresh_log() {
        let tmp = tempfile::tempdir().unwrap();
        // Tiny limit so a couple of entries trip rotation.
        let log = CrashLog::with_max_bytes(tmp.path(), true, 64);
        for i in 0..20 {
            log.error(
                "scan",
                &format!("failure number {i} with some padding text"),
            );
        }
        assert!(tmp.path().join(BACKUP_FILE).exists(), "no backup created");
        assert!(tmp.path().join(LOG_FILE).exists(), "no active log");
    }
}
