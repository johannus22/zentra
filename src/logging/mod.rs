//! Global crash/error log — human-readable debug telemetry written to a
//! per-session file `~/.zentra/logs/zentra-<timestamp>-<pid>.log`.
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

/// Keep at most this many session log files; older ones are pruned on startup.
const MAX_SESSION_LOGS: usize = 20;

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

/// Append-only plaintext log for a single session. Holds its file handle behind
/// a `Mutex` so it can be shared immutably (e.g. via a global `OnceLock`) while
/// still writing. The file is created lazily on the first entry, so a clean run
/// that logs nothing leaves no file behind.
pub struct CrashLog {
    path: PathBuf,
    enabled: bool,
    /// `None` until the first write opens the file (or stays `None` if disabled
    /// or the file can't be opened).
    writer: Mutex<Option<File>>,
}

impl CrashLog {
    /// Create a log writing to `<logs_dir>/zentra-<timestamp>-<pid>.log`. When
    /// `enabled` is false the log is a silent no-op and no file is created.
    pub fn new(logs_dir: &Path, enabled: bool) -> Self {
        Self {
            path: logs_dir.join(session_filename()),
            enabled,
            writer: Mutex::new(None),
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
        if !self.enabled {
            return;
        }
        let Ok(mut guard) = self.writer.lock() else {
            return;
        };
        // Open the session file lazily on the first entry.
        if guard.is_none() {
            let logs_dir = self.path.parent().unwrap_or_else(|| Path::new("."));
            *guard = open_log_file(logs_dir, &self.path);
            if guard.is_none() {
                return;
            }
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

        let Some(file) = guard.as_mut() else {
            return;
        };
        if file.write_all(buf.as_bytes()).is_err() {
            return;
        }
        let _ = file.flush();
    }
}

fn open_log_file(logs_dir: &Path, path: &Path) -> Option<File> {
    fs::create_dir_all(logs_dir).ok()?;
    OpenOptions::new().create(true).append(true).open(path).ok()
}

/// Filename for this session's log: `zentra-<UTC timestamp>-<pid>.log`. The
/// timestamp uses no colons so it is valid on Windows, and is lexically
/// sortable (chronological); the pid avoids same-second collisions.
fn session_filename() -> String {
    format!(
        "zentra-{}-{}.log",
        Utc::now().format("%Y-%m-%dT%H%M%SZ"),
        std::process::id()
    )
}

/// Delete the oldest session logs, keeping the `keep` most recent. Best-effort:
/// any IO error is ignored (logging must never crash or block). Newest is
/// decided by filename, which sorts chronologically thanks to [`session_filename`].
fn prune_old_logs(logs_dir: &Path, keep: usize) {
    let Ok(entries) = fs::read_dir(logs_dir) else {
        return;
    };
    let mut logs: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("zentra-") && n.ends_with(".log"))
                .unwrap_or(false)
        })
        .collect();
    if logs.len() <= keep {
        return;
    }
    logs.sort(); // ascending by path (chronological); oldest first
    let remove_count = logs.len() - keep;
    for path in logs.into_iter().take(remove_count) {
        let _ = fs::remove_file(path);
    }
}

/// Initialize the process-global crash log under `<zentra_dir>/logs/`. Prunes
/// old session logs first. Safe to call once; subsequent calls are ignored.
pub fn init(zentra_dir: &Path, enabled: bool) {
    let logs_dir = zentra_dir.join("logs");
    if enabled {
        prune_old_logs(&logs_dir, MAX_SESSION_LOGS);
    }
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
            // Anthropic-style keys, then generic long `sk-` keys. The generic rule
            // allows `_`/`-` inside the body so modern hyphenated OpenAI keys
            // (`sk-proj-…`, `sk-svcacct-…`, `sk-admin-…`) are redacted, not just
            // the legacy flat `sk-<40 alnum>` form.
            (Regex::new(r"sk-ant-[A-Za-z0-9_\-]+").unwrap(), "***"),
            (Regex::new(r"sk-[A-Za-z0-9][A-Za-z0-9_\-]{19,}").unwrap(), "***"),
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

    // L1 (chaos re-test): the generic sk- rule missed modern hyphenated OpenAI
    // key formats (sk-proj-/sk-svcacct-/sk-admin-) in free-form crash-log text.
    #[test]
    fn redact_strips_hyphenated_openai_keys() {
        for key in [
            "sk-proj-abcDEF1234567890ghijKLMN",
            "sk-svcacct-ABCdef1234567890XYZ0",
            "sk-admin-0123456789abcdefABCDEF",
        ] {
            let out = redact(&format!("panic: request failed with {key} at line 3"));
            assert!(!out.contains(key), "leaked key {key}: {out}");
            assert!(out.contains("***"), "no redaction marker: {out}");
        }
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
        assert!(!log.path().exists());
    }

    #[test]
    fn clean_run_creates_no_file() {
        // Enabled but nothing logged → file is opened lazily, so none exists.
        let tmp = tempfile::tempdir().unwrap();
        let log = CrashLog::new(tmp.path(), true);
        assert!(!log.path().exists());
    }

    #[test]
    fn session_filename_is_windows_safe_and_prefixed() {
        let name = session_filename();
        assert!(name.starts_with("zentra-"), "got: {name}");
        assert!(name.ends_with(".log"), "got: {name}");
        assert!(!name.contains(':'), "colons are invalid on Windows: {name}");
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
    fn prune_keeps_newest_n() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        // Names sort chronologically; create 5 "sessions".
        let names = [
            "zentra-2026-06-11T080000Z-1.log",
            "zentra-2026-06-11T081000Z-2.log",
            "zentra-2026-06-11T082000Z-3.log",
            "zentra-2026-06-11T083000Z-4.log",
            "zentra-2026-06-11T084000Z-5.log",
        ];
        for n in &names {
            fs::write(dir.join(n), b"x").unwrap();
        }
        // An unrelated file must be left untouched.
        fs::write(dir.join("notes.txt"), b"keep me").unwrap();

        prune_old_logs(dir, 2);

        assert!(!dir.join(names[0]).exists(), "oldest should be pruned");
        assert!(!dir.join(names[1]).exists());
        assert!(!dir.join(names[2]).exists());
        assert!(dir.join(names[3]).exists(), "newest 2 should remain");
        assert!(dir.join(names[4]).exists());
        assert!(dir.join("notes.txt").exists(), "non-log untouched");
    }

    #[test]
    fn prune_noop_when_under_limit() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("zentra-2026-06-11T080000Z-1.log"), b"x").unwrap();
        prune_old_logs(tmp.path(), 20);
        assert!(tmp.path().join("zentra-2026-06-11T080000Z-1.log").exists());
    }
}
