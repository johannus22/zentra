use ignore::WalkBuilder;
use regex::Regex;
use std::fs;
use std::path::{Component, Path};

const MAX_FILE_BYTES: u64 = 100_000;
const MAX_GREP_RESULTS: usize = 100;
const MAX_LIST_ENTRIES: usize = 10_000;
const SUMMARY_THRESHOLD: usize = 200;
const KEY_MANIFESTS: &[&str] = &[
    "package.json", "Cargo.toml", "go.mod", "pom.xml", "requirements.txt",
    "pyproject.toml", "build.gradle", "composer.json", "Gemfile",
];

/// What happened when a scanner tried to read one file. `TooLarge` and `Failed`
/// are coverage holes: the agent asked for the file and did not get the content.
/// The coverage ledger counts the three cases separately, so a scan that read
/// nothing does not look like a scan that found nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadOutcome {
    Read { bytes: u64 },
    TooLarge { bytes: u64 },
    Failed,
}

/// Reject absolute paths, `..` components, and — for paths that exist — any
/// path that resolves (via symlinks) outside the current working directory,
/// which is the scan root. Keeps the file tools safe even when the security
/// tool gate is disabled.
fn reject_unsafe_path(p: &str) -> Option<String> {
    let path = Path::new(p);
    if path.is_absolute() || path.components().any(|c| c == Component::ParentDir) {
        return Some(
            "Error: path must be relative (no absolute paths or '..' components)".to_string(),
        );
    }
    // If the path exists, require its canonical form to stay within the CWD.
    // A path that exists but cannot be canonicalized/contained is rejected.
    if path.symlink_metadata().is_ok() {
        let contained = match (
            path.canonicalize(),
            std::env::current_dir().and_then(|c| c.canonicalize()),
        ) {
            (Ok(canon), Ok(cwd)) => canon.starts_with(&cwd),
            _ => false,
        };
        if !contained {
            return Some("Error: path escapes the scan root (symlink not allowed)".to_string());
        }
    }
    None
}

/// Read one file and report the outcome beside the string the agent sees.
/// [`read_file`] delegates here, so the agent-visible message and the ledger's
/// view of the same call can never disagree.
pub fn read_file_with_outcome(path: &str) -> (String, ReadOutcome) {
    if let Some(err) = reject_unsafe_path(path) {
        return (err, ReadOutcome::Failed);
    }
    let p = Path::new(path);
    match p.metadata() {
        Err(e) => (format!("Error: {}", e), ReadOutcome::Failed),
        Ok(m) if m.is_dir() => (
            format!("Error: '{}' is a directory, not a file", path),
            ReadOutcome::Failed,
        ),
        Ok(m) if m.len() > MAX_FILE_BYTES => (
            format!(
                "File too large ({} bytes). Use grep_code to search within it.",
                m.len()
            ),
            ReadOutcome::TooLarge { bytes: m.len() },
        ),
        Ok(m) => match fs::read_to_string(p) {
            Ok(content) => (content, ReadOutcome::Read { bytes: m.len() }),
            Err(e) => (
                format!("Error reading '{}': {}", path, e),
                ReadOutcome::Failed,
            ),
        },
    }
}

pub fn read_file(path: &str) -> String {
    read_file_with_outcome(path).0
}

/// True when `path` looks like source or configuration a scanner should read.
/// This is the coverage denominator: "should an agent have opened this file?"
///
/// Deliberately separate from `ci::impact::is_text_like`, which answers a
/// different question — "can I substring-search this file for a changed-file
/// stem?". Widening one list must not silently widen CI impact selection, so the
/// two stay independent even though they overlap.
pub fn is_source_file(path: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(
                extension,
                "rs" | "ts"
                    | "tsx"
                    | "js"
                    | "jsx"
                    | "py"
                    | "go"
                    | "java"
                    | "kt"
                    | "c"
                    | "h"
                    | "cpp"
                    | "hpp"
                    | "toml"
                    | "json"
                    | "yaml"
                    | "yml"
                    | "tf"
            )
        })
}

/// Every source file under `root`, relative and slash-normalized, sorted.
/// Honors .gitignore and never follows symlinks, using the same walker settings
/// as [`list_files`], so the count reflects what the agents can actually reach.
pub fn source_file_paths(root: &Path) -> Vec<String> {
    let mut out: Vec<String> = WalkBuilder::new(root)
        .hidden(false)
        .follow_links(false)
        .build()
        .flatten()
        .filter(|entry| entry.file_type().map(|t| t.is_file()).unwrap_or(false))
        .filter_map(|entry| {
            let relative = entry.path().strip_prefix(root).ok()?;
            let normalized = relative.to_string_lossy().replace('\\', "/");
            // Exclude zentra's own output directory — its JSON/TOML/MD artifacts
            // are not source files the scanner should have opened.
            if normalized.starts_with(".zentra/") {
                return None;
            }
            is_source_file(&normalized).then_some(normalized)
        })
        .collect();
    out.sort();
    out
}

pub fn list_files(dir: &str, pattern: Option<&str>) -> String {
    if let Some(err) = reject_unsafe_path(dir) {
        return err;
    }
    let mut entries: Vec<String> = Vec::new();
    let mut truncated = false;
    for entry in WalkBuilder::new(dir)
        .hidden(false)
        .follow_links(false)
        .build()
        .flatten()
    {
        if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            let path = entry.path().to_string_lossy().to_string();
            if pattern.map(|p| path.contains(p)).unwrap_or(true) {
                entries.push(path);
                if entries.len() >= MAX_LIST_ENTRIES {
                    truncated = true;
                    break;
                }
            }
        }
    }
    if entries.is_empty() {
        return "No files found".to_string();
    }
    entries.sort();
    if entries.len() > SUMMARY_THRESHOLD {
        return summarize_tree(&entries, dir, truncated);
    }
    if truncated {
        entries.push(format!(
            "... results truncated at {} entries",
            MAX_LIST_ENTRIES
        ));
    }
    entries.join("\n")
}

/// Build a compact orientation summary for a large tree: per-top-level-dir
/// file counts, surfaced key manifests wherever they sit, and a drill-in hint.
///
/// `dir` is the scan root that was passed to `list_files`. Paths emitted by
/// WalkBuilder are prefixed with `dir`, so we strip that prefix before taking
/// the first remaining component — this ensures multi-segment dirs like
/// `crates/mylib` attribute `crates/mylib/src/main.rs` to `src`, not `mylib`.
fn summarize_tree(entries: &[String], dir: &str, truncated: bool) -> String {
    use std::collections::BTreeMap;
    let mut dir_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut manifests: Vec<String> = Vec::new();
    let dir_prefix = dir.replace('\\', "/");
    for path in entries {
        // Normalize separators so the summary is stable cross-platform.
        let norm = path.replace('\\', "/");
        // Strip the scan-root prefix so we attribute to the correct top-level
        // directory under `dir`, regardless of how many segments `dir` has.
        let relative = norm
            .strip_prefix(&dir_prefix)
            .unwrap_or(&norm)
            .trim_start_matches('/');
        let top = relative.split('/').next().unwrap_or(".").to_string();
        *dir_counts.entry(top).or_insert(0) += 1;
        if let Some(name) = norm.rsplit('/').next() {
            if KEY_MANIFESTS.contains(&name) {
                manifests.push(norm.clone());
            }
        }
    }
    let mut out = String::from("Large repo — summary shown. Pass a subdirectory to list_files, or use grep_code, to drill in.\n\nTop-level directories:\n");
    for (dir, count) in &dir_counts {
        out.push_str(&format!("  {dir}/ ({count} files)\n"));
    }
    if !manifests.is_empty() {
        manifests.sort();
        out.push_str("\nKey manifests:\n");
        for m in &manifests {
            out.push_str(&format!("  {m}\n"));
        }
    }
    if truncated {
        out.push_str(&format!(
            "\nNote: file list truncated at {} entries — directory counts are a lower bound; drill into subdirectories to see more.",
            MAX_LIST_ENTRIES
        ));
    }
    out
}

pub fn grep_code(pattern: &str, path: Option<&str>) -> String {
    let re = match Regex::new(pattern) {
        Ok(r) => r,
        Err(e) => return format!("Invalid regex pattern: {}", e),
    };

    let search_root = path.unwrap_or(".");
    if let Some(err) = reject_unsafe_path(search_root) {
        return err;
    }
    let mut results: Vec<String> = Vec::new();

    for entry in WalkBuilder::new(search_root)
        .hidden(false)
        .follow_links(false)
        .build()
        .flatten()
    {
        if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            // Skip files larger than read_file's cap to bound memory (matches read_file).
            if entry
                .metadata()
                .map(|m| m.len() > MAX_FILE_BYTES)
                .unwrap_or(false)
            {
                continue;
            }
            if let Ok(content) = fs::read_to_string(entry.path()) {
                for (i, line) in content.lines().enumerate() {
                    if re.is_match(line) {
                        results.push(format!(
                            "{}:{}: {}",
                            entry.path().display(),
                            i + 1,
                            line.trim()
                        ));
                        if results.len() >= MAX_GREP_RESULTS {
                            results.push(format!(
                                "... results truncated, showing first {} matches",
                                MAX_GREP_RESULTS
                            ));
                            return results.join("\n");
                        }
                    }
                }
            }
        }
    }

    if results.is_empty() {
        return format!("No matches for '{}'", pattern);
    }
    results.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Mutex;
    use tempfile::TempDir;

    // Tests that call std::env::set_current_dir must hold this lock to prevent
    // races under parallel `cargo test`. We define it here (rather than relying
    // on the integration-test CWD_LOCK in tests/agent_test.rs) because lib-unit
    // tests run in a separate test binary and cannot share statics across crates.
    static CWD_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn list_files_rejects_parent_traversal() {
        assert!(list_files("..", None).starts_with("Error: path must be relative"));
        assert!(list_files("../etc", None).starts_with("Error: path must be relative"));
    }

    #[test]
    fn list_files_rejects_absolute() {
        let abs = if cfg!(windows) { "C:\\Windows" } else { "/etc" };
        assert!(list_files(abs, None).starts_with("Error: path must be relative"));
    }

    #[test]
    fn grep_code_rejects_parent_traversal() {
        assert!(grep_code("x", Some("../..")).starts_with("Error: path must be relative"));
    }

    #[test]
    fn small_tree_returns_flat_list() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("a.rs"), "x").unwrap();
        fs::write(tmp.path().join("b.rs"), "y").unwrap();

        let _guard = CWD_LOCK.lock().unwrap();
        let _save_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();

        let out = list_files(".", None);

        std::env::set_current_dir(&_save_cwd).unwrap();
        drop(_guard);

        // Check for file entries
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines.iter().any(|l| l.contains("a.rs")), "Expected a.rs in output: {}", out);
        assert!(lines.iter().any(|l| l.contains("b.rs")), "Expected b.rs in output: {}", out);
        assert!(!out.contains("Large repo")); // no summary banner for small trees
    }

    #[test]
    fn large_tree_returns_structured_summary() {
        let tmp = TempDir::new().unwrap();
        // Plant a manifest and > SUMMARY_THRESHOLD files across two dirs.
        fs::write(tmp.path().join("Cargo.toml"), "[package]").unwrap();
        for d in ["services", "libs"] {
            let dir = tmp.path().join(d);
            fs::create_dir_all(&dir).unwrap();
            for i in 0..150 {
                fs::write(dir.join(format!("f{i}.rs")), "x").unwrap();
            }
        }

        let _guard = CWD_LOCK.lock().unwrap();
        let _save_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();

        let out = list_files(".", None);

        std::env::set_current_dir(&_save_cwd).unwrap();
        drop(_guard);

        assert!(out.contains("Large repo"), "expected summary banner");
        assert!(out.contains("services") && out.contains("libs"), "expected dir names");
        assert!(out.contains("Cargo.toml"), "expected surfaced manifest");
        // Must not be a full path dump of every file.
        assert!(!out.contains("f149.rs"));
    }

    /// `summarize_tree` appends the truncation notice when `truncated = true` and
    /// omits it when `truncated = false`. Calls `summarize_tree` directly with
    /// synthetic entries so no temp-dir creation or CWD mutation is needed —
    /// fast and deterministic.
    #[test]
    fn summarize_tree_truncation_notice_present_when_truncated() {
        let entries: Vec<String> = (0..=210)
            .map(|i| format!("src/file{i}.rs"))
            .collect();

        let truncated_out = summarize_tree(&entries, ".", true);
        assert!(
            truncated_out.contains("truncated at"),
            "expected truncation notice in output, got:\n{truncated_out}"
        );
        assert!(
            truncated_out.contains("lower bound"),
            "expected 'lower bound' in truncation notice, got:\n{truncated_out}"
        );

        let not_truncated_out = summarize_tree(&entries, ".", false);
        assert!(
            !not_truncated_out.contains("truncated at"),
            "expected no truncation notice when truncated=false, got:\n{not_truncated_out}"
        );
    }

    /// Regression test for multi-segment `dir` misattribution.
    ///
    /// Previously `summarize_tree` used `norm.split('/').nth(1)` which — for a
    /// path like `crates/mylib/src/main.rs` — would return `mylib` (the second
    /// segment) instead of `src` (the first component *under* the scan root
    /// `crates/mylib`). The fix strips `dir` as a prefix before taking the
    /// first remaining component, so attribution is always relative to the
    /// scan root.
    ///
    /// This test calls `summarize_tree` directly with synthetic entries to
    /// avoid any cwd mutation — no `CWD_LOCK` needed.
    #[test]
    fn summarize_tree_multi_segment_dir_attributes_correctly() {
        // Build > SUMMARY_THRESHOLD synthetic entries under crates/mylib/src/
        // so the summary is triggered.
        let mut entries: Vec<String> = (0..=210)
            .map(|i| format!("crates/mylib/src/file{i}.rs"))
            .collect();
        entries.push("crates/mylib/Cargo.toml".to_string());

        let out = summarize_tree(&entries, "crates/mylib", false);

        // The count should be attributed to "src", not "mylib".
        // Check the top-level directories section specifically (before the blank
        // line that separates it from "Key manifests:").
        let top_section = out
            .split("\nKey manifests:")
            .next()
            .unwrap_or(&out);
        assert!(
            top_section.contains("src/"),
            "expected 'src/' in top-level dirs section, got:\n{out}"
        );
        assert!(
            !top_section.contains("mylib/"),
            "misattributed to 'mylib/' in top-level dirs — multi-segment dir fix regressed:\n{out}"
        );
        // Manifest should still surface (the full path is fine here).
        assert!(
            out.contains("Cargo.toml"),
            "expected Cargo.toml in manifests:\n{out}"
        );
    }

    // --- Read outcomes and the source-file walker (coverage ledger) ---

    #[test]
    fn read_outcome_reports_bytes_for_a_normal_file() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("a.rs"), "fn a() {}").unwrap();

        let _guard = CWD_LOCK.lock().unwrap();
        let _save_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();

        let (body, outcome) = read_file_with_outcome("a.rs");

        std::env::set_current_dir(&_save_cwd).unwrap();
        drop(_guard);

        assert!(body.contains("fn a()"), "got: {body}");
        assert_eq!(outcome, ReadOutcome::Read { bytes: 9 });
    }

    #[test]
    fn read_outcome_reports_too_large() {
        let tmp = TempDir::new().unwrap();
        fs::write(
            tmp.path().join("big.rs"),
            "x".repeat(MAX_FILE_BYTES as usize + 1),
        )
        .unwrap();

        let _guard = CWD_LOCK.lock().unwrap();
        let _save_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();

        let (body, outcome) = read_file_with_outcome("big.rs");

        std::env::set_current_dir(&_save_cwd).unwrap();
        drop(_guard);

        assert!(body.starts_with("File too large"), "got: {body}");
        assert!(
            matches!(outcome, ReadOutcome::TooLarge { bytes } if bytes == MAX_FILE_BYTES + 1),
            "got: {outcome:?}"
        );
    }

    #[test]
    fn read_outcome_reports_failed_for_a_missing_file() {
        let (_, outcome) = read_file_with_outcome("does/not/exist.rs");
        assert_eq!(outcome, ReadOutcome::Failed);
    }

    #[test]
    fn read_outcome_reports_failed_for_a_rejected_path() {
        let (body, outcome) = read_file_with_outcome("../escape.rs");
        assert!(body.starts_with("Error: path must be relative"), "got: {body}");
        assert_eq!(outcome, ReadOutcome::Failed);
    }

    #[test]
    fn read_outcome_reports_failed_for_a_directory() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir(tmp.path().join("sub")).unwrap();

        let _guard = CWD_LOCK.lock().unwrap();
        let _save_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();

        let (_, outcome) = read_file_with_outcome("sub");

        std::env::set_current_dir(&_save_cwd).unwrap();
        drop(_guard);

        assert_eq!(outcome, ReadOutcome::Failed);
    }

    #[test]
    fn read_file_still_returns_only_the_body() {
        // read_file delegates to read_file_with_outcome; the string must not change.
        let (body, _) = read_file_with_outcome("does/not/exist.rs");
        assert_eq!(read_file("does/not/exist.rs"), body);
    }

    #[test]
    fn is_source_file_accepts_code_and_rejects_assets() {
        assert!(is_source_file("src/main.rs"));
        assert!(is_source_file("web/app.tsx"));
        assert!(is_source_file("infra/main.tf"));
        assert!(!is_source_file("assets/logo.png"));
        assert!(!is_source_file("README"));
    }

    #[test]
    fn source_file_paths_finds_source_and_skips_the_rest() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("a.rs"), "fn a() {}").unwrap();
        fs::write(tmp.path().join("logo.png"), [0u8, 1, 2]).unwrap();
        fs::create_dir(tmp.path().join("src")).unwrap();
        fs::write(tmp.path().join("src").join("b.rs"), "fn b() {}").unwrap();

        // No CWD change: source_file_paths takes an explicit root.
        let files = source_file_paths(tmp.path());

        assert!(files.contains(&"a.rs".to_string()), "got: {files:?}");
        assert!(files.contains(&"src/b.rs".to_string()), "got: {files:?}");
        assert!(!files.iter().any(|f| f.ends_with("logo.png")), "got: {files:?}");
    }

    #[test]
    fn source_file_paths_honors_gitignore() {
        let tmp = TempDir::new().unwrap();
        // The `ignore` crate applies .gitignore only inside a git repo, and
        // `list_files` keeps that default. The denominator must match what the
        // agents can reach, so mark the temp dir as a repo rather than relaxing
        // `require_git` on one walker but not the other.
        fs::create_dir(tmp.path().join(".git")).unwrap();
        fs::write(tmp.path().join(".gitignore"), "ignored.rs\n").unwrap();
        fs::write(tmp.path().join("kept.rs"), "fn k() {}").unwrap();
        fs::write(tmp.path().join("ignored.rs"), "fn i() {}").unwrap();

        let files = source_file_paths(tmp.path());

        assert!(files.contains(&"kept.rs".to_string()), "got: {files:?}");
        assert!(
            !files.contains(&"ignored.rs".to_string()),
            "gitignored files are unreachable for the agents too: {files:?}"
        );
    }

    #[test]
    fn source_file_paths_is_sorted_and_slash_normalized() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir(tmp.path().join("z")).unwrap();
        fs::create_dir(tmp.path().join("a")).unwrap();
        fs::write(tmp.path().join("z").join("one.rs"), "x").unwrap();
        fs::write(tmp.path().join("a").join("two.rs"), "x").unwrap();

        let files = source_file_paths(tmp.path());

        assert_eq!(files, vec!["a/two.rs".to_string(), "z/one.rs".to_string()]);
    }
}
