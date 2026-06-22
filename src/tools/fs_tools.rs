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

pub fn read_file(path: &str) -> String {
    if let Some(err) = reject_unsafe_path(path) {
        return err;
    }
    let p = Path::new(path);
    match p.metadata() {
        Err(e) => format!("Error: {}", e),
        Ok(m) if m.is_dir() => format!("Error: '{}' is a directory, not a file", path),
        Ok(m) if m.len() > MAX_FILE_BYTES => format!(
            "File too large ({} bytes). Use grep_code to search within it.",
            m.len()
        ),
        Ok(_) => match fs::read_to_string(p) {
            Ok(content) => content,
            Err(e) => format!("Error reading '{}': {}", path, e),
        },
    }
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
        return summarize_tree(&entries);
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
fn summarize_tree(entries: &[String]) -> String {
    use std::collections::BTreeMap;
    let mut dir_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut manifests: Vec<String> = Vec::new();
    for path in entries {
        // Normalize separators so the summary is stable cross-platform.
        let norm = path.replace('\\', "/");
        let top = norm.split('/').nth(1).unwrap_or(".").to_string();
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
    use tempfile::TempDir;

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

        let _save_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();

        let out = list_files(".", None);

        std::env::set_current_dir(&_save_cwd).unwrap();

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

        let _save_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();

        let out = list_files(".", None);

        std::env::set_current_dir(&_save_cwd).unwrap();

        assert!(out.contains("Large repo"), "expected summary banner");
        assert!(out.contains("services") && out.contains("libs"), "expected dir names");
        assert!(out.contains("Cargo.toml"), "expected surfaced manifest");
        // Must not be a full path dump of every file.
        assert!(!out.contains("f149.rs"));
    }
}
