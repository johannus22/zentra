use ignore::WalkBuilder;
use regex::Regex;
use std::fs;
use std::path::{Component, Path};

const MAX_FILE_BYTES: u64 = 100_000;
const MAX_GREP_RESULTS: usize = 100;
const MAX_LIST_ENTRIES: usize = 10_000;

/// Reject absolute paths and any `..` component, matching `read_file`.
fn reject_unsafe_path(p: &str) -> Option<String> {
    let path = Path::new(p);
    if path.is_absolute() || path.components().any(|c| c == Component::ParentDir) {
        return Some(
            "Error: path must be relative (no absolute paths or '..' components)".to_string(),
        );
    }
    None
}

pub fn read_file(path: &str) -> String {
    let p = Path::new(path);
    if p.is_absolute() || p.components().any(|c| c == Component::ParentDir) {
        return "Error: path must be relative (no absolute paths or '..' components)".to_string();
    }
    // Defend clone-and-scan: a symlink inside an untrusted repo could point at
    // host files. Canonicalize and require the target to stay within the CWD.
    if let (Ok(canon), Ok(cwd)) = (p.canonicalize(), std::env::current_dir()) {
        if let Ok(cwd_canon) = cwd.canonicalize() {
            if !canon.starts_with(&cwd_canon) {
                return "Error: path escapes the scan root (symlink not allowed)".to_string();
            }
        }
    }
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
    if truncated {
        entries.push(format!(
            "... results truncated at {} entries",
            MAX_LIST_ENTRIES
        ));
    }
    entries.join("\n")
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
}
