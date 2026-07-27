use std::{collections::HashMap, fs, path::Path};

use anyhow::Result;

/// Cap on file size read into memory for impact heuristics. A multi-GB file
/// would otherwise be buffered whole (OOM DoS). Files over the cap are skipped.
const MAX_READ_BYTES: u64 = 5 * 1024 * 1024;

/// Read a file as UTF-8 for impact analysis, returning `None` — never erroring
/// the whole scan — when it is missing, too large (F7), or not valid UTF-8 (F8).
fn read_text_capped(path: &Path) -> Option<String> {
    match fs::metadata(path) {
        Ok(meta) if meta.len() > MAX_READ_BYTES => return None,
        Ok(_) => {}
        Err(_) => return None,
    }
    fs::read_to_string(path).ok()
}

pub fn select_impact_files(
    root: &Path,
    changed_files: &[String],
    max_files: usize,
) -> Result<Vec<String>> {
    let mut selected = Vec::new();
    for file in changed_files {
        push_unique(&mut selected, normalize_path(file), max_files);
    }

    let all_files = list_files(root)?;
    if changed_files.iter().any(|file| is_manifest_or_config(file)) {
        for file in &all_files {
            if is_manifest_or_config(file) {
                push_unique(&mut selected, file.clone(), max_files);
            }
        }
    }

    let changed_tokens = changed_files
        .iter()
        .filter_map(|file| Path::new(file).file_stem())
        .filter_map(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    let changed_contents = changed_files
        .iter()
        .filter_map(|file| {
            read_text_capped(&root.join(file)).map(|content| (normalize_path(file), content))
        })
        .collect::<HashMap<_, _>>();

    for file in &all_files {
        if selected.len() >= max_files {
            break;
        }

        if selected.contains(file) || !is_text_like(file) {
            continue;
        }

        let Some(content) = read_text_capped(&root.join(file)) else {
            continue;
        };
        if changed_tokens.iter().any(|token| content.contains(token)) {
            push_unique(&mut selected, file.clone(), max_files);
            continue;
        }

        if changed_contents.values().any(|changed_content| {
            Path::new(file)
                .file_stem()
                .and_then(|stem| stem.to_str())
                .is_some_and(|stem| changed_content.contains(stem))
        }) {
            push_unique(&mut selected, file.clone(), max_files);
        }
    }

    Ok(selected)
}

fn push_unique(files: &mut Vec<String>, file: String, max_files: usize) {
    if files.len() < max_files && !files.contains(&file) {
        files.push(file);
    }
}

fn list_files(root: &Path) -> Result<Vec<String>> {
    let mut files = Vec::new();
    collect_files(root, root, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_files(root: &Path, dir: &Path, files: &mut Vec<String>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        if name.to_string_lossy().starts_with('.') {
            continue;
        }

        // Use the entry's own file type (does NOT follow symlinks) and skip
        // symlinks entirely — a directory symlink pointing at an ancestor would
        // otherwise recurse forever (F6), and a file symlink could escape root.
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_files(root, &path, files)?;
        } else if file_type.is_file() {
            if let Ok(relative) = path.strip_prefix(root) {
                files.push(normalize_path(&relative.to_string_lossy()));
            }
        }
    }
    Ok(())
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn is_manifest_or_config(path: &str) -> bool {
    let file_name = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path);

    matches!(
        file_name,
        "Cargo.toml"
            | "Cargo.lock"
            | "package.json"
            | "package-lock.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "requirements.txt"
            | "pyproject.toml"
            | "Dockerfile"
            | ".gitlab-ci.yml"
            | "zentra.yml"
            | "zentra.yaml"
    ) || file_name.ends_with(".config.js")
        || file_name.ends_with(".config.ts")
        || file_name.ends_with(".yml")
        || file_name.ends_with(".yaml")
}

fn is_text_like(path: &str) -> bool {
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
            )
        })
}

#[cfg(test)]
mod chaos_tests {
    use super::*;
    use tempfile::TempDir;

    // F8: a single non-UTF-8 file with a text extension must not abort the whole
    // impact selection (was `read_to_string(...)?`). One bad file could otherwise
    // suppress incremental scanning of a repo's real changes.
    #[test]
    fn non_utf8_file_does_not_abort_impact_selection() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("changed.rs"), "fn foo() {}").unwrap();
        std::fs::write(dir.path().join("bad.rs"), [0xff, 0xfe, 0x00, 0x9f, 0x80]).unwrap();
        let changed = vec!["changed.rs".to_string()];
        let result = select_impact_files(dir.path(), &changed, 100);
        assert!(
            result.is_ok(),
            "a non-UTF-8 file must not abort impact selection: {:?}",
            result.err()
        );
    }

    // F6: a directory symlink pointing at an ancestor must not cause unbounded
    // recursion (stack overflow) in the file walker.
    #[test]
    fn symlink_cycle_does_not_recurse_infinitely() {
        let dir = TempDir::new().unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("real.rs"), "fn x() {}").unwrap();

        #[cfg(unix)]
        let made = std::os::unix::fs::symlink(dir.path(), sub.join("loop")).is_ok();
        #[cfg(windows)]
        let made = std::os::windows::fs::symlink_dir(dir.path(), sub.join("loop")).is_ok();
        #[cfg(not(any(unix, windows)))]
        let made = false;

        if !made {
            return; // symlinks unsupported / unprivileged — skip (still validated on CI)
        }

        let files = list_files(dir.path()).unwrap();
        assert!(files.iter().any(|f| f.ends_with("real.rs")));
    }
}
