use std::{collections::HashMap, fs, path::Path};

use anyhow::Result;

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
            fs::read_to_string(root.join(file))
                .ok()
                .map(|content| (normalize_path(file), content))
        })
        .collect::<HashMap<_, _>>();

    for file in &all_files {
        if selected.len() >= max_files {
            break;
        }

        if selected.contains(file) || !is_text_like(file) {
            continue;
        }

        let content = fs::read_to_string(root.join(file))?;
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

        if path.is_dir() {
            collect_files(root, &path, files)?;
        } else if path.is_file() {
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
