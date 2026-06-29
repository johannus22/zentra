use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use anyhow::Result;
use sha2::{Digest, Sha256};

use crate::ci::{changed_files_from_git, select_impact_files};

#[derive(Debug, Clone, Default)]
pub struct Baseline {
    pub commit: Option<String>,
    pub file_hashes: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Default)]
pub struct ChangeSet {
    pub changed: Vec<String>,
    pub impact: Vec<String>,
}

fn normalize(path: &str) -> String {
    path.replace('\\', "/")
}

/// `git status --porcelain` → repo-relative paths of modified/added/untracked
/// files (excludes deletions; deleted files can't be scanned).
pub fn working_tree_changes(root: &Path) -> Result<Vec<String>> {
    let output = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=all"])
        .current_dir(root)
        .output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let mut files = Vec::new();
    for line in text.lines() {
        if line.len() < 4 {
            continue;
        }
        let status = &line[..2];
        if status.contains('D') {
            continue;
        }
        // Strip the 2 status chars + 1 space; handle "old -> new" renames.
        let path = line[3..].trim();
        let path = path.rsplit(" -> ").next().unwrap_or(path);
        let path = path.trim_matches('"');
        files.push(normalize(path));
    }
    files.sort();
    files.dedup();
    Ok(files)
}

pub fn changed_since_commit(root: &Path, commit: &str) -> Result<Vec<String>> {
    changed_files_from_git(root, commit, "HEAD")
}

/// sha256 every file under `root` that the impact scanner would consider.
/// Reuses `select_impact_files` with an empty changed-set trick is NOT valid
/// (it keys off changed files), so walk the tree directly here.
pub fn hash_tree(root: &Path) -> Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    hash_dir(root, root, &mut map)?;
    Ok(map)
}

fn hash_dir(root: &Path, dir: &Path, out: &mut BTreeMap<String, String>) -> Result<()> {
    for entry in std::fs::read_dir(dir)?.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == ".git" || name == ".zentra" || name == "target" || name == "node_modules" {
            continue;
        }
        if path.is_dir() {
            hash_dir(root, &path, out)?;
        } else if let Ok(bytes) = std::fs::read(&path) {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let digest = format!("{:x}", hasher.finalize());
            if let Ok(rel) = path.strip_prefix(root) {
                out.insert(normalize(&rel.to_string_lossy()), digest);
            }
        }
    }
    Ok(())
}

pub fn compute_change_set(
    root: &Path,
    baseline: &Baseline,
    impact_cap: usize,
) -> Result<ChangeSet> {
    let mut changed: Vec<String> = match &baseline.commit {
        Some(commit) => {
            let mut c = changed_since_commit(root, commit)?;
            c.extend(working_tree_changes(root)?);
            c
        }
        None => {
            let prior = baseline.file_hashes.clone().unwrap_or_default();
            let current = hash_tree(root)?;
            current
                .iter()
                .filter(|(path, hash)| prior.get(*path) != Some(*hash))
                .map(|(path, _)| path.clone())
                .collect()
        }
    };
    changed.iter_mut().for_each(|p| *p = normalize(p));
    changed.sort();
    changed.dedup();

    let impact = select_impact_files(root, &changed, impact_cap)?;
    Ok(ChangeSet { changed, impact })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;

    fn git(dir: &std::path::Path, args: &[&str]) {
        let ok = Command::new("git")
            .args(args)
            .current_dir(dir)
            .status()
            .unwrap();
        assert!(ok.success(), "git {:?} failed", args);
    }

    fn init_repo(dir: &std::path::Path) {
        git(dir, &["init", "-q"]);
        git(dir, &["config", "user.email", "t@t.dev"]);
        git(dir, &["config", "user.name", "t"]);
    }

    #[test]
    fn working_tree_changes_lists_modified_and_untracked() {
        let dir = TempDir::new().unwrap();
        init_repo(dir.path());
        std::fs::write(dir.path().join("a.rs"), "fn a() {}").unwrap();
        git(dir.path(), &["add", "."]);
        git(dir.path(), &["commit", "-qm", "init"]);
        // modify tracked + add untracked
        std::fs::write(dir.path().join("a.rs"), "fn a() { /* x */ }").unwrap();
        std::fs::write(dir.path().join("b.rs"), "fn b() {}").unwrap();
        let mut changed = working_tree_changes(dir.path()).unwrap();
        changed.sort();
        assert_eq!(changed, vec!["a.rs".to_string(), "b.rs".to_string()]);
    }

    #[test]
    fn compute_change_set_git_includes_committed_and_dirty() {
        let dir = TempDir::new().unwrap();
        init_repo(dir.path());
        std::fs::write(dir.path().join("a.rs"), "1").unwrap();
        git(dir.path(), &["add", "."]);
        git(dir.path(), &["commit", "-qm", "c1"]);
        let base = String::from_utf8(
            Command::new("git")
                .args(["rev-parse", "HEAD"])
                .current_dir(dir.path())
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();
        // new commit touching c.rs
        std::fs::write(dir.path().join("c.rs"), "3").unwrap();
        git(dir.path(), &["add", "."]);
        git(dir.path(), &["commit", "-qm", "c2"]);
        // dirty edit to d.rs (uncommitted)
        std::fs::write(dir.path().join("d.rs"), "4").unwrap();
        let baseline = Baseline {
            commit: Some(base),
            file_hashes: None,
        };
        let cs = compute_change_set(dir.path(), &baseline, 200).unwrap();
        assert!(
            cs.changed.contains(&"c.rs".to_string()),
            "committed change present"
        );
        assert!(
            cs.changed.contains(&"d.rs".to_string()),
            "dirty change present"
        );
    }

    #[test]
    fn compute_change_set_hash_path_detects_modified() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("a.rs"), "old").unwrap();
        let before = hash_tree(dir.path()).unwrap();
        std::fs::write(dir.path().join("a.rs"), "new").unwrap();
        let baseline = Baseline {
            commit: None,
            file_hashes: Some(before),
        };
        let cs = compute_change_set(dir.path(), &baseline, 200).unwrap();
        assert!(cs.changed.contains(&"a.rs".to_string()));
    }
}
