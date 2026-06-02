use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Accept only URL forms `git clone` understands as remotes. The URL is always
/// passed to `git` as an argument (never through a shell), so this is a
/// usability guard, not an injection guard. `file://` is rejected to keep the
/// feature aimed at external remotes.
pub fn validate_repo_url(url: &str) -> Result<()> {
    let u = url.trim();
    if u.is_empty() {
        bail!("Repo URL cannot be empty");
    }
    let ok = u.starts_with("https://")
        || u.starts_with("http://")
        || u.starts_with("git://")
        || u.starts_with("ssh://")
        || (u.starts_with("git@") && u.contains(':'));
    if !ok {
        bail!("Repo URL must start with https://, http://, git://, ssh://, or git@host:path");
    }
    Ok(())
}

/// Derive a filesystem-safe directory name from a git URL: take the last
/// non-empty path segment, strip a trailing `.git`, and sanitize. Falls back to
/// `"repo"` when nothing usable remains.
pub fn derive_repo_name(url: &str) -> String {
    let trimmed = url.trim().trim_end_matches('/');
    // Handle scp-like `git@host:owner/repo` by splitting on both ':' and '/'.
    let last = trimmed
        .rsplit(|c| c == '/' || c == ':')
        .find(|s| !s.is_empty())
        .unwrap_or("");
    let stripped = last.strip_suffix(".git").unwrap_or(last);
    let sanitized: String = stripped
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let cleaned = sanitized.trim_matches('-').to_string();
    if cleaned.is_empty() {
        "repo".to_string()
    } else {
        cleaned
    }
}

/// Shallow-clone `url` into `dest` using the user's local `git` (inherits their
/// credential helper / SSH keys). `dest` must not already exist.
pub fn clone_repo(url: &str, dest: &Path) -> Result<()> {
    let output = Command::new("git")
        .arg("clone")
        .arg("--depth")
        .arg("1")
        .arg(url)
        .arg(dest)
        .output()
        .context("failed to run `git` — is it installed and on PATH?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git clone failed: {}", stderr.trim());
    }
    Ok(())
}

/// Recursively copy the contents of `src` into `dst`, creating `dst` (and
/// parents) as needed. Overwrites existing files.
pub fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)
        .with_context(|| format!("failed to create {}", dst.display()))?;
    for entry in std::fs::read_dir(src)
        .with_context(|| format!("failed to read {}", src.display()))?
    {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)
                .with_context(|| format!("failed to copy {}", from.display()))?;
        }
    }
    Ok(())
}

/// Restores the process current directory to its original value when dropped,
/// so a panic or early return inside a scan can't strand the process in the
/// temp clone.
pub struct CwdGuard {
    original: PathBuf,
}

impl CwdGuard {
    pub fn change_to(target: &Path) -> Result<Self> {
        let original = std::env::current_dir().context("failed to read current dir")?;
        std::env::set_current_dir(target)
            .with_context(|| format!("failed to enter {}", target.display()))?;
        Ok(Self { original })
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.original);
    }
}
