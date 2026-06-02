use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::agent::ScannerType;

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

/// Derive a collision-resistant audit folder name as `<owner>-<repo>` when an
/// owner segment is present, else just `<repo>`. The owner is the path segment
/// before the repo; a segment containing '.' is treated as a hostname (not an
/// owner) and skipped. Sanitized to filesystem-safe characters.
pub fn derive_audit_name(url: &str) -> String {
    let repo = derive_repo_name(url);
    let trimmed = url.trim().trim_end_matches('/');
    let segments: Vec<&str> = trimmed
        .rsplit(|c| c == '/' || c == ':')
        .filter(|s| !s.is_empty())
        .collect();
    // segments[0] == repo segment; segments[1] == owner candidate (if any).
    let owner = segments.get(1).copied().unwrap_or("");
    // A dotted segment is a hostname (e.g. github.com), not an owner.
    let owner = if owner.contains('.') { "" } else { owner };
    let owner_clean: String = owner
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string();
    if owner_clean.is_empty() {
        repo
    } else {
        format!("{}-{}", owner_clean, repo)
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

/// Clone an external repo into a throwaway temp dir, run the full scan against
/// it, copy the resulting `.zentra/` artifacts into
/// `cwd/.zentra/audits/<owner>-<repo>/`, then discard the clone.
pub async fn run_clone_and_scan(url: String) -> Result<()> {
    validate_repo_url(&url)?;
    let audit_name = derive_audit_name(&url);

    // Capture where audit output should land before we change directories.
    let audit_root = std::env::current_dir()?
        .join(".zentra")
        .join("audits")
        .join(&audit_name);

    let temp = tempfile::TempDir::new().context("failed to create temp dir for clone")?;
    // Name the clone dir after the repo so the live scan header shows the real
    // repo name (project name / branch are derived from cwd during the scan).
    let clone_dir = temp.path().join(derive_repo_name(&url));

    println!("Cloning {url} …");
    clone_repo(&url, &clone_dir)?;

    // The clone is untrusted: strip any .zentra/ it ships so a malicious
    // config.json can't redirect or shape the scan. The scan recreates one.
    let clone_zentra = clone_dir.join(".zentra");
    if clone_zentra.exists() {
        std::fs::remove_dir_all(&clone_zentra)
            .context("failed to clear pre-existing .zentra/ from clone")?;
    }

    let full_scan = vec![
        ScannerType::ThreatModel,
        ScannerType::Sast,
        ScannerType::SupplyChain,
        ScannerType::ApiScan,
        ScannerType::IacScan,
        ScannerType::Report,
    ];

    {
        // Enter the clone; the guard restores cwd on drop (incl. panic/early return).
        let _guard = CwdGuard::change_to(&clone_dir)?;
        crate::commands::scan::run_with_scanners(full_scan).await?;

        // Copy the clone's .zentra/ output into the original project's audits dir.
        if clone_zentra.exists() {
            if audit_root.exists() {
                println!(
                    "⚠ Overwriting existing audit at .zentra/audits/{}/",
                    audit_name
                );
                std::fs::remove_dir_all(&audit_root).with_context(|| {
                    format!("failed to remove existing audit dir {}", audit_root.display())
                })?;
            }
            copy_dir_recursive(&clone_zentra, &audit_root)?;
        }
    } // guard drops here -> cwd restored

    println!("\n✓ Audit complete. Results in .zentra/audits/{}/", audit_name);
    Ok(())
}
