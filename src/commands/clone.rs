use anyhow::{bail, Result};

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
