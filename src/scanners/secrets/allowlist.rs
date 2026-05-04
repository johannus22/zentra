use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Default, Deserialize)]
pub struct AllowlistFile {
    #[serde(default)]
    pub allowlist: AllowlistInner,
}

#[derive(Debug, Default, Deserialize)]
pub struct AllowlistInner {
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub fingerprints: Vec<String>,
    #[serde(default)]
    pub entries: Vec<AllowlistEntry>,
}

#[derive(Debug, Deserialize)]
pub struct AllowlistEntry {
    pub detector: Option<String>,
    pub path: Option<String>,
}

pub struct Allowlist {
    inner: AllowlistInner,
}

impl Allowlist {
    pub fn load(root: &Path) -> Self {
        let path = root.join(".zentra").join("secrets-allowlist.toml");
        let inner = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| toml::from_str::<AllowlistFile>(&s).ok())
            .map(|f| f.allowlist)
            .unwrap_or_default();
        Self { inner }
    }

    pub fn is_path_allowed(&self, file: &str) -> bool {
        self.inner.paths.iter().any(|pat| glob_matches(pat, file))
    }

    pub fn is_fingerprint_allowed(&self, file: &str, line: u32, redacted: &str) -> bool {
        let fp = compute_fingerprint(file, line, redacted);
        self.inner.fingerprints.iter().any(|f| *f == fp)
    }

    pub fn is_entry_allowed(&self, detector: &str, file: &str) -> bool {
        self.inner.entries.iter().any(|entry| {
            let d_match = entry
                .detector
                .as_deref()
                .map(|d| d == detector)
                .unwrap_or(true);
            let p_match = entry
                .path
                .as_deref()
                .map(|p| glob_matches(p, file))
                .unwrap_or(true);
            d_match && p_match
        })
    }
}

pub fn compute_fingerprint(file: &str, line: u32, redacted: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{}:{}:{}", file, line, redacted).as_bytes());
    format!("{:x}", hasher.finalize())
}

fn glob_matches(pattern: &str, path: &str) -> bool {
    let re_str = glob_to_regex(pattern);
    regex::Regex::new(&re_str)
        .map(|re| re.is_match(path))
        .unwrap_or(false)
}

fn glob_to_regex(pattern: &str) -> String {
    let mut re = String::from("(?i)^");
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '*' if chars.peek() == Some(&'*') => {
                chars.next();
                re.push_str(".*");
            }
            '*' => re.push_str("[^/\\\\]*"),
            '?' => re.push('.'),
            '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '\\' | '^' | '$' | '|' => {
                re.push('\\');
                re.push(c);
            }
            _ => re.push(c),
        }
    }
    re.push('$');
    re
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write_allowlist(dir: &TempDir, content: &str) {
        let zentra = dir.path().join(".zentra");
        fs::create_dir_all(&zentra).unwrap();
        fs::write(zentra.join("secrets-allowlist.toml"), content).unwrap();
    }

    #[test]
    fn empty_allowlist_allows_nothing() {
        let dir = TempDir::new().unwrap();
        let al = Allowlist::load(dir.path());
        assert!(!al.is_path_allowed("src/config.rs"));
        assert!(!al.is_fingerprint_allowed("src/config.rs", 42, "AKIA...MPLE"));
        assert!(!al.is_entry_allowed("aws_access_key", "src/config.rs"));
    }

    #[test]
    fn missing_allowlist_file_returns_empty() {
        let dir = TempDir::new().unwrap();
        let al = Allowlist::load(dir.path()); // no .zentra/ dir
        assert!(!al.is_path_allowed("anything"));
    }

    #[test]
    fn path_glob_matches_tests_dir() {
        let dir = TempDir::new().unwrap();
        write_allowlist(
            &dir,
            r#"
[allowlist]
paths = ["tests/**"]
"#,
        );
        let al = Allowlist::load(dir.path());
        assert!(al.is_path_allowed("tests/fixtures/sample.env"));
        assert!(al.is_path_allowed("tests/integration/config.rs"));
        assert!(!al.is_path_allowed("src/config.rs"));
    }

    #[test]
    fn fingerprint_round_trip() {
        let dir = TempDir::new().unwrap();
        let fp = compute_fingerprint("src/config.rs", 42, "AKIA...MPLE");
        write_allowlist(
            &dir,
            &format!(
                r#"
[allowlist]
fingerprints = ["{}"]
"#,
                fp
            ),
        );
        let al = Allowlist::load(dir.path());
        assert!(al.is_fingerprint_allowed("src/config.rs", 42, "AKIA...MPLE"));
        assert!(!al.is_fingerprint_allowed("src/config.rs", 43, "AKIA...MPLE"));
        assert!(!al.is_fingerprint_allowed("src/other.rs", 42, "AKIA...MPLE"));
    }

    #[test]
    fn entry_allows_specific_detector_and_path() {
        let dir = TempDir::new().unwrap();
        write_allowlist(
            &dir,
            r#"
[[allowlist.entries]]
detector = "high_entropy_base64"
path = "src/test_vectors.rs"
"#,
        );
        let al = Allowlist::load(dir.path());
        assert!(al.is_entry_allowed("high_entropy_base64", "src/test_vectors.rs"));
        assert!(!al.is_entry_allowed("aws_access_key", "src/test_vectors.rs"));
        assert!(!al.is_entry_allowed("high_entropy_base64", "src/config.rs"));
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let a = compute_fingerprint("src/config.rs", 42, "AKIA...MPLE");
        let b = compute_fingerprint("src/config.rs", 42, "AKIA...MPLE");
        assert_eq!(a, b);
    }
}
