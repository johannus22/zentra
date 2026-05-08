use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::scanners::secrets::SecretsMatch;

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct FileCacheEntry {
    mtime_secs: u64,
    mtime_nanos: u32,
    findings: Vec<SecretsMatch>,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ScanCache {
    #[serde(default)]
    pub patterns_hash: String,
    #[serde(default)]
    fs_entries: std::collections::HashMap<String, FileCacheEntry>,
    #[serde(default)]
    git_head: String,
    #[serde(default)]
    git_findings: Vec<SecretsMatch>,
}

impl ScanCache {
    pub fn load(root: &Path) -> Self {
        let path = root.join(".zentra").join("secrets-cache.json");
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn patterns_hash_matches(&self, hash: &str) -> bool {
        !self.patterns_hash.is_empty() && self.patterns_hash == hash
    }

    pub fn invalidate_if_hash_mismatch(&mut self, hash: &str) {
        if !self.patterns_hash_matches(hash) {
            self.fs_entries.clear();
            self.git_head.clear();
            self.git_findings.clear();
            self.patterns_hash = hash.to_string();
        }
    }

    pub fn get_file(&self, rel: &str, mtime: SystemTime) -> Option<Vec<SecretsMatch>> {
        let entry = self.fs_entries.get(rel)?;
        let (secs, nanos) = mtime_parts(mtime);
        if entry.mtime_secs == secs && entry.mtime_nanos == nanos {
            Some(entry.findings.clone())
        } else {
            None
        }
    }

    pub fn set_file(&mut self, rel: String, mtime: SystemTime, findings: Vec<SecretsMatch>) {
        let (mtime_secs, mtime_nanos) = mtime_parts(mtime);
        self.fs_entries.insert(rel, FileCacheEntry { mtime_secs, mtime_nanos, findings });
    }

    pub fn git_head_matches(&self, head: &str) -> bool {
        !self.git_head.is_empty() && self.git_head == head
    }

    pub fn get_git_findings(&self) -> &[SecretsMatch] {
        &self.git_findings
    }

    pub fn set_git(&mut self, head: String, findings: Vec<SecretsMatch>) {
        self.git_head = head;
        self.git_findings = findings;
    }

    pub fn save(&self, root: &Path) {
        let dir = root.join(".zentra");
        if std::fs::create_dir_all(&dir).is_err() {
            return;
        }
        let tmp = dir.join("secrets-cache.tmp");
        let dest = dir.join("secrets-cache.json");
        if let Ok(json) = serde_json::to_string(self) {
            if std::fs::write(&tmp, &json).is_ok() {
                let _ = std::fs::rename(&tmp, &dest);
            }
        }
    }
}

fn mtime_parts(t: SystemTime) -> (u64, u32) {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    (d.as_secs(), d.subsec_nanos())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fake_mtime(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn one_finding() -> Vec<SecretsMatch> {
        vec![SecretsMatch {
            file: "src/config.rs".to_string(),
            line: 1,
            commit: None,
            detector: "aws_access_key".to_string(),
            entropy: Some(4.8),
            redacted: "AKIA...MPLE".to_string(),
            suppressed: false,
            suppression_reason: None,
        }]
    }

    #[test]
    fn load_missing_file_returns_empty() {
        let dir = TempDir::new().unwrap();
        let cache = ScanCache::load(dir.path());
        assert!(cache.fs_entries.is_empty());
        assert!(cache.git_head.is_empty());
    }

    #[test]
    fn get_file_miss_on_empty_cache() {
        let dir = TempDir::new().unwrap();
        let cache = ScanCache::load(dir.path());
        assert!(cache.get_file("src/foo.rs", fake_mtime(100)).is_none());
    }

    #[test]
    fn set_then_get_file_hit_same_mtime() {
        let dir = TempDir::new().unwrap();
        let mut cache = ScanCache::load(dir.path());
        cache.set_file("src/foo.rs".to_string(), fake_mtime(100), one_finding());
        let result = cache.get_file("src/foo.rs", fake_mtime(100));
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[test]
    fn get_file_miss_on_mtime_change() {
        let dir = TempDir::new().unwrap();
        let mut cache = ScanCache::load(dir.path());
        cache.set_file("src/foo.rs".to_string(), fake_mtime(100), one_finding());
        assert!(cache.get_file("src/foo.rs", fake_mtime(200)).is_none());
    }

    #[test]
    fn git_head_hit_and_miss() {
        let dir = TempDir::new().unwrap();
        let mut cache = ScanCache::load(dir.path());
        cache.set_git("abc123".to_string(), one_finding());
        assert!(cache.git_head_matches("abc123"));
        assert!(!cache.git_head_matches("def456"));
        assert_eq!(cache.get_git_findings().len(), 1);
    }

    #[test]
    fn patterns_hash_mismatch_clears_cache() {
        let dir = TempDir::new().unwrap();
        let mut cache = ScanCache::load(dir.path());
        cache.set_file("src/foo.rs".to_string(), fake_mtime(100), one_finding());
        cache.set_git("abc123".to_string(), one_finding());
        cache.patterns_hash = "oldhash".to_string();
        cache.invalidate_if_hash_mismatch("newhash");
        assert!(cache.fs_entries.is_empty());
        assert!(cache.git_head.is_empty());
        assert!(cache.git_findings.is_empty());
    }

    #[test]
    fn patterns_hash_match_preserves_cache() {
        let dir = TempDir::new().unwrap();
        let mut cache = ScanCache::load(dir.path());
        cache.set_file("src/foo.rs".to_string(), fake_mtime(100), one_finding());
        cache.patterns_hash = "samehash".to_string();
        cache.invalidate_if_hash_mismatch("samehash");
        assert!(!cache.fs_entries.is_empty());
    }

    #[test]
    fn save_and_reload_round_trip() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".zentra")).unwrap();
        let mut cache = ScanCache::load(dir.path());
        cache.patterns_hash = "testhash".to_string();
        cache.set_file("src/foo.rs".to_string(), fake_mtime(100), one_finding());
        cache.set_git("abc123".to_string(), one_finding());
        cache.save(dir.path());

        let reloaded = ScanCache::load(dir.path());
        assert_eq!(reloaded.patterns_hash, "testhash");
        assert!(reloaded.get_file("src/foo.rs", fake_mtime(100)).is_some());
        assert!(reloaded.git_head_matches("abc123"));
        assert_eq!(reloaded.get_git_findings().len(), 1);
    }

    #[test]
    fn save_corrupt_file_load_returns_empty() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".zentra")).unwrap();
        std::fs::write(dir.path().join(".zentra").join("secrets-cache.json"), b"not json").unwrap();
        let cache = ScanCache::load(dir.path());
        assert!(cache.fs_entries.is_empty());
    }
}
