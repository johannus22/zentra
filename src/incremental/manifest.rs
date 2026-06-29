use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

pub const MANIFEST_FILE: &str = "scan-manifest.json";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanManifest {
    pub last_scan_commit: Option<String>,
    pub was_dirty: bool,
    pub scanned_at: String,
    pub scanner_set: Vec<String>,
    pub engine_version: String,
    pub model_id: String,
    pub mode: String,
    pub file_hashes: Option<BTreeMap<String, String>>,
}

impl ScanManifest {
    pub fn load(zentra_dir: &Path) -> Option<ScanManifest> {
        let raw = std::fs::read_to_string(zentra_dir.join(MANIFEST_FILE)).ok()?;
        serde_json::from_str(&raw).ok()
    }

    pub fn save(&self, zentra_dir: &Path) -> Result<()> {
        let body = serde_json::to_string_pretty(self)?;
        std::fs::write(zentra_dir.join(MANIFEST_FILE), body)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn save_then_load_roundtrips() {
        let dir = TempDir::new().unwrap();
        let manifest = ScanManifest {
            last_scan_commit: Some("abc123".into()),
            was_dirty: true,
            scanned_at: "2026-06-29T10:00:00Z".into(),
            scanner_set: vec!["sast".into(), "report".into()],
            engine_version: "0.10.0".into(),
            model_id: "claude · default".into(),
            mode: "incremental".into(),
            file_hashes: None,
        };
        manifest.save(dir.path()).unwrap();
        let loaded = ScanManifest::load(dir.path()).expect("should load");
        assert_eq!(loaded.last_scan_commit.as_deref(), Some("abc123"));
        assert!(loaded.was_dirty);
        assert_eq!(loaded.scanner_set, vec!["sast", "report"]);
    }

    #[test]
    fn load_missing_returns_none() {
        let dir = TempDir::new().unwrap();
        assert!(ScanManifest::load(dir.path()).is_none());
    }

    #[test]
    fn load_corrupt_returns_none() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(MANIFEST_FILE), b"{ not json").unwrap();
        assert!(ScanManifest::load(dir.path()).is_none());
    }
}
