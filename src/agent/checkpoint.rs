use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

/// Records which scanners completed successfully in a prior run.
/// The orchestrator uses this to skip completed scanners on resume.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Scanner names that completed successfully (for example "sast", "threat_model").
    #[serde(default)]
    pub completed: BTreeSet<String>,
    /// ISO 8601 timestamp of when the checkpoint was last updated.
    #[serde(default)]
    pub updated_at: String,
    /// The scanner set from the run that created this checkpoint.
    #[serde(default)]
    pub scanner_set: Vec<String>,
}

impl Checkpoint {
    /// Load from `.zentra/checkpoint.json`. Return `Default` if the file does
    /// not exist or fails to parse. A missing or corrupt checkpoint must not
    /// block a scan; it means nothing is pre-completed.
    pub fn load(zentra_dir: &Path) -> Self {
        let path = zentra_dir.join("checkpoint.json");
        match std::fs::read_to_string(&path) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Load an explicitly requested resume checkpoint.
    ///
    /// Unlike the best-effort loader used by the legacy pentest path, resume
    /// for a static scan must not turn a missing or corrupt file into a fresh
    /// scan.
    pub fn load_strict(zentra_dir: &Path) -> anyhow::Result<Self> {
        let path = zentra_dir.join("checkpoint.json");
        let contents = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", path.display()))?;
        serde_json::from_str(&contents)
            .map_err(|e| anyhow::anyhow!("failed to parse {}: {e}", path.display()))
    }

    /// Save to `.zentra/checkpoint.json`. Best-effort: errors are logged, not fatal.
    pub fn save(&self, zentra_dir: &Path) {
        let path = zentra_dir.join("checkpoint.json");
        if let Ok(s) = serde_json::to_string_pretty(self) {
            if let Err(e) = std::fs::write(&path, s) {
                crate::logging::warn("checkpoint", format!("failed to write checkpoint: {e}"));
            }
        }
    }

    /// Mark a scanner as completed and save.
    pub fn mark_completed(&mut self, zentra_dir: &Path, scanner: &str) {
        self.completed.insert(scanner.to_string());
        self.updated_at = chrono::Utc::now().to_rfc3339();
        self.save(zentra_dir);
    }

    /// Whether a scanner should be skipped on resume.
    pub fn is_completed(&self, scanner: &str) -> bool {
        self.completed.contains(scanner)
    }

    /// Clear the checkpoint. Call this when a fresh (non-resume) scan starts.
    pub fn clear(zentra_dir: &Path) {
        let path = zentra_dir.join("checkpoint.json");
        let _ = std::fs::remove_file(&path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn zentra_dir(tmp: &TempDir) -> std::path::PathBuf {
        let dir = tmp.path().join(".zentra");
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn load_returns_default_when_file_is_missing() {
        let tmp = TempDir::new().unwrap();
        let dir = zentra_dir(&tmp);
        let cp = Checkpoint::load(&dir);
        assert!(cp.completed.is_empty());
        assert!(cp.updated_at.is_empty());
        assert!(cp.scanner_set.is_empty());
    }

    #[test]
    fn load_returns_default_when_file_is_corrupt() {
        let tmp = TempDir::new().unwrap();
        let dir = zentra_dir(&tmp);
        std::fs::write(dir.join("checkpoint.json"), "not valid json {{{").unwrap();
        let cp = Checkpoint::load(&dir);
        assert!(cp.completed.is_empty());
        assert!(cp.updated_at.is_empty());
    }

    #[test]
    fn strict_load_rejects_missing_and_corrupt_files() {
        let tmp = TempDir::new().unwrap();
        let dir = zentra_dir(&tmp);
        assert!(Checkpoint::load_strict(&dir).is_err());

        std::fs::write(dir.join("checkpoint.json"), "not valid json {{{").unwrap();
        assert!(Checkpoint::load_strict(&dir).is_err());
    }

    #[test]
    fn strict_load_accepts_empty_checkpoint() {
        let tmp = TempDir::new().unwrap();
        let dir = zentra_dir(&tmp);
        std::fs::write(dir.join("checkpoint.json"), "{}").unwrap();
        let checkpoint = Checkpoint::load_strict(&dir).unwrap();
        assert!(checkpoint.completed.is_empty());
    }

    #[test]
    fn save_then_load_round_trips_completed_scanners() {
        let tmp = TempDir::new().unwrap();
        let dir = zentra_dir(&tmp);
        let mut cp = Checkpoint::default();
        cp.completed.insert("sast".to_string());
        cp.completed.insert("threat_model".to_string());
        cp.updated_at = "2024-01-01T00:00:00Z".to_string();
        cp.scanner_set = vec!["sast".to_string(), "threat_model".to_string()];
        cp.save(&dir);

        let loaded = Checkpoint::load(&dir);
        assert_eq!(loaded.completed, cp.completed);
        assert_eq!(loaded.updated_at, cp.updated_at);
        assert_eq!(loaded.scanner_set, cp.scanner_set);
    }

    #[test]
    fn mark_completed_adds_to_set_and_persists() {
        let tmp = TempDir::new().unwrap();
        let dir = zentra_dir(&tmp);
        let mut cp = Checkpoint::default();
        cp.mark_completed(&dir, "sast");
        cp.mark_completed(&dir, "threat_model");

        let loaded = Checkpoint::load(&dir);
        assert!(loaded.is_completed("sast"));
        assert!(loaded.is_completed("threat_model"));
        assert!(!loaded.updated_at.is_empty());
    }

    #[test]
    fn is_completed_returns_true_for_completed_false_for_others() {
        let mut cp = Checkpoint::default();
        cp.completed.insert("sast".to_string());
        assert!(cp.is_completed("sast"));
        assert!(!cp.is_completed("supply_chain"));
        assert!(!cp.is_completed(""));
    }

    #[test]
    fn clear_removes_the_file() {
        let tmp = TempDir::new().unwrap();
        let dir = zentra_dir(&tmp);
        let mut cp = Checkpoint::default();
        cp.mark_completed(&dir, "sast");
        assert!(dir.join("checkpoint.json").exists());

        Checkpoint::clear(&dir);
        assert!(!dir.join("checkpoint.json").exists());

        let loaded = Checkpoint::load(&dir);
        assert!(loaded.completed.is_empty());
    }
}
