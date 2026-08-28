use crate::agent::chat::ConfirmedChatAction;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

/// Records which scanners completed successfully in a prior run.
/// The orchestrator uses this to skip completed scanners on resume.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Security/chat session that owns the pending confirmed actions. Empty
    /// for legacy checkpoints created before interactive chat existed.
    #[serde(default, deserialize_with = "deserialize_checkpoint_session_id")]
    pub session_id: String,
    /// Locally confirmed, typed actions waiting for an orchestration boundary.
    /// Conversation text is intentionally never checkpointed.
    #[serde(default)]
    pub confirmed_chat_actions: Vec<ConfirmedChatAction>,
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
        if let Err(e) = self.save_strict(zentra_dir) {
            crate::logging::warn("checkpoint", format!("failed to write checkpoint: {e}"));
        }
    }

    /// Atomically save a durable checkpoint. Chat lifecycle callers use this
    /// path to guarantee persistence before exposing a pending action.
    pub fn save_strict(&self, zentra_dir: &Path) -> anyhow::Result<()> {
        let path = zentra_dir.join("checkpoint.json");
        let bytes = serde_json::to_vec_pretty(self)?;
        let temp = zentra_dir.join(format!(
            ".checkpoint-{}-{}.tmp",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let write_result = (|| -> anyhow::Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temp, &path)?;
            sync_dir(zentra_dir)?;
            Ok(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        write_result
    }

    /// Mark a scanner as completed and save.
    pub fn mark_completed(&mut self, zentra_dir: &Path, scanner: &str) {
        self.completed.insert(scanner.to_string());
        self.updated_at = chrono::Utc::now().to_rfc3339();
        self.save(zentra_dir);
    }

    /// Set the scan session and persist it at fresh-run creation.
    pub fn set_session_id(&mut self, zentra_dir: &Path, session_id: String) {
        if let Err(error) = self.set_session_id_strict(zentra_dir, session_id) {
            crate::logging::warn(
                "checkpoint",
                format!("failed to persist chat session: {error}"),
            );
        }
    }

    pub fn set_session_id_strict(
        &mut self,
        zentra_dir: &Path,
        session_id: String,
    ) -> anyhow::Result<()> {
        crate::agent::chat::validate_session_id(&session_id)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let mut updated = self.clone();
        updated.session_id = session_id;
        updated.updated_at = chrono::Utc::now().to_rfc3339();
        updated.save_strict(zentra_dir)?;
        *self = updated;
        Ok(())
    }

    /// Persist a locally confirmed chat action before it is reported as
    /// pending. Replacing an existing proposal ID keeps retries idempotent.
    pub fn save_confirmed_chat_action(&mut self, zentra_dir: &Path, action: ConfirmedChatAction) {
        if let Err(error) = self.save_confirmed_chat_action_strict(zentra_dir, action) {
            crate::logging::warn(
                "checkpoint",
                format!("failed to persist chat action: {error}"),
            );
        }
    }

    pub fn save_confirmed_chat_action_strict(
        &mut self,
        zentra_dir: &Path,
        action: ConfirmedChatAction,
    ) -> anyhow::Result<()> {
        let mut updated = self.clone();
        updated
            .confirmed_chat_actions
            .retain(|existing| existing.proposal_id != action.proposal_id);
        updated.confirmed_chat_actions.push(action);
        updated
            .confirmed_chat_actions
            .sort_by_key(|action| action.confirmation_sequence);
        updated.updated_at = chrono::Utc::now().to_rfc3339();
        updated.save_strict(zentra_dir)?;
        *self = updated;
        Ok(())
    }

    /// Remove an action once it is coalesced, applied, deferred, cancelled, or
    /// expired. This is intentionally explicit so lifecycle callers cannot
    /// accidentally leave actionable state in a resume checkpoint.
    pub fn remove_confirmed_chat_action(
        &mut self,
        zentra_dir: &Path,
        proposal_id: uuid::Uuid,
    ) -> bool {
        match self.remove_confirmed_chat_action_strict(zentra_dir, proposal_id) {
            Ok(removed) => removed,
            Err(error) => {
                crate::logging::warn(
                    "checkpoint",
                    format!("failed to remove chat action: {error}"),
                );
                false
            }
        }
    }

    pub fn remove_confirmed_chat_action_strict(
        &mut self,
        zentra_dir: &Path,
        proposal_id: uuid::Uuid,
    ) -> anyhow::Result<bool> {
        let mut updated = self.clone();
        let before = updated.confirmed_chat_actions.len();
        updated
            .confirmed_chat_actions
            .retain(|action| action.proposal_id != proposal_id);
        let removed = updated.confirmed_chat_actions.len() != before;
        if !removed {
            return Ok(false);
        }
        updated.updated_at = chrono::Utc::now().to_rfc3339();
        updated.save_strict(zentra_dir)?;
        *self = updated;
        Ok(true)
    }

    /// Atomically invalidate a scanner and the report before a fresh chat
    /// rerun. Clone-before-save is important: a persistence failure must leave
    /// the caller's in-memory checkpoint accurately representing disk.
    pub fn invalidate_for_chat_rerun_strict(
        &mut self,
        zentra_dir: &Path,
        scanner: &str,
    ) -> anyhow::Result<()> {
        let mut updated = self.clone();
        updated.completed.remove(scanner);
        updated.completed.remove("report");
        updated.updated_at = chrono::Utc::now().to_rfc3339();
        updated.save_strict(zentra_dir)?;
        *self = updated;
        Ok(())
    }

    /// Atomically invalidate every requested chat target and the report.  This
    /// is deliberately a single clone/save/swap so a resume can never observe a
    /// subset of a multi-scanner action as fresh.
    pub fn invalidate_chat_reruns_strict(
        &mut self,
        zentra_dir: &Path,
        scanners: impl IntoIterator<Item = String>,
    ) -> anyhow::Result<()> {
        let mut updated = self.clone();
        for scanner in scanners {
            updated.completed.remove(&scanner);
        }
        updated.completed.remove("report");
        updated.updated_at = chrono::Utc::now().to_rfc3339();
        updated.save_strict(zentra_dir)?;
        *self = updated;
        Ok(())
    }

    /// Restore only the exact completion names captured immediately before a
    /// resume invalidation. This compensates a fail-closed snapshot boundary
    /// before any scanner work begins; it never reconstructs arbitrary state.
    pub fn restore_completed_names_strict(
        &mut self,
        zentra_dir: &Path,
        names: &BTreeSet<String>,
    ) -> anyhow::Result<()> {
        if names.is_empty() {
            return Ok(());
        }
        let mut updated = self.clone();
        updated.completed.extend(names.iter().cloned());
        updated.updated_at = chrono::Utc::now().to_rfc3339();
        updated.save_strict(zentra_dir)?;
        *self = updated;
        Ok(())
    }

    /// Commit scanner completion and durable per-proposal progress together.
    pub fn complete_chat_scanner_strict(
        &mut self,
        zentra_dir: &Path,
        scanner: &str,
        proposal_ids: &[uuid::Uuid],
    ) -> anyhow::Result<Vec<ConfirmedChatAction>> {
        let supplied_count = proposal_ids.len();
        let proposal_ids: BTreeSet<_> = proposal_ids.iter().copied().collect();
        // The input is captured when a scanner is spawned. Reject accidental
        // duplicate attribution rather than silently widening progress.
        if proposal_ids.len() != supplied_count {
            anyhow::bail!("duplicate chat proposal attribution for scanner completion");
        }
        let mut updated = self.clone();
        updated.completed.insert(scanner.to_string());
        let mut newly_complete = Vec::new();
        for action in &mut updated.confirmed_chat_actions {
            let was_pending = !action.remaining_scanners.is_empty();
            if proposal_ids.contains(&action.proposal_id) {
                action
                    .remaining_scanners
                    .retain(|target| target.name() != scanner);
            }
            if was_pending && action.remaining_scanners.is_empty() {
                newly_complete.push(action.clone());
            }
        }
        updated.updated_at = chrono::Utc::now().to_rfc3339();
        updated.save_strict(zentra_dir)?;
        *self = updated;
        Ok(newly_complete)
    }

    /// Strictly remove several terminal actions in one durable replacement.
    pub fn remove_confirmed_chat_actions_strict(
        &mut self,
        zentra_dir: &Path,
        proposal_ids: &BTreeSet<uuid::Uuid>,
    ) -> anyhow::Result<()> {
        if proposal_ids.is_empty() {
            return Ok(());
        }
        let mut updated = self.clone();
        updated
            .confirmed_chat_actions
            .retain(|action| !proposal_ids.contains(&action.proposal_id));
        updated.updated_at = chrono::Utc::now().to_rfc3339();
        updated.save_strict(zentra_dir)?;
        *self = updated;
        Ok(())
    }

    /// Return pending actions only when this checkpoint belongs to exactly the
    /// resumed session and canonical scanner set. A subset could widen or
    /// silently reinterpret confirmed work, so it is deliberately rejected.
    pub fn confirmed_chat_actions_for_resume(
        &self,
        session_id: &str,
        selected: &[crate::agent::ScannerType],
    ) -> Result<Vec<ConfirmedChatAction>, crate::agent::chat::ChatValidationError> {
        use crate::agent::chat::ChatValidationError;
        if self.session_id != session_id {
            return Err(ChatValidationError::SessionMismatch);
        }
        let mut canonical_selected: Vec<_> =
            selected.iter().map(|scanner| scanner.name()).collect();
        canonical_selected.sort_unstable();
        if canonical_selected.windows(2).any(|pair| pair[0] == pair[1])
            || self.scanner_set.windows(2).any(|pair| pair[0] >= pair[1])
            || self
                .scanner_set
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                != canonical_selected
        {
            return Err(ChatValidationError::ScannerSetMismatch);
        }
        let mut actions: Vec<_> = self
            .confirmed_chat_actions
            .iter()
            .map(|action| {
                action.validate_for_resume(selected)?;
                Ok(action.clone())
            })
            .collect::<Result<_, ChatValidationError>>()?;
        actions.sort_by_key(|action| action.confirmation_sequence);
        let action_refs: Vec<_> = actions.iter().map(|action| &action.action).collect();
        crate::agent::chat::ChatAction::validate_coalesced_plan(&action_refs, selected)?;
        Ok(actions)
    }

    /// Whether a scanner should be skipped on resume.
    pub fn is_completed(&self, scanner: &str) -> bool {
        self.completed.contains(scanner)
    }

    /// Clear the checkpoint. Call this when a fresh (non-resume) scan starts.
    pub fn clear(zentra_dir: &Path) {
        if let Err(error) = Self::clear_strict(zentra_dir) {
            crate::logging::warn("checkpoint", format!("failed to clear checkpoint: {error}"));
        }
    }

    pub fn clear_strict(zentra_dir: &Path) -> anyhow::Result<()> {
        let path = zentra_dir.join("checkpoint.json");
        match std::fs::remove_file(&path) {
            Ok(()) => {
                sync_dir(zentra_dir)?;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

fn deserialize_checkpoint_session_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let session_id = String::deserialize(deserializer)?;
    if session_id.is_empty() {
        return Ok(session_id);
    }
    crate::agent::chat::validate_session_id(&session_id).map_err(serde::de::Error::custom)?;
    Ok(session_id)
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
        assert!(cp.session_id.is_empty());
        assert!(cp.confirmed_chat_actions.is_empty());
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
        assert!(checkpoint.session_id.is_empty());
        assert!(checkpoint.confirmed_chat_actions.is_empty());
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

    #[test]
    fn legacy_checkpoint_loads_with_empty_chat_fields() {
        let tmp = TempDir::new().unwrap();
        let dir = zentra_dir(&tmp);
        std::fs::write(
            dir.join("checkpoint.json"),
            r#"{"completed":["sast"],"updated_at":"now","scanner_set":["sast"]}"#,
        )
        .unwrap();
        let checkpoint = Checkpoint::load_strict(&dir).unwrap();
        assert!(checkpoint.session_id.is_empty());
        assert!(checkpoint.confirmed_chat_actions.is_empty());
        assert!(checkpoint.is_completed("sast"));
    }

    #[test]
    fn confirmed_chat_action_lifecycle_persists_and_removes() {
        use crate::agent::chat::{ChatAction, ConfirmedChatAction, FocusScope};
        use crate::agent::ScannerType;
        use uuid::Uuid;

        let tmp = TempDir::new().unwrap();
        let dir = zentra_dir(&tmp);
        let mut checkpoint = Checkpoint::default();
        checkpoint.set_session_id(&dir, "safe-session".to_string());
        let action = ConfirmedChatAction::new(
            Uuid::new_v4(),
            1,
            ChatAction::focus_and_rerun(
                [ScannerType::Sast],
                FocusScope::new([crate::agent::chat::FocusFragment::InputValidation], []).unwrap(),
            )
            .unwrap(),
            [ScannerType::Sast],
        )
        .unwrap();
        let proposal_id = action.proposal_id;
        checkpoint.save_confirmed_chat_action(&dir, action.clone());

        let loaded = Checkpoint::load_strict(&dir).unwrap();
        assert_eq!(loaded.session_id, "safe-session");
        assert_eq!(loaded.confirmed_chat_actions, vec![action]);
        assert!(checkpoint.remove_confirmed_chat_action(&dir, proposal_id));
        assert!(Checkpoint::load_strict(&dir)
            .unwrap()
            .confirmed_chat_actions
            .is_empty());
    }

    #[test]
    fn resume_requires_exact_canonical_scanner_set() {
        use crate::agent::chat::ChatValidationError;
        use crate::agent::ScannerType;

        let checkpoint = Checkpoint {
            session_id: "session".to_string(),
            scanner_set: vec!["api_scan".to_string(), "sast".to_string()],
            ..Checkpoint::default()
        };
        assert!(checkpoint
            .confirmed_chat_actions_for_resume(
                "session",
                &[ScannerType::ApiScan, ScannerType::Sast]
            )
            .is_ok());
        assert_eq!(
            checkpoint.confirmed_chat_actions_for_resume("session", &[ScannerType::Sast]),
            Err(ChatValidationError::ScannerSetMismatch)
        );
        assert_eq!(
            checkpoint.confirmed_chat_actions_for_resume(
                "other",
                &[ScannerType::ApiScan, ScannerType::Sast]
            ),
            Err(ChatValidationError::SessionMismatch)
        );
    }

    #[test]
    fn duplicate_or_noncanonical_scanner_set_is_rejected() {
        use crate::agent::ScannerType;
        let duplicate = Checkpoint {
            session_id: "session".to_string(),
            scanner_set: vec!["api_scan".to_string(), "api_scan".to_string()],
            ..Checkpoint::default()
        };
        assert!(duplicate
            .confirmed_chat_actions_for_resume(
                "session",
                &[ScannerType::ApiScan, ScannerType::Sast]
            )
            .is_err());
        let noncanonical = Checkpoint {
            session_id: "session".to_string(),
            scanner_set: vec!["sast".to_string(), "api_scan".to_string()],
            ..Checkpoint::default()
        };
        assert!(noncanonical
            .confirmed_chat_actions_for_resume(
                "session",
                &[ScannerType::ApiScan, ScannerType::Sast]
            )
            .is_err());
    }

    #[test]
    fn strict_chat_lifecycle_does_not_mutate_when_persistence_fails() {
        let tmp = TempDir::new().unwrap();
        let not_a_directory = tmp.path().join("not-a-directory");
        std::fs::write(&not_a_directory, "file").unwrap();
        let mut checkpoint = Checkpoint::default();
        assert!(checkpoint
            .set_session_id_strict(&not_a_directory, "session".to_string())
            .is_err());
        assert!(checkpoint.session_id.is_empty());
    }

    #[test]
    fn strict_rerun_invalidation_removes_target_and_report_without_partial_mutation() {
        let tmp = TempDir::new().unwrap();
        let dir = zentra_dir(&tmp);
        let mut checkpoint = Checkpoint::default();
        checkpoint.completed.extend([
            "sast".to_string(),
            "report".to_string(),
            "api_scan".to_string(),
        ]);
        checkpoint.save_strict(&dir).unwrap();
        checkpoint
            .invalidate_for_chat_rerun_strict(&dir, "sast")
            .unwrap();
        assert!(!checkpoint.is_completed("sast"));
        assert!(!checkpoint.is_completed("report"));
        assert!(checkpoint.is_completed("api_scan"));

        let original = checkpoint.clone();
        let not_a_directory = tmp.path().join("not-a-directory");
        std::fs::write(&not_a_directory, "file").unwrap();
        assert!(checkpoint
            .invalidate_for_chat_rerun_strict(&not_a_directory, "api_scan")
            .is_err());
        assert_eq!(checkpoint.completed, original.completed);
    }

    #[test]
    fn strict_batch_invalidation_is_atomic_for_remaining_chat_targets() {
        let tmp = TempDir::new().unwrap();
        let dir = zentra_dir(&tmp);
        let mut checkpoint = Checkpoint::default();
        checkpoint.completed.extend([
            "sast".to_string(),
            "api_scan".to_string(),
            "report".to_string(),
            "iac_scan".to_string(),
        ]);
        checkpoint.save_strict(&dir).unwrap();
        checkpoint
            .invalidate_chat_reruns_strict(&dir, ["sast".to_string(), "api_scan".to_string()])
            .unwrap();
        assert!(!checkpoint.is_completed("sast"));
        assert!(!checkpoint.is_completed("api_scan"));
        assert!(!checkpoint.is_completed("report"));
        assert!(checkpoint.is_completed("iac_scan"));

        let before = checkpoint.clone();
        let bad = tmp.path().join("not-a-directory");
        std::fs::write(&bad, "file").unwrap();
        assert!(checkpoint
            .invalidate_chat_reruns_strict(&bad, ["iac_scan".to_string()])
            .is_err());
        assert_eq!(checkpoint, before);
    }

    #[test]
    fn completing_chat_scanner_only_updates_dependents_and_reports_newly_empty_actions() {
        use crate::agent::chat::{ChatAction, FocusFragment, FocusScope};
        use crate::agent::ScannerType;
        use uuid::Uuid;

        let tmp = TempDir::new().unwrap();
        let dir = zentra_dir(&tmp);
        let scope = || FocusScope::new([FocusFragment::InputValidation], []).unwrap();
        let multi = ConfirmedChatAction::new(
            Uuid::new_v4(),
            1,
            ChatAction::focus_and_rerun([ScannerType::Sast, ScannerType::ApiScan], scope())
                .unwrap(),
            [ScannerType::Sast, ScannerType::ApiScan],
        )
        .unwrap();
        let unrelated = ConfirmedChatAction::new(
            Uuid::new_v4(),
            2,
            ChatAction::focus_and_rerun([ScannerType::IacScan], scope()).unwrap(),
            [ScannerType::IacScan],
        )
        .unwrap();
        let mut checkpoint = Checkpoint {
            confirmed_chat_actions: vec![multi.clone(), unrelated.clone()],
            ..Checkpoint::default()
        };
        checkpoint.save_strict(&dir).unwrap();

        assert!(checkpoint
            .complete_chat_scanner_strict(&dir, "sast", &[multi.proposal_id])
            .unwrap()
            .is_empty());
        assert_eq!(
            checkpoint.confirmed_chat_actions[0].remaining_scanners,
            vec![ScannerType::ApiScan]
        );
        assert_eq!(
            checkpoint.confirmed_chat_actions[1].remaining_scanners,
            unrelated.remaining_scanners
        );
        assert_eq!(
            checkpoint
                .complete_chat_scanner_strict(&dir, "api_scan", &[multi.proposal_id])
                .unwrap(),
            vec![checkpoint.confirmed_chat_actions[0].clone()]
        );

        let before = checkpoint.clone();
        let file = tmp.path().join("not-a-directory");
        std::fs::write(&file, "file").unwrap();
        assert!(checkpoint
            .complete_chat_scanner_strict(&file, "iac_scan", &[unrelated.proposal_id])
            .is_err());
        assert_eq!(checkpoint.completed, before.completed);
        assert_eq!(
            checkpoint.confirmed_chat_actions,
            before.confirmed_chat_actions
        );
    }

    #[test]
    fn scanner_completion_advances_only_focus_members_present_at_spawn() {
        use crate::agent::chat::{ChatAction, FocusFragment, FocusScope};
        use crate::agent::ScannerType;
        use uuid::Uuid;

        let tmp = TempDir::new().unwrap();
        let dir = zentra_dir(&tmp);
        let action = |sequence| {
            ConfirmedChatAction::new(
                Uuid::new_v4(),
                sequence,
                ChatAction::focus_and_rerun(
                    [ScannerType::Sast],
                    FocusScope::new([FocusFragment::InputValidation], []).unwrap(),
                )
                .unwrap(),
                [ScannerType::Sast],
            )
            .unwrap()
        };
        let before = action(1);
        let late = action(2);
        let unrelated = ConfirmedChatAction::new(
            Uuid::new_v4(),
            3,
            ChatAction::focus_and_rerun(
                [ScannerType::ApiScan],
                FocusScope::new([FocusFragment::InputValidation], []).unwrap(),
            )
            .unwrap(),
            [ScannerType::ApiScan],
        )
        .unwrap();
        let mut checkpoint = Checkpoint {
            confirmed_chat_actions: vec![before.clone(), late.clone(), unrelated.clone()],
            ..Checkpoint::default()
        };
        checkpoint.save_strict(&dir).unwrap();
        let completed = checkpoint
            .complete_chat_scanner_strict(&dir, "sast", &[before.proposal_id])
            .unwrap();
        assert_eq!(
            completed,
            vec![checkpoint.confirmed_chat_actions[0].clone()]
        );
        assert!(checkpoint.confirmed_chat_actions[0]
            .remaining_scanners
            .is_empty());
        assert_eq!(
            checkpoint.confirmed_chat_actions[1].remaining_scanners,
            vec![ScannerType::Sast]
        );
        assert_eq!(
            checkpoint.confirmed_chat_actions[2].remaining_scanners,
            vec![ScannerType::ApiScan]
        );
        assert!(checkpoint
            .complete_chat_scanner_strict(&dir, "sast", &[late.proposal_id, late.proposal_id])
            .is_err());
    }

    #[test]
    fn checkpoint_rejects_malicious_session_and_strict_setter_keeps_state() {
        let tmp = TempDir::new().unwrap();
        let dir = zentra_dir(&tmp);
        std::fs::write(
            dir.join("checkpoint.json"),
            r#"{"session_id":"../../../x"}"#,
        )
        .unwrap();
        assert!(Checkpoint::load_strict(&dir).is_err());

        let mut checkpoint = Checkpoint::default();
        assert!(checkpoint
            .set_session_id_strict(&dir, "../../../x".to_string())
            .is_err());
        assert!(checkpoint.session_id.is_empty());
        assert_eq!(
            std::fs::read_to_string(dir.join("checkpoint.json")).unwrap(),
            r#"{"session_id":"../../../x"}"#
        );
    }

    #[test]
    fn restored_actions_require_contextual_supply_chain_focus() {
        use crate::agent::chat::{ChatAction, FocusFragment, FocusScope};
        use crate::agent::ScannerType;
        use uuid::Uuid;

        let supply = ConfirmedChatAction::new(
            Uuid::new_v4(),
            2,
            ChatAction::focus_and_rerun(
                [ScannerType::SupplyChain],
                FocusScope::new([FocusFragment::InputValidation], []).unwrap(),
            )
            .unwrap(),
            [ScannerType::SupplyChain],
        )
        .unwrap();
        let mut checkpoint = Checkpoint {
            session_id: "session".to_string(),
            scanner_set: vec!["supply_chain".to_string()],
            confirmed_chat_actions: vec![supply.clone()],
            ..Checkpoint::default()
        };
        assert_eq!(
            checkpoint.confirmed_chat_actions_for_resume("session", &[ScannerType::SupplyChain]),
            Err(crate::agent::chat::ChatValidationError::SupplyChainFocusRequired)
        );

        let category = ConfirmedChatAction::new(
            Uuid::new_v4(),
            1,
            ChatAction::prioritize(
                crate::agent::chat::VulnerabilityCategory::DependencySupplyChain,
            ),
            [ScannerType::SupplyChain],
        )
        .unwrap();
        checkpoint.confirmed_chat_actions.push(category);
        let restored = checkpoint
            .confirmed_chat_actions_for_resume("session", &[ScannerType::SupplyChain])
            .unwrap();
        assert_eq!(restored[0].confirmation_sequence, 1);
        assert_eq!(restored[1].confirmation_sequence, 2);
    }
}
