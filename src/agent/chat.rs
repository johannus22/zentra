//! Pure contracts and best-effort persistence for the interactive scan chat.
//!
//! This module deliberately contains no provider, tool, channel, or
//! orchestrator code.  Keeping these values independently serialisable makes
//! persisted chat state reviewable without turning it into executable input.

use crate::agent::ScannerType;
use chrono::{DateTime, Utc};
use serde::de::{self, Deserializer};
use serde::ser::{SerializeStruct, Serializer};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

pub const MAX_FOCUS_FRAGMENTS: usize = 4;
pub const MAX_FOCUS_PATHS: usize = 20;
pub const MAX_PATH_BYTES: usize = 1024;
pub const MAX_CHAT_TEXT_BYTES: usize = 4096;
pub const MAX_LIFECYCLE_MESSAGE_BYTES: usize = 1024;
/// Worst-case JSON expansion is six bytes per source byte (`\u00XX`). This
/// covers every independently valid path/text field plus fixed schema data.
pub const MAX_CHAT_RECORD_BYTES: usize =
    MAX_FOCUS_PATHS * MAX_PATH_BYTES * 6 + MAX_CHAT_TEXT_BYTES * 6 + 8 * 1024;
pub const MAX_CHAT_SESSION_FILES: usize = 20;
pub const CHAT_RECORD_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VulnerabilityCategory {
    AuthenticationAuthorization,
    Injection,
    SensitiveDataExposure,
    DependencySupplyChain,
    InfrastructureMisconfiguration,
}

impl VulnerabilityCategory {
    /// Fixed text only; persisted actions cannot inject a model-supplied prompt
    /// fragment into scanner context.
    pub fn prompt_fragment(self) -> &'static str {
        match self {
            Self::AuthenticationAuthorization => {
                "Prioritize authentication, authorization, and boundary enforcement risks."
            }
            Self::Injection => "Prioritize injection and unsafe input interpretation risks.",
            Self::SensitiveDataExposure => {
                "Prioritize sensitive-data exposure, leakage, and protection risks."
            }
            Self::DependencySupplyChain => {
                "Prioritize dependency, advisory, provenance, and supply-chain risks."
            }
            Self::InfrastructureMisconfiguration => {
                "Prioritize infrastructure configuration and privilege-boundary risks."
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FocusFragment {
    AuthBoundary,
    InputValidation,
    DataFlow,
    SecretsAndSensitiveData,
    DependencyManifest,
    NetworkExposure,
    IaCPrivilege,
}

impl FocusFragment {
    /// Fixed template content for later prompt construction.
    pub fn prompt_fragment(self) -> &'static str {
        match self {
            Self::AuthBoundary => "authentication and authorization boundaries",
            Self::InputValidation => "input validation and parsing boundaries",
            Self::DataFlow => "sensitive data flows and trust transitions",
            Self::SecretsAndSensitiveData => "secrets and sensitive-data handling",
            Self::DependencyManifest => "dependency manifests and declared packages",
            Self::NetworkExposure => "network-exposed services and interfaces",
            Self::IaCPrivilege => "infrastructure privilege and identity configuration",
        }
    }
}

/// A project-relative, slash-normalized path suitable for a bounded focus
/// scope. It is never an OS path and therefore cannot escape the project.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NormalizedRepoPath(String);

impl NormalizedRepoPath {
    /// Normalize separators while rejecting absolute paths, parent traversal,
    /// empty components, and implausibly large inputs.
    pub fn normalize(path: impl AsRef<str>) -> Result<Self, ChatValidationError> {
        let raw = path.as_ref();
        if raw.is_empty() || raw.len() > MAX_PATH_BYTES || raw.contains('\0') {
            return Err(ChatValidationError::InvalidPath);
        }
        let normalized = raw.replace('\\', "/");
        if normalized.starts_with('/')
            || normalized.starts_with("//")
            || normalized.starts_with("~/")
            || normalized
                .as_bytes()
                .get(1)
                .is_some_and(|byte| *byte == b':')
        {
            return Err(ChatValidationError::InvalidPath);
        }

        let mut parts = Vec::new();
        for part in normalized.split('/') {
            if part.is_empty() || part == "." || part == ".." {
                return Err(ChatValidationError::InvalidPath);
            }
            parts.push(part);
        }
        if parts.is_empty() {
            return Err(ChatValidationError::InvalidPath);
        }
        Ok(Self(parts.join("/")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Verify that this logical repository path cannot resolve outside `root`.
    /// For a not-yet-created file, the nearest existing ancestor is resolved so
    /// an existing symlink in the path cannot redirect later writes/reads.
    pub fn validate_within_root(&self, root: &Path) -> Result<(), ChatValidationError> {
        let canonical_root =
            fs::canonicalize(root).map_err(|_| ChatValidationError::InvalidRoot)?;
        if !canonical_root.is_dir() {
            return Err(ChatValidationError::InvalidRoot);
        }
        let target = root.join(&self.0);
        let mut existing = target.as_path();
        loop {
            match fs::symlink_metadata(existing) {
                Ok(_) => break,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    existing = existing
                        .parent()
                        .ok_or(ChatValidationError::PathOutsideRoot)?;
                }
                Err(_) => return Err(ChatValidationError::PathOutsideRoot),
            }
        }
        let canonical_existing =
            fs::canonicalize(existing).map_err(|_| ChatValidationError::PathOutsideRoot)?;
        if canonical_existing.starts_with(&canonical_root) {
            Ok(())
        } else {
            Err(ChatValidationError::PathOutsideRoot)
        }
    }
}

impl fmt::Display for NormalizedRepoPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for NormalizedRepoPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for NormalizedRepoPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        let path = Self::normalize(&raw).map_err(de::Error::custom)?;
        if path.as_str() != raw {
            return Err(de::Error::custom(
                "repository path must be slash-normalized",
            ));
        }
        Ok(path)
    }
}

/// Canonical, bounded narrowing data. `BTreeSet` guarantees deterministic
/// fragment rendering; paths are sorted lexically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FocusScope {
    pub fragments: BTreeSet<FocusFragment>,
    pub paths: Vec<NormalizedRepoPath>,
}

impl FocusScope {
    pub fn new(
        fragments: impl IntoIterator<Item = FocusFragment>,
        paths: impl IntoIterator<Item = NormalizedRepoPath>,
    ) -> Result<Self, ChatValidationError> {
        let fragments: BTreeSet<_> = fragments.into_iter().collect();
        let mut paths: Vec<_> = paths.into_iter().collect();
        paths.sort();
        if fragments.len() > MAX_FOCUS_FRAGMENTS || paths.len() > MAX_FOCUS_PATHS {
            return Err(ChatValidationError::ScopeLimit);
        }
        if fragments.is_empty() && paths.is_empty() {
            return Err(ChatValidationError::EmptyScope);
        }
        if paths.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ChatValidationError::DuplicatePath);
        }
        Ok(Self { fragments, paths })
    }

    /// Build a canonical scope from UI/model-normalized input. Separators are
    /// normalized and duplicate paths are rejected rather than silently
    /// widening a request.
    pub fn from_paths(
        fragments: impl IntoIterator<Item = FocusFragment>,
        paths: impl IntoIterator<Item = String>,
    ) -> Result<Self, ChatValidationError> {
        let paths = paths
            .into_iter()
            .map(NormalizedRepoPath::normalize)
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(fragments, paths)
    }

    pub fn validate_subset_of(
        &self,
        allowed: &[NormalizedRepoPath],
    ) -> Result<(), ChatValidationError> {
        if self
            .paths
            .iter()
            .all(|path| allowed.iter().any(|candidate| candidate == path))
        {
            Ok(())
        } else {
            Err(ChatValidationError::PathOutsideScope)
        }
    }

    pub fn validate_within_root(&self, root: &Path) -> Result<(), ChatValidationError> {
        self.paths
            .iter()
            .try_for_each(|path| path.validate_within_root(root))
    }
}

impl Serialize for FocusScope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("FocusScope", 2)?;
        state.serialize_field("fragments", &self.fragments)?;
        state.serialize_field("paths", &self.paths)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for FocusScope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawScope {
            fragments: Vec<FocusFragment>,
            paths: Vec<NormalizedRepoPath>,
        }
        let raw = RawScope::deserialize(deserializer)?;
        if raw.fragments.len() != raw.fragments.iter().collect::<BTreeSet<_>>().len() {
            return Err(de::Error::custom("duplicate focus fragment"));
        }
        FocusScope::new(raw.fragments, raw.paths).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChatAction {
    FocusAndRerun {
        scanners: Vec<ScannerType>,
        scope: FocusScope,
    },
    PrioritizeVulnerability {
        category: VulnerabilityCategory,
    },
}

impl ChatAction {
    pub fn focus_and_rerun(
        scanners: impl IntoIterator<Item = ScannerType>,
        scope: FocusScope,
    ) -> Result<Self, ChatValidationError> {
        let scanners = canonical_scanners(scanners)?;
        if scanners.iter().any(|scanner| !is_phase_two(*scanner)) {
            return Err(ChatValidationError::IneligibleScanner);
        }
        Ok(Self::FocusAndRerun { scanners, scope })
    }

    pub fn prioritize(category: VulnerabilityCategory) -> Self {
        Self::PrioritizeVulnerability { category }
    }

    /// Validate that the action can only affect scanners selected for this run.
    pub fn validate_for_selected(
        &self,
        selected: &[ScannerType],
    ) -> Result<(), ChatValidationError> {
        if let Self::FocusAndRerun { scanners, .. } = self {
            if scanners.iter().all(|scanner| selected.contains(scanner)) {
                return Ok(());
            }
            return Err(ChatValidationError::ScannerNotSelected);
        }
        Ok(())
    }

    pub fn scanners(&self) -> &[ScannerType] {
        match self {
            Self::FocusAndRerun { scanners, .. } => scanners,
            Self::PrioritizeVulnerability { .. } => &[],
        }
    }

    /// Validate the coalesced plan, where a separately confirmed category can
    /// provide the dependency focus required by SupplyChain. This contextual
    /// check intentionally does not make an individual action invalid.
    pub fn validate_coalesced_plan(
        actions: &[&ChatAction],
        selected: &[ScannerType],
    ) -> Result<(), ChatValidationError> {
        let mut supply_chain_targeted = false;
        let mut has_dependency_focus = false;
        for action in actions {
            action.validate_for_selected(selected)?;
            match action {
                Self::FocusAndRerun { scanners, scope } => {
                    supply_chain_targeted |= scanners.contains(&ScannerType::SupplyChain);
                    has_dependency_focus |=
                        scope.fragments.contains(&FocusFragment::DependencyManifest);
                }
                Self::PrioritizeVulnerability { category } => {
                    has_dependency_focus |=
                        *category == VulnerabilityCategory::DependencySupplyChain;
                }
            }
        }
        if supply_chain_targeted && !has_dependency_focus {
            Err(ChatValidationError::SupplyChainFocusRequired)
        } else {
            Ok(())
        }
    }
}

impl Serialize for ChatAction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        #[serde(tag = "type", rename_all = "snake_case")]
        enum RawAction<'a> {
            FocusAndRerun {
                scanners: Vec<&'static str>,
                scope: &'a FocusScope,
            },
            PrioritizeVulnerability {
                category: VulnerabilityCategory,
            },
        }
        let raw = match self {
            Self::FocusAndRerun { scanners, scope } => RawAction::FocusAndRerun {
                scanners: scanners.iter().map(ScannerType::name).collect(),
                scope,
            },
            Self::PrioritizeVulnerability { category } => RawAction::PrioritizeVulnerability {
                category: *category,
            },
        };
        raw.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ChatAction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
        enum RawAction {
            FocusAndRerun {
                scanners: Vec<String>,
                scope: FocusScope,
            },
            PrioritizeVulnerability {
                category: VulnerabilityCategory,
            },
        }
        match RawAction::deserialize(deserializer)? {
            RawAction::FocusAndRerun { scanners, scope } => ChatAction::focus_and_rerun(
                scanners
                    .iter()
                    .map(|scanner| scanner_from_name(scanner))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(de::Error::custom)?,
                scope,
            )
            .map_err(de::Error::custom),
            RawAction::PrioritizeVulnerability { category } => Ok(ChatAction::prioritize(category)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseBoundary {
    AfterFramework,
    AfterThreatModel,
    AfterParallel,
    Finalized,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionProposal {
    pub proposal_id: Uuid,
    pub request_id: Uuid,
    pub action: ChatAction,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub earliest_boundary: PhaseBoundary,
}

impl ActionProposal {
    pub fn validate_at(
        &self,
        now: DateTime<Utc>,
        selected: &[ScannerType],
    ) -> Result<(), ChatValidationError> {
        if self.expires_at <= self.created_at
            || self.expires_at - self.created_at > chrono::Duration::minutes(5)
        {
            return Err(ChatValidationError::InvalidExpiry);
        }
        if self.expires_at <= now {
            return Err(ChatValidationError::ExpiredProposal);
        }
        self.action.validate_for_selected(selected)
    }

    pub fn validate(&self, selected: &[ScannerType]) -> Result<(), ChatValidationError> {
        self.validate_at(Utc::now(), selected)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ChatCommand {
    Ask {
        request_id: Uuid,
        #[serde(deserialize_with = "deserialize_chat_text")]
        text: String,
    },
    Confirm {
        proposal_id: Uuid,
    },
    Reject {
        proposal_id: Uuid,
    },
    Cancel {
        request_id: Uuid,
    },
    Close,
}

impl ChatCommand {
    pub fn ask(request_id: Uuid, text: String) -> Result<Self, ChatValidationError> {
        validate_text(&text, MAX_CHAT_TEXT_BYTES, "chat request")?;
        Ok(Self::Ask { request_id, text })
    }

    pub fn validate(&self) -> Result<(), ChatValidationError> {
        if let Self::Ask { text, .. } = self {
            validate_text(text, MAX_CHAT_TEXT_BYTES, "chat request")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChatError {
    Backpressure,
    Cancelled,
    Provider,
    Security,
    Budget,
    InvalidProposal,
    Persistence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ChatEvent {
    RequestQueued {
        request_id: Uuid,
        position: usize,
    },
    Answer {
        request_id: Uuid,
        #[serde(deserialize_with = "deserialize_chat_text")]
        text: String,
    },
    Proposal {
        proposal: ActionProposal,
    },
    Applied {
        proposal_id: Uuid,
        boundary: PhaseBoundary,
    },
    Deferred {
        proposal_id: Uuid,
        #[serde(deserialize_with = "deserialize_lifecycle_message")]
        reason: String,
    },
    Cancelled {
        request_id: Uuid,
    },
    Error {
        request_id: Option<Uuid>,
        kind: ChatError,
        #[serde(deserialize_with = "deserialize_lifecycle_message")]
        message: String,
    },
}

impl ChatEvent {
    pub fn validate(&self) -> Result<(), ChatValidationError> {
        match self {
            Self::Answer { text, .. } => validate_text(text, MAX_CHAT_TEXT_BYTES, "chat answer"),
            Self::Deferred { reason, .. }
            | Self::Error {
                message: reason, ..
            } => validate_text(reason, MAX_LIFECYCLE_MESSAGE_BYTES, "chat event message"),
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestLifecycle {
    Draft,
    Queued,
    Running,
    Answered,
    Proposed,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalLifecycle {
    Proposed,
    Confirmed,
    PendingBoundary,
    Applied,
    Deferred,
    Expired,
    Rejected,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ChatLifecycle {
    Request { state: RequestLifecycle },
    Proposal { state: ProposalLifecycle },
}

/// The only chat data saved in a checkpoint. It has no transcript or model
/// output and is revalidated against the resumed scanner selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedChatAction {
    pub proposal_id: Uuid,
    pub confirmation_sequence: u64,
    pub action: ChatAction,
    pub required_scanners: Vec<ScannerType>,
}

impl ConfirmedChatAction {
    pub fn new(
        proposal_id: Uuid,
        confirmation_sequence: u64,
        action: ChatAction,
        required_scanners: impl IntoIterator<Item = ScannerType>,
    ) -> Result<Self, ChatValidationError> {
        let required_scanners = canonical_scanners(required_scanners)?;
        action.validate_for_selected(&required_scanners)?;
        Ok(Self {
            proposal_id,
            confirmation_sequence,
            action,
            required_scanners,
        })
    }

    pub fn validate_for_resume(&self, selected: &[ScannerType]) -> Result<(), ChatValidationError> {
        self.action.validate_for_selected(selected)?;
        if self
            .required_scanners
            .iter()
            .all(|scanner| selected.contains(scanner))
        {
            Ok(())
        } else {
            Err(ChatValidationError::ScannerNotSelected)
        }
    }
}

impl Serialize for ConfirmedChatAction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct Raw<'a> {
            proposal_id: Uuid,
            confirmation_sequence: u64,
            action: &'a ChatAction,
            required_scanners: Vec<&'static str>,
        }
        Raw {
            proposal_id: self.proposal_id,
            confirmation_sequence: self.confirmation_sequence,
            action: &self.action,
            required_scanners: self
                .required_scanners
                .iter()
                .map(ScannerType::name)
                .collect(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ConfirmedChatAction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            proposal_id: Uuid,
            confirmation_sequence: u64,
            action: ChatAction,
            required_scanners: Vec<String>,
        }
        let raw = Raw::deserialize(deserializer)?;
        ConfirmedChatAction::new(
            raw.proposal_id,
            raw.confirmation_sequence,
            raw.action,
            raw.required_scanners
                .iter()
                .map(|scanner| scanner_from_name(scanner))
                .collect::<Result<Vec<_>, _>>()
                .map_err(de::Error::custom)?,
        )
        .map_err(de::Error::custom)
    }
}

/// One append-only, schema-versioned JSONL entry. `text` is redacted by
/// [`ChatStore::append`] immediately before it reaches disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatRecord {
    #[serde(deserialize_with = "deserialize_schema_version")]
    pub schema_version: u16,
    pub timestamp: DateTime<Utc>,
    #[serde(deserialize_with = "deserialize_session_id")]
    pub session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposal_id: Option<Uuid>,
    pub lifecycle: ChatLifecycle,
    #[serde(
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_chat_text"
    )]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<ChatAction>,
}

impl ChatRecord {
    pub fn new(
        session_id: String,
        request_id: Option<Uuid>,
        proposal_id: Option<Uuid>,
        lifecycle: ChatLifecycle,
        text: Option<String>,
        action: Option<ChatAction>,
    ) -> Result<Self, ChatValidationError> {
        validate_session_id(&session_id)?;
        if let Some(text) = &text {
            validate_text(text, MAX_CHAT_TEXT_BYTES, "chat record text")?;
        }
        Ok(Self {
            schema_version: CHAT_RECORD_SCHEMA_VERSION,
            timestamp: Utc::now(),
            session_id,
            request_id,
            proposal_id,
            lifecycle,
            text,
            action,
        })
    }

    pub fn validate(&self) -> Result<(), ChatValidationError> {
        if self.schema_version != CHAT_RECORD_SCHEMA_VERSION {
            return Err(ChatValidationError::UnsupportedSchema);
        }
        validate_session_id(&self.session_id)?;
        if let Some(text) = &self.text {
            validate_text(text, MAX_CHAT_TEXT_BYTES, "chat record text")?;
        }
        Ok(())
    }

    fn redacted(&self) -> Self {
        let mut record = self.clone();
        record.text = record.text.as_deref().map(crate::logging::redact);
        record
    }
}

/// A best-effort JSONL transcript store. Errors are returned as values for the
/// coordinator to turn into `ChatError::Persistence`; they never represent a
/// scan failure.
#[derive(Debug, Clone)]
pub struct ChatStore {
    session_id: String,
    chat_dir: PathBuf,
    write_lock: Arc<Mutex<()>>,
}

impl ChatStore {
    pub fn new(
        zentra_dir: &Path,
        session_id: impl Into<String>,
    ) -> Result<Self, ChatPersistenceError> {
        let session_id = session_id.into();
        validate_session_id(&session_id).map_err(ChatPersistenceError::from)?;
        Ok(Self {
            session_id,
            chat_dir: zentra_dir.join("chat"),
            write_lock: Arc::new(Mutex::new(())),
        })
    }

    pub fn path(&self) -> PathBuf {
        self.chat_dir.join(format!("{}.jsonl", self.session_id))
    }

    pub fn append(&self, record: &ChatRecord) -> Result<(), ChatPersistenceError> {
        record.validate().map_err(ChatPersistenceError::from)?;
        if record.session_id != self.session_id {
            return Err(ChatPersistenceError::new(
                "chat record session does not match store",
            ));
        }
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| ChatPersistenceError::new("chat store write lock poisoned"))?;
        self.ensure_chat_dir()?;
        let serialized =
            serde_json::to_string(&record.redacted()).map_err(ChatPersistenceError::json)?;
        let mut line = serialized.into_bytes();
        line.push(b'\n');
        if line.len() > MAX_CHAT_RECORD_BYTES {
            return Err(ChatPersistenceError::new(
                "chat record exceeds storage limit",
            ));
        }
        let target = self.path();
        match fs::symlink_metadata(&target) {
            Ok(metadata)
                if metadata.file_type().is_symlink() || !metadata.file_type().is_file() =>
            {
                return Err(ChatPersistenceError::new(
                    "chat target is not a regular file",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(ChatPersistenceError::io(error)),
        }
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&target).map_err(ChatPersistenceError::io)?;
        file.write_all(&line)
            .and_then(|_| file.sync_data())
            .map_err(ChatPersistenceError::io)?;
        self.prune();
        Ok(())
    }

    fn ensure_chat_dir(&self) -> Result<(), ChatPersistenceError> {
        match fs::symlink_metadata(&self.chat_dir) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(ChatPersistenceError::new(
                        "chat path is not a real directory",
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match fs::create_dir(&self.chat_dir) {
                    Ok(()) => {}
                    Err(create_error)
                        if create_error.kind() == std::io::ErrorKind::AlreadyExists =>
                    {
                        return self.ensure_chat_dir();
                    }
                    Err(create_error) => return Err(ChatPersistenceError::io(create_error)),
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&self.chat_dir, fs::Permissions::from_mode(0o700))
                        .map_err(ChatPersistenceError::io)?;
                }
            }
            Err(error) => return Err(ChatPersistenceError::io(error)),
        }
        Ok(())
    }

    /// Keep the newest session files. Cleanup is intentionally best-effort.
    pub fn prune(&self) {
        let Ok(entries) = fs::read_dir(&self.chat_dir) else {
            return;
        };
        let active = self.path();
        let mut sessions: Vec<_> = entries
            .flatten()
            .filter_map(|entry| {
                let path = entry.path();
                (path.extension().and_then(|ext| ext.to_str()) == Some("jsonl"))
                    .then(|| {
                        entry
                            .metadata()
                            .ok()
                            .and_then(|metadata| metadata.modified().ok())
                            .map(|time| (time, path))
                    })
                    .flatten()
            })
            .collect();
        let remove_count = sessions.len().saturating_sub(MAX_CHAT_SESSION_FILES);
        sessions.sort_by_key(|(time, path)| (*time, path.clone()));
        for (_, path) in sessions
            .into_iter()
            .filter(|(_, path)| *path != active)
            .take(remove_count)
        {
            let _ = fs::remove_file(path);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatPersistenceError {
    pub message: String,
}

impl ChatPersistenceError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    fn io(error: std::io::Error) -> Self {
        Self::new(format!("chat persistence I/O error: {error}"))
    }

    fn json(error: serde_json::Error) -> Self {
        Self::new(format!("chat persistence serialization error: {error}"))
    }
}

impl From<ChatValidationError> for ChatPersistenceError {
    fn from(error: ChatValidationError) -> Self {
        Self::new(error.to_string())
    }
}

impl fmt::Display for ChatPersistenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ChatPersistenceError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatValidationError {
    InvalidPath,
    InvalidRoot,
    PathOutsideRoot,
    DuplicatePath,
    PathOutsideScope,
    ScopeLimit,
    EmptyScope,
    UnknownScanner,
    IneligibleScanner,
    ScannerNotSelected,
    SupplyChainFocusRequired,
    InvalidExpiry,
    ExpiredProposal,
    SessionMismatch,
    ScannerSetMismatch,
    InvalidSessionId,
    TextLimit,
    UnsupportedSchema,
}

impl fmt::Display for ChatValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidPath => "invalid repository-relative path",
            Self::InvalidRoot => "invalid repository root",
            Self::PathOutsideRoot => "chat path resolves outside the repository root",
            Self::DuplicatePath => "duplicate repository path",
            Self::PathOutsideScope => "chat path is outside the incremental scope",
            Self::ScopeLimit => "focus scope exceeds its fixed limit",
            Self::EmptyScope => "focus scope must contain a fragment or path",
            Self::UnknownScanner => "unknown scanner type",
            Self::IneligibleScanner => "scanner cannot be targeted by chat focus",
            Self::ScannerNotSelected => "scanner is not selected for this scan",
            Self::SupplyChainFocusRequired => "supply-chain focus requires dependency_manifest",
            Self::InvalidExpiry => "proposal expiry must be after creation and within five minutes",
            Self::ExpiredProposal => "proposal has expired",
            Self::SessionMismatch => "chat session does not match the checkpoint",
            Self::ScannerSetMismatch => "scanner set does not exactly match the checkpoint",
            Self::InvalidSessionId => "invalid chat session identifier",
            Self::TextLimit => "chat text exceeds its fixed limit",
            Self::UnsupportedSchema => "unsupported chat record schema version",
        };
        f.write_str(message)
    }
}

impl std::error::Error for ChatValidationError {}

fn is_phase_two(scanner: ScannerType) -> bool {
    matches!(
        scanner,
        ScannerType::Sast | ScannerType::SupplyChain | ScannerType::ApiScan | ScannerType::IacScan
    )
}

fn canonical_scanners(
    scanners: impl IntoIterator<Item = ScannerType>,
) -> Result<Vec<ScannerType>, ChatValidationError> {
    let mut scanners: Vec<_> = scanners.into_iter().collect();
    scanners.sort_by_key(|scanner| scanner.name());
    scanners.dedup();
    if scanners.is_empty() {
        return Err(ChatValidationError::IneligibleScanner);
    }
    Ok(scanners)
}

fn scanner_from_name(name: &str) -> Result<ScannerType, ChatValidationError> {
    match name {
        "framework" => Ok(ScannerType::FrameworkAnalysis),
        "threat_model" => Ok(ScannerType::ThreatModel),
        "sast" => Ok(ScannerType::Sast),
        "supply_chain" => Ok(ScannerType::SupplyChain),
        "api_scan" => Ok(ScannerType::ApiScan),
        "iac_scan" => Ok(ScannerType::IacScan),
        "report" => Ok(ScannerType::Report),
        _ => Err(ChatValidationError::UnknownScanner),
    }
}

/// Validate an identifier before it is ever interpolated into a session file
/// path. This is shared by chat persistence, checkpoint restoration, and audit
/// storage so the three state stores have the same traversal boundary.
pub(crate) fn validate_session_id(session_id: &str) -> Result<(), ChatValidationError> {
    if session_id.is_empty()
        || session_id.len() > 128
        || !session_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(ChatValidationError::InvalidSessionId);
    }
    Ok(())
}

fn deserialize_chat_text<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let text = String::deserialize(deserializer)?;
    validate_text(&text, MAX_CHAT_TEXT_BYTES, "chat text").map_err(de::Error::custom)?;
    Ok(text)
}

fn deserialize_optional_chat_text<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let text = Option::<String>::deserialize(deserializer)?;
    if let Some(text) = &text {
        validate_text(text, MAX_CHAT_TEXT_BYTES, "chat record text").map_err(de::Error::custom)?;
    }
    Ok(text)
}

fn deserialize_lifecycle_message<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let message = String::deserialize(deserializer)?;
    validate_text(&message, MAX_LIFECYCLE_MESSAGE_BYTES, "chat event message")
        .map_err(de::Error::custom)?;
    Ok(message)
}

fn deserialize_session_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let session_id = String::deserialize(deserializer)?;
    validate_session_id(&session_id).map_err(de::Error::custom)?;
    Ok(session_id)
}

fn deserialize_schema_version<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    let version = u16::deserialize(deserializer)?;
    if version != CHAT_RECORD_SCHEMA_VERSION {
        return Err(de::Error::custom(ChatValidationError::UnsupportedSchema));
    }
    Ok(version)
}

fn validate_text(text: &str, limit: usize, _field: &str) -> Result<(), ChatValidationError> {
    if text.is_empty() || text.len() > limit {
        return Err(ChatValidationError::TextLimit);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> FocusScope {
        FocusScope::from_paths(
            [FocusFragment::InputValidation, FocusFragment::DataFlow],
            ["src\\api.rs".to_string(), "src/main.rs".to_string()],
        )
        .unwrap()
    }

    #[test]
    fn action_schema_round_trip_is_typed_and_canonical() {
        let action =
            ChatAction::focus_and_rerun([ScannerType::IacScan, ScannerType::Sast], scope())
                .unwrap();
        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains("focus_and_rerun"));
        let decoded: ChatAction = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, action);
        assert_eq!(
            decoded.scanners(),
            &[ScannerType::IacScan, ScannerType::Sast],
            "scanner list is sorted by canonical scanner name"
        );
    }

    #[test]
    fn rejects_unknown_scanner_invalid_scope_and_path_traversal() {
        assert!(serde_json::from_str::<ChatAction>(
            r#"{"type":"focus_and_rerun","scanners":["unknown"],"scope":{"fragments":[],"paths":[]}}"#
        )
        .is_err());
        assert!(serde_json::from_str::<FocusScope>(
            r#"{"fragments":[],"paths":["../Cargo.toml"]}"#
        )
        .is_err());
        assert!(
            serde_json::from_str::<FocusScope>(r#"{"fragments":[],"paths":["src\\main.rs"]}"#)
                .is_err()
        );
        let too_many = format!(
            r#"{{"fragments":[],"paths":[{}]}}"#,
            (0..=MAX_FOCUS_PATHS)
                .map(|i| format!("\"src/{i}.rs\""))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(serde_json::from_str::<FocusScope>(&too_many).is_err());
        let oversized = "x".repeat(MAX_CHAT_TEXT_BYTES + 1);
        assert!(serde_json::from_value::<ChatCommand>(serde_json::json!({
            "type": "ask",
            "request_id": Uuid::new_v4(),
            "text": oversized,
        }))
        .is_err());
    }

    #[test]
    fn coalesced_supply_chain_requires_dependency_focus_and_selected_scanner() {
        let supply = ChatAction::focus_and_rerun([ScannerType::SupplyChain], scope()).unwrap();
        assert_eq!(
            ChatAction::validate_coalesced_plan(&[&supply], &[ScannerType::SupplyChain]),
            Err(ChatValidationError::SupplyChainFocusRequired)
        );
        let category = ChatAction::prioritize(VulnerabilityCategory::DependencySupplyChain);
        assert!(ChatAction::validate_coalesced_plan(
            &[&supply, &category],
            &[ScannerType::SupplyChain]
        )
        .is_ok());
        let action = ChatAction::focus_and_rerun([ScannerType::Sast], scope()).unwrap();
        assert_eq!(
            action.validate_for_selected(&[ScannerType::ApiScan]),
            Err(ChatValidationError::ScannerNotSelected)
        );
    }

    #[test]
    fn redacts_sensitive_chat_text() {
        let redacted =
            crate::logging::redact("password=hunter2 bearer abc.def sk-ant-SUPERSECRET123");
        assert!(!redacted.contains("hunter2"));
        assert!(!redacted.contains("abc.def"));
        assert!(!redacted.contains("SUPERSECRET123"));
    }

    #[test]
    fn rejects_empty_scope_and_accepts_unsorted_subset() {
        assert_eq!(
            FocusScope::new([], []),
            Err(ChatValidationError::EmptyScope)
        );
        let scope = FocusScope::from_paths([], ["src/a.rs".to_string()]).unwrap();
        let allowed = vec![
            NormalizedRepoPath::normalize("src/z.rs").unwrap(),
            NormalizedRepoPath::normalize("src/a.rs").unwrap(),
        ];
        assert!(scope.validate_subset_of(&allowed).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn root_validation_rejects_symlink_escape() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), root.path().join("linked")).unwrap();
        let escaped = NormalizedRepoPath::normalize("linked/secret.txt").unwrap();
        assert_eq!(
            escaped.validate_within_root(root.path()),
            Err(ChatValidationError::PathOutsideRoot)
        );
    }

    #[test]
    fn proposal_validation_enforces_lifetime_and_expiry() {
        let now = Utc::now();
        let action = ChatAction::focus_and_rerun([ScannerType::Sast], scope()).unwrap();
        let proposal = ActionProposal {
            proposal_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            action,
            created_at: now,
            expires_at: now + chrono::Duration::minutes(6),
            earliest_boundary: PhaseBoundary::AfterFramework,
        };
        assert_eq!(
            proposal.validate_at(now, &[ScannerType::Sast]),
            Err(ChatValidationError::InvalidExpiry)
        );
        let expired = ActionProposal {
            created_at: now - chrono::Duration::minutes(2),
            expires_at: now - chrono::Duration::seconds(1),
            ..proposal
        };
        assert_eq!(
            expired.validate_at(now, &[ScannerType::Sast]),
            Err(ChatValidationError::ExpiredProposal)
        );
    }

    #[test]
    fn store_appends_redacted_jsonl_and_prunes_sessions() {
        let tmp = tempfile::tempdir().unwrap();
        for i in 0..=MAX_CHAT_SESSION_FILES {
            let session = format!("session-{i}");
            let store = ChatStore::new(tmp.path(), session.clone()).unwrap();
            let record = ChatRecord::new(
                session,
                Some(Uuid::new_v4()),
                None,
                ChatLifecycle::Request {
                    state: RequestLifecycle::Queued,
                },
                Some("token=secret-value".to_string()),
                None,
            )
            .unwrap();
            store.append(&record).unwrap();
        }
        let chat_dir = tmp.path().join("chat");
        let files = fs::read_dir(&chat_dir).unwrap().count();
        assert_eq!(files, MAX_CHAT_SESSION_FILES);
        let content = fs::read_to_string(chat_dir.join("session-20.jsonl")).unwrap();
        assert!(!content.contains("secret-value"));
        assert!(content.contains("token=***"));
    }

    #[test]
    fn store_rejects_session_path_traversal_and_mismatched_records() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(ChatStore::new(tmp.path(), "../escape").is_err());
        let store = ChatStore::new(tmp.path(), "safe-session").unwrap();
        let record = ChatRecord::new(
            "other-session".to_string(),
            None,
            None,
            ChatLifecycle::Request {
                state: RequestLifecycle::Queued,
            },
            None,
            None,
        )
        .unwrap();
        assert!(store.append(&record).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn store_rejects_symlinked_chat_dir_and_target() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let store = ChatStore::new(tmp.path(), "safe-session").unwrap();
        symlink(outside.path(), tmp.path().join("chat")).unwrap();
        let record = ChatRecord::new(
            "safe-session".to_string(),
            None,
            None,
            ChatLifecycle::Request {
                state: RequestLifecycle::Queued,
            },
            None,
            None,
        )
        .unwrap();
        assert!(store.append(&record).is_err());

        fs::remove_file(tmp.path().join("chat")).unwrap();
        fs::create_dir(tmp.path().join("chat")).unwrap();
        symlink(outside.path().join("target"), store.path()).unwrap();
        assert!(store.append(&record).is_err());
    }

    #[test]
    fn pruning_preserves_active_session_on_timestamp_ties() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ChatStore::new(tmp.path(), "active").unwrap();
        fs::create_dir(tmp.path().join("chat")).unwrap();
        for i in 0..=MAX_CHAT_SESSION_FILES {
            fs::write(
                tmp.path().join("chat").join(format!("old-{i}.jsonl")),
                "{}\n",
            )
            .unwrap();
        }
        fs::write(store.path(), "{}\n").unwrap();
        store.prune();
        assert!(store.path().exists());
        assert_eq!(
            fs::read_dir(tmp.path().join("chat")).unwrap().count(),
            MAX_CHAT_SESSION_FILES
        );
    }

    #[test]
    fn clone_writes_are_serialized_into_valid_jsonl() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ChatStore::new(tmp.path(), "shared").unwrap();
        let mut workers = Vec::new();
        for _ in 0..8 {
            let clone = store.clone();
            workers.push(std::thread::spawn(move || {
                let record = ChatRecord::new(
                    "shared".to_string(),
                    Some(Uuid::new_v4()),
                    None,
                    ChatLifecycle::Request {
                        state: RequestLifecycle::Queued,
                    },
                    Some("question".to_string()),
                    None,
                )
                .unwrap();
                clone.append(&record).unwrap();
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        let content = fs::read_to_string(store.path()).unwrap();
        let lines: Vec<_> = content.lines().collect();
        assert_eq!(lines.len(), 8);
        assert!(lines
            .iter()
            .all(|line| serde_json::from_str::<ChatRecord>(line).is_ok()));
    }

    #[test]
    fn confirmed_action_round_trips_without_transcript() {
        let action = ConfirmedChatAction::new(
            Uuid::new_v4(),
            2,
            ChatAction::focus_and_rerun([ScannerType::Sast], scope()).unwrap(),
            [ScannerType::Sast],
        )
        .unwrap();
        let json = serde_json::to_string(&action).unwrap();
        assert!(!json.contains("transcript"));
        assert_eq!(
            serde_json::from_str::<ConfirmedChatAction>(&json).unwrap(),
            action
        );
    }
}
