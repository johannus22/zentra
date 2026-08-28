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
use tokio::sync::oneshot;
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
/// Bound transcript replay before allocation. Terminal lifecycle lookup only
/// needs the recent bounded history used by the coordinator retry path.
pub const MAX_CHAT_REPLAY_BYTES: u64 = (MAX_CHAT_RECORD_BYTES * MAX_CHAT_TURNS * 4) as u64;
pub const CHAT_RECORD_SCHEMA_VERSION: u16 = 1;
pub const MAX_CHAT_TURNS: usize = 12;

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

    /// Deterministic applicability table. Categories can influence only an
    /// analyzer which is already selected by the scan; this table never causes
    /// an otherwise unselected scanner to start.
    pub fn applicable_scanners(self) -> &'static [ScannerType] {
        match self {
            Self::AuthenticationAuthorization => &[ScannerType::Sast, ScannerType::ApiScan],
            Self::Injection => &[ScannerType::Sast, ScannerType::ApiScan],
            Self::SensitiveDataExposure => &[ScannerType::Sast, ScannerType::ApiScan],
            Self::DependencySupplyChain => &[ScannerType::SupplyChain],
            Self::InfrastructureMisconfiguration => &[ScannerType::IacScan],
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

/// Typed, canonical focus passed to a new scanner instance.  It deliberately
/// stores no model/UI supplied prompt text; rendering is fixed below.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChatFocus {
    pub categories: BTreeSet<VulnerabilityCategory>,
    pub fragments: BTreeSet<FocusFragment>,
    pub paths: Vec<NormalizedRepoPath>,
}

impl ChatFocus {
    pub fn merge_scope(&mut self, scope: &FocusScope) {
        self.fragments.extend(scope.fragments.iter().copied());
        self.paths.extend(scope.paths.iter().cloned());
        self.paths.sort();
        self.paths.dedup();
    }

    /// The only Chat Focus prompt rendering path. All content comes from closed
    /// enums or normalized repository paths.
    pub fn render(&self) -> Option<String> {
        if self.categories.is_empty() && self.fragments.is_empty() && self.paths.is_empty() {
            return None;
        }
        let mut lines = Vec::new();
        for category in &self.categories {
            lines.push(category.prompt_fragment().to_string());
        }
        if !self.fragments.is_empty() {
            lines.push(format!(
                "Review these bounded areas: {}.",
                self.fragments
                    .iter()
                    .map(|fragment| fragment.prompt_fragment())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if !self.paths.is_empty() {
            lines.push(format!(
                "Prioritize these repository paths:\n{}",
                self.paths
                    .iter()
                    .map(|path| format!("- {path}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ));
        }
        Some(lines.join("\n"))
    }
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

    /// Legacy action-only compatibility validation. New confirmation paths use
    /// [`plan_confirmed_chat_actions`] over durable confirmed actions instead.
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

impl Default for PhaseBoundary {
    fn default() -> Self {
        Self::AfterFramework
    }
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
    /// The operator confirmed a proposal and it was durably queued for the
    /// next orchestration boundary. This is deliberately separate from
    /// `Applied`, which remains owned by the phase loop.
    Confirmed {
        proposal_id: Uuid,
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

/// Terminal result emitted by the orchestrator and consumed by the coordinator.
/// It is intentionally not a ScanEvent: chat lifecycle cannot couple CI or the
/// scan event's exhaustive consumers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChatActionOutcome {
    Applied {
        proposal_id: Uuid,
        boundary: PhaseBoundary,
    },
    Deferred {
        proposal_id: Uuid,
        reason: String,
    },
}

/// A non-persistent, acknowledged handoff from the phase loop to the chat
/// coordinator.  The action snapshot prevents a stale proposal ID from
/// terminally resolving different durable work.
#[derive(Debug)]
pub struct ChatActionOutcomeEnvelope {
    pub expected: ConfirmedChatAction,
    pub outcome: ChatActionOutcome,
    pub ack: oneshot::Sender<Result<ChatOutcomeAck, ChatOutcomeFailure>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatOutcomeAck {
    Committed,
    Duplicate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChatOutcomeFailure {
    MismatchedAction,
    AppliedBeforeCompletion,
    Persistence,
    CoordinatorUnavailable,
}

impl fmt::Display for ChatOutcomeFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MismatchedAction => "chat action no longer matches durable state",
            Self::AppliedBeforeCompletion => "chat action still has unfinished scanners",
            Self::Persistence => "chat action outcome could not be persisted",
            Self::CoordinatorUnavailable => "chat outcome coordinator is unavailable",
        })
    }
}

impl std::error::Error for ChatOutcomeFailure {}

/// The bounded, serialisable view of a running scan that chat may receive.
/// It intentionally contains summaries and normalized names only: scanner
/// histories, raw source, credentials, and provider material never belong here.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatSnapshot {
    pub session_id: String,
    pub boundary: PhaseBoundary,
    pub selected_scanners: Vec<String>,
    #[serde(default)]
    pub scanner_status: Vec<ChatScannerStatus>,
    #[serde(default)]
    pub checkpoint_completed: Vec<String>,
    #[serde(default)]
    pub findings_summary: String,
    #[serde(default)]
    pub coverage_summary: String,
    #[serde(default)]
    pub architecture_context_hash: Option<String>,
    #[serde(default)]
    pub incremental_summary: Option<String>,
    #[serde(default)]
    pub incremental_paths: Vec<String>,
    #[serde(default)]
    pub focus_fragments: Vec<FocusFragment>,
    /// Whether a confirmation may still enter the scan's last mutable boundary.
    #[serde(default)]
    pub action_eligible: bool,
    /// Bounded count of durable actions awaiting scanner progress.
    #[serde(default)]
    pub pending_action_count: usize,
}

impl Default for ChatSnapshot {
    fn default() -> Self {
        Self {
            session_id: "chat-default".to_string(),
            boundary: PhaseBoundary::default(),
            selected_scanners: Vec::new(),
            scanner_status: Vec::new(),
            checkpoint_completed: Vec::new(),
            findings_summary: String::new(),
            coverage_summary: String::new(),
            architecture_context_hash: None,
            incremental_summary: None,
            incremental_paths: Vec::new(),
            focus_fragments: Vec::new(),
            action_eligible: true,
            pending_action_count: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatScannerStatus {
    pub scanner: String,
    pub status: ChatScannerState,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChatScannerState {
    NotStarted,
    Running,
    Completed,
    Failed,
}

/// Redacted, compact conversational context passed between independent chat
/// completions. It is not scanner history and is never checkpointed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatTurn {
    pub request_id: Uuid,
    pub request: String,
    pub response: String,
}

impl ChatSnapshot {
    /// Defensively cap caller-provided summaries before they enter the provider
    /// context. Snapshot construction is outside this module, so this keeps an
    /// accidentally verbose status producer from defeating chat's small budget.
    pub fn bounded(mut self) -> Self {
        const MAX_SUMMARY_CHARS: usize = 4096;
        const MAX_NAMES: usize = 32;
        const MAX_PATHS: usize = 20;
        fn cap(value: &mut String, max: usize) {
            if value.chars().count() > max {
                *value = value.chars().take(max).collect();
            }
        }
        self.selected_scanners.truncate(MAX_NAMES);
        self.scanner_status.truncate(MAX_NAMES);
        self.checkpoint_completed.truncate(MAX_NAMES);
        self.incremental_paths.truncate(MAX_PATHS);
        self.focus_fragments.truncate(MAX_FOCUS_FRAGMENTS);
        cap(&mut self.findings_summary, MAX_SUMMARY_CHARS);
        cap(&mut self.coverage_summary, MAX_SUMMARY_CHARS);
        if let Some(summary) = &mut self.incremental_summary {
            cap(summary, MAX_SUMMARY_CHARS);
        }
        for value in self
            .selected_scanners
            .iter_mut()
            .chain(self.checkpoint_completed.iter_mut())
            .chain(self.incremental_paths.iter_mut())
        {
            cap(value, MAX_PATH_BYTES);
        }
        for status in &mut self.scanner_status {
            cap(&mut status.scanner, MAX_PATH_BYTES);
        }
        self
    }

    /// Validate and cap every externally assembled field before provider use.
    /// Caps are bytes (not Unicode scalar values) and preserve UTF-8 boundaries.
    pub fn try_bounded(mut self) -> Result<Self, ChatValidationError> {
        validate_session_id(&self.session_id)?;
        if let Some(hash) = &self.architecture_context_hash {
            if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(ChatValidationError::InvalidPath);
            }
        }
        fn cap(value: &mut String, max: usize) {
            if value.len() > max {
                let mut end = max;
                while !value.is_char_boundary(end) {
                    end -= 1;
                }
                value.truncate(end);
            }
            *value = crate::logging::redact(value);
        }
        self.selected_scanners.truncate(32);
        self.scanner_status.truncate(32);
        self.checkpoint_completed.truncate(32);
        self.incremental_paths.truncate(20);
        self.focus_fragments.truncate(MAX_FOCUS_FRAGMENTS);
        cap(&mut self.findings_summary, 4096);
        cap(&mut self.coverage_summary, 4096);
        if let Some(summary) = &mut self.incremental_summary {
            cap(summary, 4096);
        }
        for value in self
            .selected_scanners
            .iter_mut()
            .chain(self.checkpoint_completed.iter_mut())
            .chain(self.incremental_paths.iter_mut())
        {
            cap(value, MAX_PATH_BYTES);
        }
        for status in &mut self.scanner_status {
            cap(&mut status.scanner, MAX_PATH_BYTES);
        }
        Ok(self)
    }
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
    /// Targets still requiring a successful scanner run. Older checkpoint
    /// records omit it; deserialization derives the canonical action targets.
    pub remaining_scanners: Vec<ScannerType>,
}

/// One scanner-specific target in a coalesced, confirmed chat plan.  The
/// proposal IDs are in confirmation order and make the dependency from a
/// proposal to the scanner which must complete explicit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatFocusTarget {
    pub scanner: ScannerType,
    pub focus: ChatFocus,
    pub proposal_ids: Vec<Uuid>,
}

/// The ordered scanner membership for one confirmed proposal.  This is kept in
/// addition to [`ChatFocusTarget::proposal_ids`] so callers can account for a
/// proposal exactly once without reverse-engineering a merged focus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatProposalTargets {
    pub proposal_id: Uuid,
    pub confirmation_sequence: u64,
    pub scanners: Vec<ScannerType>,
}

/// A deterministic, bounded plan for applying confirmed chat actions at an
/// orchestration boundary.  `targets` is sorted by canonical scanner name;
/// `proposals` is sorted by confirmation sequence.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CoalescedChatPlan {
    pub targets: Vec<ChatFocusTarget>,
    pub proposals: Vec<ChatProposalTargets>,
}

impl CoalescedChatPlan {
    pub fn target(&self, scanner: ScannerType) -> Option<&ChatFocusTarget> {
        self.targets.iter().find(|target| target.scanner == scanner)
    }
}

/// The fixed limit violated by a merged focus.  These variants deliberately do
/// not include caller-provided text or paths so they remain safe for lifecycle
/// messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatFocusLimit {
    PathCount,
    PathBytes,
    FragmentCount,
    FragmentBytes,
    RenderedBytes,
}

/// Typed failure for [`plan_confirmed_chat_actions`].  [`Self::user_reason`]
/// is fixed, bounded text suitable for a deferred chat lifecycle event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChatPlanError {
    DuplicateProposalId {
        proposal_id: Uuid,
    },
    DuplicateConfirmationSequence {
        confirmation_sequence: u64,
    },
    ScannerSetMismatch {
        proposal_id: Uuid,
    },
    InvalidAction {
        proposal_id: Uuid,
        error: ChatValidationError,
    },
    NoApplicableSelectedScanner {
        proposal_id: Uuid,
        category: VulnerabilityCategory,
    },
    SupplyChainCategoryRequired {
        proposal_id: Uuid,
    },
    MergedFocusLimit {
        scanner: ScannerType,
        limit: ChatFocusLimit,
    },
}

impl ChatPlanError {
    pub const fn user_reason(&self) -> &'static str {
        match self {
            Self::DuplicateProposalId { .. } => "duplicate confirmed chat proposal",
            Self::DuplicateConfirmationSequence { .. } => "duplicate chat confirmation sequence",
            Self::ScannerSetMismatch { .. } => {
                "chat action scanner set no longer matches this scan"
            }
            Self::InvalidAction { .. } => "confirmed chat action is no longer valid",
            Self::NoApplicableSelectedScanner { .. } => {
                "vulnerability category has no applicable selected scanner"
            }
            Self::SupplyChainCategoryRequired { .. } => {
                "supply-chain focus requires dependency_supply_chain category context"
            }
            Self::MergedFocusLimit { .. } => "merged chat focus exceeds its fixed limit",
        }
    }
}

impl fmt::Display for ChatPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.user_reason())
    }
}

impl std::error::Error for ChatPlanError {}

/// Build an ordered, scanner-coalesced plan from confirmed actions.
///
/// This is intentionally pure: it has no TUI, event, checkpoint, or scanner
/// dependencies.  It validates the durable scanner set for every action,
/// rejects ambiguous ordering, and validates the completed merged targets
/// rather than truncating them.
pub fn plan_confirmed_chat_actions(
    actions: &[ConfirmedChatAction],
    selected_scanners: &[ScannerType],
) -> Result<CoalescedChatPlan, ChatPlanError> {
    let selected = canonical_scanners(selected_scanners.iter().copied()).map_err(|error| {
        ChatPlanError::InvalidAction {
            proposal_id: Uuid::nil(),
            error,
        }
    })?;
    let mut proposal_ids = BTreeSet::new();
    let mut sequences = BTreeSet::new();
    for confirmed in actions {
        if !proposal_ids.insert(confirmed.proposal_id) {
            return Err(ChatPlanError::DuplicateProposalId {
                proposal_id: confirmed.proposal_id,
            });
        }
        if !sequences.insert(confirmed.confirmation_sequence) {
            return Err(ChatPlanError::DuplicateConfirmationSequence {
                confirmation_sequence: confirmed.confirmation_sequence,
            });
        }
    }

    let mut ordered = actions.to_vec();
    ordered.sort_by_key(|confirmed| confirmed.confirmation_sequence);
    let mut plan = CoalescedChatPlan::default();

    for confirmed in ordered {
        validate_confirmed_action_for_plan(&confirmed, &selected)?;
        let targets = targets_for_action(&confirmed, &selected)?;
        plan.proposals.push(ChatProposalTargets {
            proposal_id: confirmed.proposal_id,
            confirmation_sequence: confirmed.confirmation_sequence,
            scanners: targets.clone(),
        });

        for scanner in targets {
            let target = match plan
                .targets
                .iter_mut()
                .find(|target| target.scanner == scanner)
            {
                Some(target) => target,
                None => {
                    plan.targets.push(ChatFocusTarget {
                        scanner,
                        focus: ChatFocus::default(),
                        proposal_ids: Vec::new(),
                    });
                    plan.targets.last_mut().expect("target was just pushed")
                }
            };
            target.proposal_ids.push(confirmed.proposal_id);
            match &confirmed.action {
                ChatAction::FocusAndRerun { scope, .. } => target.focus.merge_scope(scope),
                ChatAction::PrioritizeVulnerability { category } => {
                    target.focus.categories.insert(*category);
                }
            }
        }
    }

    plan.targets.sort_by_key(|target| target.scanner.name());
    for target in &plan.targets {
        validate_merged_target(target)?;
    }
    Ok(plan)
}

fn validate_confirmed_action_for_plan(
    confirmed: &ConfirmedChatAction,
    selected: &[ScannerType],
) -> Result<(), ChatPlanError> {
    if confirmed.required_scanners != selected {
        return Err(ChatPlanError::ScannerSetMismatch {
            proposal_id: confirmed.proposal_id,
        });
    }
    confirmed
        .action
        .validate_for_selected(selected)
        .map_err(|error| ChatPlanError::InvalidAction {
            proposal_id: confirmed.proposal_id,
            error,
        })?;
    if let ChatAction::FocusAndRerun { scanners, scope } = &confirmed.action {
        let canonical = canonical_scanners(scanners.iter().copied()).map_err(|error| {
            ChatPlanError::InvalidAction {
                proposal_id: confirmed.proposal_id,
                error,
            }
        })?;
        if scanners != &canonical || scanners.iter().any(|scanner| !is_phase_two(*scanner)) {
            return Err(ChatPlanError::InvalidAction {
                proposal_id: confirmed.proposal_id,
                error: ChatValidationError::IneligibleScanner,
            });
        }
        let canonical_scope =
            FocusScope::new(scope.fragments.iter().copied(), scope.paths.iter().cloned()).map_err(
                |error| ChatPlanError::InvalidAction {
                    proposal_id: confirmed.proposal_id,
                    error,
                },
            )?;
        if scope != &canonical_scope {
            return Err(ChatPlanError::InvalidAction {
                proposal_id: confirmed.proposal_id,
                error: ChatValidationError::DuplicatePath,
            });
        }
    }
    Ok(())
}

fn targets_for_action(
    confirmed: &ConfirmedChatAction,
    selected: &[ScannerType],
) -> Result<Vec<ScannerType>, ChatPlanError> {
    let all = match &confirmed.action {
        ChatAction::FocusAndRerun { scanners, .. } => scanners.clone(),
        ChatAction::PrioritizeVulnerability { category } => {
            let targets: Vec<_> = category
                .applicable_scanners()
                .iter()
                .filter(|scanner| selected.contains(scanner) && is_phase_two(**scanner))
                .copied()
                .collect();
            if targets.is_empty() {
                return Err(ChatPlanError::NoApplicableSelectedScanner {
                    proposal_id: confirmed.proposal_id,
                    category: *category,
                });
            } else {
                targets
            }
        }
    };
    if confirmed
        .remaining_scanners
        .iter()
        .any(|scanner| !all.contains(scanner))
    {
        return Err(ChatPlanError::InvalidAction {
            proposal_id: confirmed.proposal_id,
            error: ChatValidationError::IneligibleScanner,
        });
    }
    Ok(all
        .into_iter()
        .filter(|scanner| confirmed.remaining_scanners.contains(scanner))
        .collect())
}

fn action_targets(
    action: &ChatAction,
    selected: &[ScannerType],
) -> Result<Vec<ScannerType>, ChatValidationError> {
    match action {
        ChatAction::FocusAndRerun { scanners, .. } => Ok(scanners.clone()),
        ChatAction::PrioritizeVulnerability { category } => {
            let targets: Vec<_> = category
                .applicable_scanners()
                .iter()
                .filter(|scanner| selected.contains(scanner) && is_phase_two(**scanner))
                .copied()
                .collect();
            Ok(targets)
        }
    }
}

fn validate_merged_target(target: &ChatFocusTarget) -> Result<(), ChatPlanError> {
    let limit_error = |limit| ChatPlanError::MergedFocusLimit {
        scanner: target.scanner,
        limit,
    };
    if target.focus.paths.len() > MAX_FOCUS_PATHS {
        return Err(limit_error(ChatFocusLimit::PathCount));
    }
    if target
        .focus
        .paths
        .iter()
        .map(|path| path.as_str().len())
        .sum::<usize>()
        > MAX_FOCUS_PATHS * MAX_PATH_BYTES
    {
        return Err(limit_error(ChatFocusLimit::PathBytes));
    }
    if target.focus.fragments.len() > MAX_FOCUS_FRAGMENTS {
        return Err(limit_error(ChatFocusLimit::FragmentCount));
    }
    if target
        .focus
        .fragments
        .iter()
        .map(|fragment| fragment.prompt_fragment().len())
        .sum::<usize>()
        > MAX_CHAT_TEXT_BYTES
    {
        return Err(limit_error(ChatFocusLimit::FragmentBytes));
    }
    if target
        .focus
        .render()
        .is_some_and(|rendered| rendered.len() > MAX_CHAT_TEXT_BYTES)
    {
        return Err(limit_error(ChatFocusLimit::RenderedBytes));
    }
    if target.scanner == ScannerType::SupplyChain
        && !target
            .focus
            .fragments
            .contains(&FocusFragment::DependencyManifest)
        && !target
            .focus
            .categories
            .contains(&VulnerabilityCategory::DependencySupplyChain)
    {
        return Err(ChatPlanError::SupplyChainCategoryRequired {
            proposal_id: target.proposal_ids[0],
        });
    }
    Ok(())
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
        let remaining_scanners = action_targets(&action, &required_scanners)?;
        Ok(Self {
            proposal_id,
            confirmation_sequence,
            action,
            required_scanners,
            remaining_scanners,
        })
    }

    pub fn validate_for_resume(&self, selected: &[ScannerType]) -> Result<(), ChatValidationError> {
        self.action.validate_for_selected(selected)?;
        let selected = canonical_scanners(selected.iter().copied())?;
        if self.required_scanners != selected {
            return Err(ChatValidationError::ScannerSetMismatch);
        }
        let targets = action_targets(&self.action, &selected)?;
        let remaining = if self.remaining_scanners.is_empty() {
            Vec::new()
        } else {
            canonical_scanners(self.remaining_scanners.iter().copied())?
        };
        if remaining != self.remaining_scanners
            || remaining.iter().any(|scanner| !targets.contains(scanner))
        {
            return Err(ChatValidationError::IneligibleScanner);
        }
        Ok(())
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
            remaining_scanners: Vec<&'static str>,
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
            remaining_scanners: self
                .remaining_scanners
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
            #[serde(default)]
            remaining_scanners: Option<Vec<String>>,
        }
        let raw = Raw::deserialize(deserializer)?;
        let mut confirmed = ConfirmedChatAction::new(
            raw.proposal_id,
            raw.confirmation_sequence,
            raw.action,
            raw.required_scanners
                .iter()
                .map(|scanner| scanner_from_name(scanner))
                .collect::<Result<Vec<_>, _>>()
                .map_err(de::Error::custom)?,
        )
        .map_err(de::Error::custom)?;
        if let Some(remaining_scanners) = raw.remaining_scanners {
            confirmed.remaining_scanners = if remaining_scanners.is_empty() {
                Vec::new()
            } else {
                canonical_scanners(
                    remaining_scanners
                        .iter()
                        .map(|scanner| scanner_from_name(scanner))
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(de::Error::custom)?,
                )
                .map_err(de::Error::custom)?
            };
        }
        Ok(confirmed)
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
        default,
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

    /// Immutable lifecycle identity. Coordinator persistence must not depend
    /// on a live snapshot lock, which can be poisoned by UI code.
    pub fn session_id(&self) -> &str {
        &self.session_id
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

    /// Return the already durable terminal state for a proposal. This bounded
    /// lookup is used to make a retry after transcript success idempotent.
    pub fn terminal_proposal_lifecycle(
        &self,
        proposal_id: Uuid,
    ) -> Result<Option<ProposalLifecycle>, ChatPersistenceError> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| ChatPersistenceError::new("chat store write lock poisoned"))?;
        let path = self.path();
        match fs::symlink_metadata(&path) {
            Ok(metadata)
                if metadata.file_type().is_symlink() || !metadata.file_type().is_file() =>
            {
                return Err(ChatPersistenceError::new(
                    "chat target is not a regular file",
                ));
            }
            Ok(metadata) if metadata.len() > MAX_CHAT_REPLAY_BYTES => {
                return Err(ChatPersistenceError::new(
                    "chat transcript exceeds replay limit",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(ChatPersistenceError::io(error)),
        }
        let contents = match fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(error) => return Err(ChatPersistenceError::io(error)),
        };
        // A session is bounded by record-size limits; cap this defensive replay
        // scan as well rather than accepting an unbounded hostile transcript.
        let mut found = None;
        for line in contents.lines().rev().take(MAX_CHAT_TURNS * 4) {
            let Ok(record) = serde_json::from_str::<ChatRecord>(line) else {
                continue;
            };
            if record.proposal_id != Some(proposal_id) {
                continue;
            }
            if let ChatLifecycle::Proposal { state } = record.lifecycle {
                if matches!(
                    state,
                    ProposalLifecycle::Applied | ProposalLifecycle::Deferred
                ) {
                    found = Some(state);
                    break;
                }
            }
        }
        Ok(found)
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

    #[test]
    fn terminal_lifecycle_lookup_rejects_oversize_transcript_before_replay() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ChatStore::new(tmp.path(), "safe-session").unwrap();
        fs::create_dir(tmp.path().join("chat")).unwrap();
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(store.path())
            .unwrap();
        file.set_len(MAX_CHAT_REPLAY_BYTES + 1).unwrap();
        assert!(store.terminal_proposal_lifecycle(Uuid::new_v4()).is_err());
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
        assert!(store.terminal_proposal_lifecycle(Uuid::new_v4()).is_err());
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

    #[test]
    fn confirmed_action_preserves_explicit_empty_progress_but_derives_legacy_progress() {
        let selected = [ScannerType::Sast];
        let mut action = ConfirmedChatAction::new(
            Uuid::new_v4(),
            2,
            ChatAction::focus_and_rerun([ScannerType::Sast], scope()).unwrap(),
            selected,
        )
        .unwrap();
        action.remaining_scanners.clear();
        let json = serde_json::to_string(&action).unwrap();
        let restored: ConfirmedChatAction = serde_json::from_str(&json).unwrap();
        assert!(restored.remaining_scanners.is_empty());
        assert!(plan_confirmed_chat_actions(&[restored], &selected)
            .unwrap()
            .proposals[0]
            .scanners
            .is_empty());

        let legacy = json.replace(",\"remaining_scanners\":[]", "");
        let restored: ConfirmedChatAction = serde_json::from_str(&legacy).unwrap();
        assert_eq!(restored.remaining_scanners, vec![ScannerType::Sast]);
    }

    fn confirmed(
        id: u128,
        sequence: u64,
        action: ChatAction,
        selected: &[ScannerType],
    ) -> ConfirmedChatAction {
        ConfirmedChatAction::new(
            Uuid::from_u128(id),
            sequence,
            action,
            selected.iter().copied(),
        )
        .unwrap()
    }

    fn paths_scope(start: usize, count: usize) -> FocusScope {
        FocusScope::from_paths(
            [],
            (start..start + count)
                .map(|index| format!("src/{index}.rs"))
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    #[test]
    fn planner_rejects_category_without_an_applicable_selected_scanner() {
        let selected = [ScannerType::IacScan];
        let action = confirmed(
            1,
            1,
            ChatAction::prioritize(VulnerabilityCategory::Injection),
            &selected,
        );

        assert_eq!(
            plan_confirmed_chat_actions(&[action], &selected),
            Err(ChatPlanError::NoApplicableSelectedScanner {
                proposal_id: Uuid::from_u128(1),
                category: VulnerabilityCategory::Injection,
            })
        );
    }

    #[test]
    fn planner_rejects_duplicate_ids_and_confirmation_sequences() {
        let selected = [ScannerType::Sast];
        let first = confirmed(
            2,
            1,
            ChatAction::focus_and_rerun([ScannerType::Sast], scope()).unwrap(),
            &selected,
        );
        let duplicate_id = confirmed(
            2,
            2,
            ChatAction::focus_and_rerun([ScannerType::Sast], scope()).unwrap(),
            &selected,
        );
        assert!(matches!(
            plan_confirmed_chat_actions(&[first.clone(), duplicate_id], &selected),
            Err(ChatPlanError::DuplicateProposalId { .. })
        ));

        let duplicate_sequence = confirmed(
            3,
            1,
            ChatAction::focus_and_rerun([ScannerType::Sast], scope()).unwrap(),
            &selected,
        );
        assert!(matches!(
            plan_confirmed_chat_actions(&[first, duplicate_sequence], &selected),
            Err(ChatPlanError::DuplicateConfirmationSequence { .. })
        ));
    }

    #[test]
    fn planner_rejects_per_action_valid_merged_path_and_fragment_limits() {
        let selected = [ScannerType::Sast];
        let path_actions = [
            confirmed(
                4,
                1,
                ChatAction::focus_and_rerun([ScannerType::Sast], paths_scope(0, 11)).unwrap(),
                &selected,
            ),
            confirmed(
                5,
                2,
                ChatAction::focus_and_rerun([ScannerType::Sast], paths_scope(11, 10)).unwrap(),
                &selected,
            ),
        ];
        assert!(matches!(
            plan_confirmed_chat_actions(&path_actions, &selected),
            Err(ChatPlanError::MergedFocusLimit {
                limit: ChatFocusLimit::PathCount,
                ..
            })
        ));

        let fragment_actions = [
            confirmed(
                6,
                1,
                ChatAction::focus_and_rerun(
                    [ScannerType::Sast],
                    FocusScope::new(
                        [
                            FocusFragment::AuthBoundary,
                            FocusFragment::InputValidation,
                            FocusFragment::DataFlow,
                            FocusFragment::SecretsAndSensitiveData,
                        ],
                        [],
                    )
                    .unwrap(),
                )
                .unwrap(),
                &selected,
            ),
            confirmed(
                7,
                2,
                ChatAction::focus_and_rerun(
                    [ScannerType::Sast],
                    FocusScope::new(
                        [
                            FocusFragment::DependencyManifest,
                            FocusFragment::NetworkExposure,
                            FocusFragment::IaCPrivilege,
                        ],
                        [],
                    )
                    .unwrap(),
                )
                .unwrap(),
                &selected,
            ),
        ];
        assert!(matches!(
            plan_confirmed_chat_actions(&fragment_actions, &selected),
            Err(ChatPlanError::MergedFocusLimit {
                limit: ChatFocusLimit::FragmentCount,
                ..
            })
        ));
    }

    #[test]
    fn planner_accepts_supply_chain_manifest_or_category_and_rejects_neither() {
        let selected = [ScannerType::SupplyChain];
        let supply_without_evidence = confirmed(
            8,
            1,
            ChatAction::focus_and_rerun([ScannerType::SupplyChain], scope()).unwrap(),
            &selected,
        );
        assert!(matches!(
            plan_confirmed_chat_actions(std::slice::from_ref(&supply_without_evidence), &selected),
            Err(ChatPlanError::SupplyChainCategoryRequired { .. })
        ));

        let manifest = confirmed(
            9,
            2,
            ChatAction::focus_and_rerun(
                [ScannerType::SupplyChain],
                FocusScope::new([FocusFragment::DependencyManifest], []).unwrap(),
            )
            .unwrap(),
            &selected,
        );
        assert!(plan_confirmed_chat_actions(&[manifest], &selected).is_ok());

        let category = confirmed(
            10,
            3,
            ChatAction::prioritize(VulnerabilityCategory::DependencySupplyChain),
            &selected,
        );
        let plan =
            plan_confirmed_chat_actions(&[supply_without_evidence, category], &selected).unwrap();
        assert!(plan.targets[0]
            .focus
            .categories
            .contains(&VulnerabilityCategory::DependencySupplyChain));
    }

    #[test]
    fn planner_is_input_order_independent_and_preserves_membership() {
        let selected = [ScannerType::Sast, ScannerType::ApiScan];
        let focus = confirmed(
            10,
            2,
            ChatAction::focus_and_rerun([ScannerType::Sast], scope()).unwrap(),
            &selected,
        );
        let category = confirmed(
            11,
            1,
            ChatAction::prioritize(VulnerabilityCategory::AuthenticationAuthorization),
            &selected,
        );
        let forward =
            plan_confirmed_chat_actions(&[focus.clone(), category.clone()], &selected).unwrap();
        let reversed = plan_confirmed_chat_actions(&[category, focus], &selected).unwrap();
        assert_eq!(forward, reversed);
        assert_eq!(
            forward.target(ScannerType::Sast).unwrap().proposal_ids,
            vec![Uuid::from_u128(11), Uuid::from_u128(10)]
        );
        assert_eq!(
            forward
                .proposals
                .iter()
                .map(|proposal| proposal.confirmation_sequence)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    #[test]
    fn planner_collapses_repeated_scanner_targets_and_excludes_unselected_scanners() {
        let selected = [ScannerType::Sast];
        let first = confirmed(
            12,
            1,
            ChatAction::focus_and_rerun([ScannerType::Sast], paths_scope(0, 1)).unwrap(),
            &selected,
        );
        let second = confirmed(
            13,
            2,
            ChatAction::focus_and_rerun([ScannerType::Sast], paths_scope(1, 1)).unwrap(),
            &selected,
        );
        let category = confirmed(
            14,
            3,
            ChatAction::prioritize(VulnerabilityCategory::AuthenticationAuthorization),
            &selected,
        );
        let plan = plan_confirmed_chat_actions(&[second, category, first], &selected).unwrap();

        assert_eq!(plan.targets.len(), 1);
        assert_eq!(plan.targets[0].scanner, ScannerType::Sast);
        assert_eq!(
            plan.targets[0].proposal_ids,
            vec![
                Uuid::from_u128(12),
                Uuid::from_u128(13),
                Uuid::from_u128(14)
            ]
        );
        assert!(plan
            .proposals
            .iter()
            .all(|proposal| proposal.scanners == vec![ScannerType::Sast]));
    }
}
