use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::agent::chat::{
    plan_confirmed_chat_actions, ChatActionOutcome, ChatActionOutcomeEnvelope, ChatFocus,
    ChatOutcomeFailure, ChatScannerState, ChatSnapshot, ConfirmedChatAction, PhaseBoundary,
};
use crate::agent::checkpoint::Checkpoint;
use crate::agent::scanner::ScannerAgent;
use crate::agent::{ScanEvent, ScannerType};
use crate::incremental::{is_arch_significant, reconcile, ChangeSet, ScanDelta};
use crate::provider::LLMProvider;
use crate::security::SecurityContext;
use crate::state::{Finding, StateWriter};
use crate::tools::ToolRegistry;

struct IncrementalCtx {
    prior: Vec<Finding>,
    change_set: ChangeSet,
}

struct ChatBoundaryContext<'a> {
    scanners: &'a [ScannerType],
    checkpoint: &'a mut Checkpoint,
    statuses: &'a HashMap<ScannerType, ChatScannerState>,
    focus: &'a mut HashMap<ScannerType, ChatFocus>,
    focus_members: &'a mut HashMap<ScannerType, Vec<uuid::Uuid>>,
    reruns: &'a mut Vec<ScannerType>,
    force_rerun: bool,
}

pub struct RunSummary {
    pub failed: Vec<ScannerType>,
    pub delta: Option<ScanDelta>,
    /// What the agents actually read. A scan that read almost nothing must not
    /// be indistinguishable from a scan that found nothing.
    pub coverage: crate::agent::coverage::CoverageSummary,
}

/// All-or-nothing bindings for the interactive control plane. Constructing this
/// value is the only supported way to enable chat for an orchestrator run.
pub struct OrchestratorChatRuntime {
    /// The coordinator-owned session identity. This is deliberately independent
    /// of the mutable snapshot and must match the durable checkpoint.
    pub session_id: String,
    pub pending_actions: mpsc::Receiver<ConfirmedChatAction>,
    pub outcome_tx: mpsc::Sender<ChatActionOutcomeEnvelope>,
    pub checkpoint: Arc<Mutex<Checkpoint>>,
    pub snapshot: Arc<Mutex<ChatSnapshot>>,
    /// Closed before the final durable drain. Shared with the coordinator so a
    /// confirmation cannot be stranded behind the final boundary.
    pub action_eligible: Arc<AtomicBool>,
}

const PARALLEL_SCANNERS: &[ScannerType] = &[
    ScannerType::Sast,
    ScannerType::SupplyChain,
    ScannerType::ApiScan,
    ScannerType::IacScan,
];

/// Which files a given scanner is restricted to on an incremental run.
/// SupplyChain is deliberately exempt: dependency CVE status can change with
/// zero local code changes, so scoping it to the diff would silently miss
/// newly-disclosed vulnerabilities in unchanged manifests.
fn incremental_scope_for(scanner_type: ScannerType, change_set: &ChangeSet) -> Option<Vec<String>> {
    match scanner_type {
        ScannerType::Sast | ScannerType::ApiScan | ScannerType::IacScan => {
            Some(change_set.impact.clone())
        }
        _ => None,
    }
}

pub struct OrchestratorAgent {
    provider: Arc<dyn LLMProvider>,
    tool_registry: Arc<ToolRegistry>,
    state_writer: Arc<StateWriter>,
    tx: mpsc::Sender<ScanEvent>,
    cancel_token: CancellationToken,
    focus_context: Option<String>,
    security: SecurityContext,
    incremental: Option<IncrementalCtx>,
    /// The whole filtered repository, when pack mode is on. Every scanner opens
    /// with it instead of navigating, so it is shared behind one Arc.
    pack: Option<Arc<String>>,
    /// Resume checkpoint. `None` means start fresh and write one as the scan
    /// progresses (so a crash enables future resume). `Some(cp)` means skip
    /// scanners that the checkpoint records as completed.
    resume: Option<Checkpoint>,
    board: crate::agent::board::ObservationBoard,
    chat_runtime: Option<OrchestratorChatRuntime>,
    #[cfg(test)]
    test_pipeline_trace: Option<Arc<Mutex<Vec<&'static str>>>>,
}

impl OrchestratorAgent {
    pub fn new(
        provider: Arc<dyn LLMProvider>,
        tool_registry: Arc<ToolRegistry>,
        state_writer: Arc<StateWriter>,
        tx: mpsc::Sender<ScanEvent>,
        cancel_token: CancellationToken,
    ) -> Self {
        Self {
            provider,
            tool_registry,
            state_writer,
            tx,
            cancel_token,
            focus_context: None,
            pack: None,
            security: SecurityContext::disabled(),
            incremental: None,
            resume: None,
            board: crate::agent::board::ObservationBoard::new(),
            chat_runtime: None,
            #[cfg(test)]
            test_pipeline_trace: None,
        }
    }

    pub fn with_focus_context(mut self, focus_context: Option<String>) -> Self {
        self.focus_context = focus_context;
        self
    }

    pub fn with_security(mut self, security: SecurityContext) -> Self {
        self.security = security;
        self
    }

    pub fn with_incremental(mut self, prior: Vec<Finding>, change_set: ChangeSet) -> Self {
        self.incremental = Some(IncrementalCtx { prior, change_set });
        self
    }

    /// Open every scanner with the whole filtered repository instead of a
    /// navigation prompt. The caller checks the budget first - by the time the
    /// pack reaches here it has already been shown to fit.
    pub fn with_pack(mut self, pack: Option<Arc<String>>) -> Self {
        self.pack = pack;
        self
    }

    /// Set the resume checkpoint. Pass `None` for a fresh scan (the orchestrator
    /// creates an empty checkpoint and writes to it as scanners complete). Pass
    /// `Some(cp)` to skip scanners that the checkpoint records as completed.
    pub fn with_resume(mut self, checkpoint: Option<Checkpoint>) -> Self {
        self.resume = checkpoint;
        self
    }

    pub fn with_chat_runtime(mut self, runtime: OrchestratorChatRuntime) -> Self {
        self.chat_runtime = Some(runtime);
        self
    }

    #[cfg(test)]
    fn with_test_pipeline_trace(mut self, trace: Arc<Mutex<Vec<&'static str>>>) -> Self {
        self.test_pipeline_trace = Some(trace);
        self
    }

    #[cfg(test)]
    fn trace_pipeline(&self, phase: &'static str) {
        if let Some(trace) = &self.test_pipeline_trace {
            trace.lock().expect("test trace lock").push(phase);
        }
    }

    fn checkpoint_save(&self, checkpoint: &Checkpoint, zentra_dir: &std::path::Path) -> Result<()> {
        if self.chat_runtime.is_some() {
            // Chat never writes a local checkpoint snapshot over the shared
            // checkpoint. Every mutation goes through one of the strict helpers.
            return Err(anyhow::anyhow!("attempted stale chat checkpoint save"));
        }
        checkpoint.save(zentra_dir);
        Ok(())
    }

    fn shared_checkpoint(&self) -> Result<Checkpoint> {
        self.chat_runtime
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("chat runtime unavailable"))?
            .checkpoint
            .lock()
            .map_err(|_| anyhow::anyhow!("chat checkpoint lock poisoned"))
            .map(|checkpoint| checkpoint.clone())
    }

    fn set_scanner_set_strict(
        &self,
        local: &mut Checkpoint,
        zentra_dir: &std::path::Path,
        scanners: &[ScannerType],
    ) -> Result<()> {
        let mut names: Vec<String> = scanners
            .iter()
            .map(|scanner| scanner.name().to_string())
            .collect();
        names.sort();
        if names.windows(2).any(|pair| pair[0] == pair[1]) {
            anyhow::bail!("chat scanner set contains duplicate scanners");
        }
        if let Some(runtime) = &self.chat_runtime {
            let mut shared = runtime
                .checkpoint
                .lock()
                .map_err(|_| anyhow::anyhow!("chat checkpoint lock poisoned"))?;
            if shared.scanner_set.is_empty() {
                let mut updated = shared.clone();
                updated.scanner_set = names;
                updated.updated_at = chrono::Utc::now().to_rfc3339();
                updated.save_strict(zentra_dir)?;
                *shared = updated;
            } else if shared.scanner_set != names
                || shared.scanner_set.windows(2).any(|pair| pair[0] >= pair[1])
            {
                anyhow::bail!("chat checkpoint scanner set does not match this run");
            }
            *local = shared.clone();
            Ok(())
        } else if local.scanner_set.is_empty() {
            local.scanner_set = names;
            self.checkpoint_save(local, zentra_dir)
        } else {
            Ok(())
        }
    }

    /// Resolve the one authoritative chat checkpoint before any findings state
    /// is recovered or read. A poisoned snapshot is not an identity source: the
    /// caller will fail closed at its first safe boundary instead.
    fn validate_chat_runtime_checkpoint(
        &self,
        local: &mut Checkpoint,
        zentra_dir: &std::path::Path,
    ) -> Result<bool> {
        let Some(runtime) = &self.chat_runtime else {
            return Ok(false);
        };
        crate::agent::chat::validate_session_id(&runtime.session_id)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let mut shared = runtime
            .checkpoint
            .lock()
            .map_err(|_| anyhow::anyhow!("chat checkpoint lock poisoned"))?;
        if shared.session_id.is_empty() {
            if !shared.confirmed_chat_actions.is_empty() {
                anyhow::bail!("chat checkpoint actions have no owning session");
            }
            let mut initialized = shared.clone();
            initialized.session_id = runtime.session_id.clone();
            initialized.updated_at = chrono::Utc::now().to_rfc3339();
            initialized.save_strict(zentra_dir)?;
            *shared = initialized;
        } else if shared.session_id != runtime.session_id {
            anyhow::bail!("chat runtime session does not match checkpoint");
        }
        *local = shared.clone();
        drop(shared);
        match runtime.snapshot.lock() {
            Ok(snapshot) => {
                if snapshot.session_id != runtime.session_id {
                    anyhow::bail!("chat runtime session does not match snapshot");
                }
                Ok(false)
            }
            Err(_) => Ok(true),
        }
    }

    fn checkpoint_mark_completed(
        &self,
        checkpoint: &mut Checkpoint,
        zentra_dir: &std::path::Path,
        scanner: &str,
        proposal_ids: &[uuid::Uuid],
    ) -> Result<Vec<ConfirmedChatAction>> {
        if let Some(shared) = self
            .chat_runtime
            .as_ref()
            .map(|runtime| &runtime.checkpoint)
        {
            let mut shared = shared
                .lock()
                .map_err(|_| anyhow::anyhow!("chat checkpoint lock poisoned"))?;
            let complete =
                shared.complete_chat_scanner_strict(zentra_dir, scanner, proposal_ids)?;
            *checkpoint = shared.clone();
            return Ok(complete);
        }
        checkpoint.completed.insert(scanner.to_string());
        checkpoint.updated_at = chrono::Utc::now().to_rfc3339();
        self.checkpoint_save(checkpoint, zentra_dir)?;
        Ok(Vec::new())
    }

    fn invalidate_chat_targets_strict(
        &self,
        checkpoint: &mut Checkpoint,
        zentra_dir: &std::path::Path,
        targets: &[ScannerType],
    ) -> Result<BTreeSet<String>> {
        if targets.is_empty() {
            return Ok(BTreeSet::new());
        }
        let runtime = self
            .chat_runtime
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("chat runtime unavailable"))?;
        let mut shared = runtime
            .checkpoint
            .lock()
            .map_err(|_| anyhow::anyhow!("chat checkpoint lock poisoned"))?;
        let mut removed = BTreeSet::new();
        for scanner in targets {
            let name = scanner.name().to_string();
            if shared.completed.contains(&name) {
                removed.insert(name);
            }
        }
        if shared.completed.contains(ScannerType::Report.name()) {
            removed.insert(ScannerType::Report.name().to_string());
        }
        shared.invalidate_chat_reruns_strict(
            zentra_dir,
            targets.iter().map(|scanner| scanner.name().to_string()),
        )?;
        *checkpoint = shared.clone();
        Ok(removed)
    }

    fn restore_resume_completions_strict(
        &self,
        checkpoint: &mut Checkpoint,
        zentra_dir: &std::path::Path,
        names: &BTreeSet<String>,
    ) -> Result<()> {
        if names.is_empty() {
            return Ok(());
        }
        let runtime = self
            .chat_runtime
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("chat runtime unavailable"))?;
        let mut shared = runtime
            .checkpoint
            .lock()
            .map_err(|_| anyhow::anyhow!("chat checkpoint lock poisoned"))?;
        shared.restore_completed_names_strict(zentra_dir, names)?;
        *checkpoint = shared.clone();
        Ok(())
    }

    fn rollback_after_checkpoint_progress_failure(
        &self,
        staging: &crate::state::FindingsRerun,
        progress: anyhow::Error,
    ) -> Result<()> {
        match self.state_writer.rollback_findings_rerun(staging) {
            Ok(()) => Err(progress),
            Err(restore) => Err(anyhow::anyhow!(
                "checkpoint progress failed after committed rerun: {progress}; exact findings restore failed: {restore}"
            )),
        }
    }

    async fn publish_chat_outcome(
        &self,
        proposal_id: uuid::Uuid,
        outcome: ChatActionOutcome,
    ) -> Result<()> {
        let Some(runtime) = &self.chat_runtime else {
            return Ok(());
        };
        let expected = runtime
            .checkpoint
            .lock()
            .map_err(|_| anyhow::anyhow!("chat checkpoint lock poisoned"))?
            .confirmed_chat_actions
            .iter()
            .find(|action| action.proposal_id == proposal_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("durable chat action is unavailable"))?;
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        runtime
            .outcome_tx
            .send(ChatActionOutcomeEnvelope {
                expected,
                outcome,
                ack: ack_tx,
            })
            .await
            .map_err(|_| anyhow::anyhow!("chat outcome receiver closed"))?;
        ack_rx
            .await
            .map_err(|_| anyhow::anyhow!("chat outcome acknowledgement dropped"))?
            .map_err(|error: ChatOutcomeFailure| anyhow::anyhow!(error.to_string()))?;
        Ok(())
    }

    fn update_chat_snapshot(
        &self,
        boundary: PhaseBoundary,
        statuses: &HashMap<ScannerType, ChatScannerState>,
        checkpoint: &Checkpoint,
        focus: &HashMap<ScannerType, ChatFocus>,
    ) -> bool {
        let Some(snapshot) = self.chat_runtime.as_ref().map(|runtime| &runtime.snapshot) else {
            return true;
        };
        match snapshot.lock() {
            Ok(mut snapshot) => {
                snapshot.boundary = boundary;
                snapshot.scanner_status = statuses
                    .iter()
                    .map(|(scanner, status)| crate::agent::chat::ChatScannerStatus {
                        scanner: scanner.name().to_string(),
                        status: *status,
                    })
                    .collect();
                snapshot
                    .scanner_status
                    .sort_by(|a, b| a.scanner.cmp(&b.scanner));
                snapshot.checkpoint_completed =
                    checkpoint.completed.iter().take(32).cloned().collect();
                snapshot.pending_action_count = checkpoint.confirmed_chat_actions.len().min(16);
                snapshot.action_eligible = self
                    .chat_runtime
                    .as_ref()
                    .is_some_and(|runtime| runtime.action_eligible.load(Ordering::Acquire));
                snapshot.focus_fragments = focus
                    .values()
                    .flat_map(|value| value.fragments.iter().copied())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                let findings = crate::state::parse_findings(
                    &self.state_writer.read_findings_raw().unwrap_or_default(),
                );
                let mut scanner_counts = BTreeMap::new();
                let mut severity_counts = BTreeMap::new();
                let mut category_counts = BTreeMap::new();
                for finding in &findings {
                    *scanner_counts
                        .entry(finding.scanner.clone())
                        .or_insert(0usize) += 1;
                    *severity_counts
                        .entry(finding.severity.to_string())
                        .or_insert(0usize) += 1;
                    if let Some(category) = &finding.owasp {
                        *category_counts.entry(category.clone()).or_insert(0usize) += 1;
                    }
                }
                let counts = |values: &BTreeMap<String, usize>| {
                    values
                        .iter()
                        .take(16)
                        .map(|(name, count)| format!("{name}:{count}"))
                        .collect::<Vec<_>>()
                        .join(",")
                };
                snapshot.findings_summary = format!(
                    "findings={}; scanners=[{}]; severities=[{}]; categories=[{}]",
                    findings.len(),
                    counts(&scanner_counts),
                    counts(&severity_counts),
                    counts(&category_counts)
                );
                snapshot.coverage_summary = format!(
                    "{} scanner files read",
                    self.tool_registry.coverage_snapshot(0).distinct_read
                );
                let architecture = self.state_writer.read_architecture();
                snapshot.architecture_context_hash = (!architecture.is_empty())
                    .then(|| crate::security::audit_log::sha256_str(&architecture));
                if let Some(incremental) = &self.incremental {
                    let mut paths: Vec<_> = incremental
                        .change_set
                        .impact
                        .iter()
                        .filter_map(|path| {
                            crate::agent::chat::NormalizedRepoPath::normalize(path).ok()
                        })
                        .map(|path| path.to_string())
                        .collect();
                    paths.sort();
                    paths.dedup();
                    paths.truncate(20);
                    snapshot.incremental_summary = Some(format!(
                        "changed={}; impacted={}",
                        incremental.change_set.changed.len(),
                        incremental.change_set.impact.len()
                    ));
                    snapshot.incremental_paths = paths;
                } else {
                    snapshot.incremental_summary = None;
                    snapshot.incremental_paths.clear();
                }
                match snapshot.clone().try_bounded() {
                    Ok(bounded) => {
                        *snapshot = bounded;
                        true
                    }
                    Err(_) => false,
                }
            }
            Err(_) => {
                crate::logging::warn(
                    "orchestrator",
                    "chat snapshot lock poisoned; actions are deferred fail-closed",
                );
                false
            }
        }
    }

    fn merge_lifetime_focus(focus: &mut ChatFocus, next: &ChatFocus) -> Result<()> {
        let mut merged = focus.clone();
        merged.categories.extend(next.categories.iter().copied());
        merged.fragments.extend(next.fragments.iter().copied());
        merged.paths.extend(next.paths.iter().cloned());
        merged.paths.sort();
        merged.paths.dedup();
        if merged.fragments.len() > crate::agent::chat::MAX_FOCUS_FRAGMENTS
            || merged.paths.len() > crate::agent::chat::MAX_FOCUS_PATHS
            || merged
                .render()
                .is_some_and(|rendered| rendered.len() > crate::agent::chat::MAX_CHAT_TEXT_BYTES)
        {
            anyhow::bail!("chat focus exceeds the validated planning bounds");
        }
        *focus = merged;
        Ok(())
    }

    /// Nonblocking boundary drain. The durable checkpoint is the source of
    /// truth, while the receiver is only a low-latency notification; proposal
    /// IDs deduplicate the two paths.
    async fn drain_chat_actions(
        &mut self,
        scanners: &[ScannerType],
    ) -> Result<Vec<ConfirmedChatAction>> {
        if self.chat_runtime.is_none() {
            return Ok(Vec::new());
        }
        if let Some(receiver) = self
            .chat_runtime
            .as_mut()
            .map(|runtime| &mut runtime.pending_actions)
        {
            while receiver.try_recv().is_ok() {}
        }
        let actions = self.shared_checkpoint()?.confirmed_chat_actions;
        if let Err(error) = plan_confirmed_chat_actions(&actions, scanners) {
            // A corrupted aggregate cannot be partially interpreted. The
            // coordinator owns removal, so acknowledgement failure deliberately
            // retains the durable records for retry.
            for action in &actions {
                self.publish_chat_outcome(
                    action.proposal_id,
                    ChatActionOutcome::Deferred {
                        proposal_id: action.proposal_id,
                        reason: error.user_reason().to_string(),
                    },
                )
                .await?;
            }
            return Ok(Vec::new());
        }
        Ok(actions)
    }

    /// The single durable-action boundary state machine. Receiver messages are
    /// only wakeups; planning always reads the complete ordered checkpoint.
    async fn apply_chat_boundary(
        &mut self,
        boundary: PhaseBoundary,
        context: ChatBoundaryContext<'_>,
    ) -> Result<bool> {
        let ChatBoundaryContext {
            scanners,
            checkpoint,
            statuses,
            focus,
            focus_members,
            reruns,
            force_rerun,
        } = context;
        if self.chat_runtime.is_none() {
            return Ok(false);
        }
        let actions = self.drain_chat_actions(scanners).await?;
        *checkpoint = self.shared_checkpoint()?;
        let plan = plan_confirmed_chat_actions(&actions, scanners)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        focus_members.clear();
        for target in &plan.targets {
            match focus.get_mut(&target.scanner) {
                Some(existing) => Self::merge_lifetime_focus(existing, &target.focus)?,
                None => {
                    focus.insert(target.scanner, target.focus.clone());
                }
            }
            focus_members.insert(target.scanner, target.proposal_ids.clone());
            if (force_rerun
                || !matches!(
                    statuses.get(&target.scanner),
                    Some(ChatScannerState::NotStarted)
                ))
                && !reruns.contains(&target.scanner)
            {
                reruns.push(target.scanner);
            }
        }
        let snapshot_failed = !self.update_chat_snapshot(boundary, statuses, checkpoint, focus);
        if snapshot_failed {
            for action in actions {
                self.publish_chat_outcome(
                    action.proposal_id,
                    ChatActionOutcome::Deferred {
                        proposal_id: action.proposal_id,
                        reason: "chat snapshot unavailable at safe boundary".to_string(),
                    },
                )
                .await?;
            }
            *checkpoint = self.shared_checkpoint()?;
            focus_members.clear();
            reruns.clear();
        }
        Ok(snapshot_failed)
    }

    pub async fn run(mut self, scanners: &[ScannerType]) -> Result<RunSummary> {
        let mut failed: Vec<ScannerType> = Vec::new();

        if self.resume.is_some() && self.incremental.is_some() {
            anyhow::bail!("--resume cannot be combined with incremental scanning");
        }
        let is_resume = self.resume.is_some();

        // Resolve the resume checkpoint. When `resume` is `None` (no --resume
        // flag), create a fresh empty one and write it as scanners complete, so
        // a crash enables a future resume. When `Some(cp)`, use the loaded
        // checkpoint and skip completed scanners.
        let zentra_dir = self.state_writer.project_root().join(".zentra");
        let restored = self.resume.take();
        let mut checkpoint = if self.chat_runtime.is_some() {
            let shared = self.shared_checkpoint()?;
            if let Some(restored) = restored {
                if restored != shared {
                    anyhow::bail!(
                        "resume checkpoint does not match the initialized chat checkpoint"
                    );
                }
            }
            shared
        } else {
            restored.unwrap_or_default()
        };

        // Identity and checkpoint authority precede journal recovery: committed
        // bytes can only be accepted when this exact checkpoint records the
        // matching scanner/proposal progress.
        let initial_snapshot_poisoned =
            self.validate_chat_runtime_checkpoint(&mut checkpoint, &zentra_dir)?;

        // Record the scanner set for the current run in the checkpoint.
        self.set_scanner_set_strict(&mut checkpoint, &zentra_dir, scanners)?;
        self.state_writer
            .recover_interrupted_findings_rerun(&checkpoint)
            .map_err(|error| anyhow::anyhow!("cannot safely recover findings rerun: {error}"))?;

        let mut chat_status: HashMap<ScannerType, ChatScannerState> = scanners
            .iter()
            .map(|scanner| {
                (
                    *scanner,
                    if checkpoint.is_completed(scanner.name()) {
                        ChatScannerState::Completed
                    } else {
                        ChatScannerState::NotStarted
                    },
                )
            })
            .collect();
        let mut chat_focus: HashMap<ScannerType, ChatFocus> = HashMap::new();
        let mut chat_focus_members: HashMap<ScannerType, Vec<uuid::Uuid>> = HashMap::new();
        let mut rerun_targets: Vec<ScannerType> = Vec::new();
        let mut resume_invalidated_completions = BTreeSet::new();
        let mut resume_snapshot_failed_closed = false;

        // Resume restores only exact-session, exact-scanner, typed actions. A
        // bad legacy/mismatched record is terminally deferred, never treated as
        // executable input. No transcript is involved in this path.
        // Validate restored durable actions before calculating ordinary resume
        // work. Remaining targets are transactionally forced reruns, while
        // already-satisfied actions are recovered as Applied without a scan.
        if is_resume && self.chat_runtime.is_some() {
            // This is deliberately before resume invalidation. An unavailable or
            // invalid snapshot must not turn completed targets/report into forced
            // work or rewrite their findings.
            let snapshot_unavailable = initial_snapshot_poisoned
                || !self.update_chat_snapshot(
                    PhaseBoundary::AfterFramework,
                    &chat_status,
                    &checkpoint,
                    &chat_focus,
                );
            let invalid_resume_actions = if snapshot_unavailable {
                false
            } else if let Some(runtime) = self.chat_runtime.as_ref() {
                checkpoint
                    .confirmed_chat_actions_for_resume(&runtime.session_id, scanners)
                    .is_err()
            } else {
                false
            };
            if snapshot_unavailable {
                resume_snapshot_failed_closed = true;
                let actions = checkpoint.confirmed_chat_actions.clone();
                for action in actions {
                    self.publish_chat_outcome(
                        action.proposal_id,
                        ChatActionOutcome::Deferred {
                            proposal_id: action.proposal_id,
                            reason: "chat snapshot unavailable before resume rerun".to_string(),
                        },
                    )
                    .await?;
                }
                checkpoint = self.shared_checkpoint()?;
            } else if invalid_resume_actions && !checkpoint.confirmed_chat_actions.is_empty() {
                let actions = checkpoint.confirmed_chat_actions.clone();
                for action in actions {
                    self.publish_chat_outcome(
                        action.proposal_id,
                        ChatActionOutcome::Deferred {
                            proposal_id: action.proposal_id,
                            reason: "resume action session, scanner set, or typed scope is invalid"
                                .to_string(),
                        },
                    )
                    .await?;
                }
                checkpoint = self.shared_checkpoint()?;
            }
            let restored_actions = if snapshot_unavailable {
                Vec::new()
            } else {
                self.shared_checkpoint()?.confirmed_chat_actions
            };
            let mut forced: Vec<_> = restored_actions
                .iter()
                .flat_map(|action| action.remaining_scanners.iter().copied())
                .collect();
            forced.sort_by_key(ScannerType::name);
            forced.dedup();
            resume_invalidated_completions =
                self.invalidate_chat_targets_strict(&mut checkpoint, &zentra_dir, &forced)?;
            rerun_targets.extend(forced);
            for action in restored_actions
                .into_iter()
                .filter(|action| action.remaining_scanners.is_empty())
            {
                self.publish_chat_outcome(
                    action.proposal_id,
                    ChatActionOutcome::Applied {
                        proposal_id: action.proposal_id,
                        boundary: PhaseBoundary::AfterFramework,
                    },
                )
                .await?;
            }
            checkpoint = self.shared_checkpoint()?;
            self.update_chat_snapshot(
                PhaseBoundary::AfterFramework,
                &chat_status,
                &checkpoint,
                &chat_focus,
            );
        }

        // Phase 0: FrameworkAnalysis - builds .zentra/architecture.md for all subsequent scanners.
        // Skip on resume when the checkpoint marks "framework" and the architecture file exists.
        let skip_framework = checkpoint.is_completed(ScannerType::FrameworkAnalysis.name())
            && self.state_writer.architecture_exists();

        // A completed report is stale when any requested scanner before it will
        // run again. Invalidate it before replaying skipped events so the report
        // is regenerated from the current findings.
        let rerunning_pre_report = [
            ScannerType::FrameworkAnalysis,
            ScannerType::ThreatModel,
            ScannerType::Sast,
            ScannerType::SupplyChain,
            ScannerType::ApiScan,
            ScannerType::IacScan,
        ]
        .iter()
        .any(|&scanner| {
            scanners.contains(&scanner)
                && match scanner {
                    ScannerType::FrameworkAnalysis => !skip_framework,
                    _ => !checkpoint.is_completed(scanner.name()),
                }
        });
        if scanners.contains(&ScannerType::Report) && rerunning_pre_report {
            if let Some(runtime) = &self.chat_runtime {
                let mut shared = runtime
                    .checkpoint
                    .lock()
                    .map_err(|_| anyhow::anyhow!("chat checkpoint lock poisoned"))?;
                if shared.completed.contains(ScannerType::Report.name()) {
                    let mut updated = shared.clone();
                    updated.completed.remove(ScannerType::Report.name());
                    updated.updated_at = chrono::Utc::now().to_rfc3339();
                    updated.save_strict(&zentra_dir)?;
                    *shared = updated;
                }
                checkpoint = shared.clone();
                self.update_chat_snapshot(
                    PhaseBoundary::AfterFramework,
                    &chat_status,
                    &checkpoint,
                    &chat_focus,
                );
            } else if checkpoint.completed.remove(ScannerType::Report.name()) {
                checkpoint.updated_at = chrono::Utc::now().to_rfc3339();
                self.checkpoint_save(&checkpoint, &zentra_dir)?;
            }
        }

        // On resume, remove findings for every scanner that will run again.
        // An empty, valid checkpoint means no scanner completed, so it starts
        // with a clean findings set rather than appending to stale output.
        let raw = self.state_writer.read_findings_raw().unwrap_or_default();
        let all_findings = crate::state::parse_findings(&raw);
        let will_run = |scanner: ScannerType| match scanner {
            ScannerType::FrameworkAnalysis => scanners.contains(&scanner) && !skip_framework,
            _ => {
                scanners.contains(&scanner)
                    && !checkpoint.is_completed(scanner.name())
                    && !rerun_targets.contains(&scanner)
            }
        };
        let kept: Vec<Finding> =
            if is_resume && checkpoint.completed.is_empty() && rerun_targets.is_empty() {
                Vec::new()
            } else if is_resume {
                all_findings
                    .iter()
                    .filter(|finding| {
                        ![
                            ScannerType::FrameworkAnalysis,
                            ScannerType::ThreatModel,
                            ScannerType::Sast,
                            ScannerType::SupplyChain,
                            ScannerType::ApiScan,
                            ScannerType::IacScan,
                            ScannerType::Report,
                        ]
                        .iter()
                        .any(|&scanner| scanner.name() == finding.scanner && will_run(scanner))
                    })
                    .cloned()
                    .collect()
            } else {
                all_findings.clone()
            };
        if (is_resume && checkpoint.completed.is_empty() && rerun_targets.is_empty())
            || kept.len() != all_findings.len()
        {
            let _ = self.state_writer.rewrite_findings(&kept);
        }

        // Replay skipped scanners through the same event channel as active
        // scanners. This keeps the TUI's terminal state and finding counters
        // complete during a resume.
        let skipped = [
            (
                ScannerType::FrameworkAnalysis,
                scanners.contains(&ScannerType::FrameworkAnalysis) && skip_framework,
            ),
            (
                ScannerType::ThreatModel,
                scanners.contains(&ScannerType::ThreatModel)
                    && checkpoint.is_completed(ScannerType::ThreatModel.name()),
            ),
            (
                ScannerType::Sast,
                scanners.contains(&ScannerType::Sast)
                    && checkpoint.is_completed(ScannerType::Sast.name()),
            ),
            (
                ScannerType::SupplyChain,
                scanners.contains(&ScannerType::SupplyChain)
                    && checkpoint.is_completed(ScannerType::SupplyChain.name()),
            ),
            (
                ScannerType::ApiScan,
                scanners.contains(&ScannerType::ApiScan)
                    && checkpoint.is_completed(ScannerType::ApiScan.name()),
            ),
            (
                ScannerType::IacScan,
                scanners.contains(&ScannerType::IacScan)
                    && checkpoint.is_completed(ScannerType::IacScan.name()),
            ),
            (
                ScannerType::Report,
                scanners.contains(&ScannerType::Report)
                    && checkpoint.is_completed(ScannerType::Report.name()),
            ),
        ];
        for (scanner, is_skipped) in skipped {
            if !is_skipped {
                continue;
            }
            self.tx.send(ScanEvent::ScannerStarted(scanner)).await.ok();
            for finding in &kept {
                if finding.scanner == scanner.name() {
                    self.tx
                        .send(ScanEvent::FindingAdded(finding.clone()))
                        .await
                        .ok();
                }
            }
            self.tx
                .send(ScanEvent::ScannerCompleted(scanner))
                .await
                .ok();
        }

        if !skip_framework && scanners.contains(&ScannerType::FrameworkAnalysis) {
            chat_status.insert(ScannerType::FrameworkAnalysis, ChatScannerState::Running);
            self.update_chat_snapshot(
                PhaseBoundary::AfterFramework,
                &chat_status,
                &checkpoint,
                &chat_focus,
            );
            if self
                .run_llm_scanner(ScannerType::FrameworkAnalysis, None)
                .await
                .is_ok()
                && !self.cancel_token.is_cancelled()
            {
                self.checkpoint_mark_completed(
                    &mut checkpoint,
                    &zentra_dir,
                    ScannerType::FrameworkAnalysis.name(),
                    &[],
                )?;
            } else {
                failed.push(ScannerType::FrameworkAnalysis);
                chat_status.insert(ScannerType::FrameworkAnalysis, ChatScannerState::Failed);
                self.update_chat_snapshot(
                    PhaseBoundary::AfterFramework,
                    &chat_status,
                    &checkpoint,
                    &chat_focus,
                );
            }

            if !failed.contains(&ScannerType::FrameworkAnalysis) {
                chat_status.insert(ScannerType::FrameworkAnalysis, ChatScannerState::Completed);
                self.update_chat_snapshot(
                    PhaseBoundary::AfterFramework,
                    &chat_status,
                    &checkpoint,
                    &chat_focus,
                );
            }

            // Safety net: if the agent exhausted iterations without calling write_architecture,
            // write a minimal placeholder so Phase 0 won't re-trigger on the next scan.
            if self.state_writer.read_architecture().is_empty() {
                let _ = self.state_writer.write_architecture(
                    "# Framework Architecture Analysis\n\nAnalysis incomplete. \
                    Delete this file and re-run the scan to retry.",
                );
            }
        }

        let boundary_failed_closed = self
            .apply_chat_boundary(
                PhaseBoundary::AfterFramework,
                ChatBoundaryContext {
                    scanners,
                    checkpoint: &mut checkpoint,
                    statuses: &chat_status,
                    focus: &mut chat_focus,
                    focus_members: &mut chat_focus_members,
                    reruns: &mut rerun_targets,
                    force_rerun: false,
                },
            )
            .await?;
        if boundary_failed_closed {
            if is_resume {
                resume_snapshot_failed_closed = true;
            }
            self.restore_resume_completions_strict(
                &mut checkpoint,
                &zentra_dir,
                &resume_invalidated_completions,
            )?;
            resume_invalidated_completions.clear();
        }

        // After Phase 0, post a summary observation for later scanners.
        let arch = self.state_writer.read_architecture();
        if !arch.is_empty() {
            self.board.post(crate::agent::board::Observation {
                scanner: "framework".to_string(),
                category: "architecture".to_string(),
                text: "Framework analysis completed. See .zentra/architecture.md for details."
                    .to_string(),
            });
        }

        // Read produced architecture; inject into every LLM scanner that follows
        let context = self.state_writer.read_architecture();
        let context_opt: Option<String> = if context.is_empty() {
            None
        } else {
            Some(context)
        };

        // Phase 1: ThreatModel - sequential. On incremental, skip unless
        // architecturally-significant files changed (carried forward otherwise).
        let skip_threat_model = checkpoint.is_completed(ScannerType::ThreatModel.name());
        let run_threat_model = !skip_threat_model
            && scanners.contains(&ScannerType::ThreatModel)
            && match &self.incremental {
                Some(ctx) => is_arch_significant(&ctx.change_set.changed),
                None => true,
            };
        if run_threat_model {
            chat_status.insert(ScannerType::ThreatModel, ChatScannerState::Running);
            self.update_chat_snapshot(
                PhaseBoundary::AfterFramework,
                &chat_status,
                &checkpoint,
                &chat_focus,
            );
            if self
                .run_llm_scanner(ScannerType::ThreatModel, context_opt.as_deref())
                .await
                .is_ok()
                && !self.cancel_token.is_cancelled()
            {
                self.checkpoint_mark_completed(
                    &mut checkpoint,
                    &zentra_dir,
                    ScannerType::ThreatModel.name(),
                    &[],
                )?;
            } else {
                failed.push(ScannerType::ThreatModel);
                chat_status.insert(ScannerType::ThreatModel, ChatScannerState::Failed);
                self.update_chat_snapshot(
                    PhaseBoundary::AfterFramework,
                    &chat_status,
                    &checkpoint,
                    &chat_focus,
                );
            }
            if !failed.contains(&ScannerType::ThreatModel) {
                chat_status.insert(ScannerType::ThreatModel, ChatScannerState::Completed);
                self.update_chat_snapshot(
                    PhaseBoundary::AfterThreatModel,
                    &chat_status,
                    &checkpoint,
                    &chat_focus,
                );
            }
        }

        let boundary_failed_closed = self
            .apply_chat_boundary(
                PhaseBoundary::AfterThreatModel,
                ChatBoundaryContext {
                    scanners,
                    checkpoint: &mut checkpoint,
                    statuses: &chat_status,
                    focus: &mut chat_focus,
                    focus_members: &mut chat_focus_members,
                    reruns: &mut rerun_targets,
                    force_rerun: false,
                },
            )
            .await?;
        if boundary_failed_closed {
            if is_resume {
                resume_snapshot_failed_closed = true;
            }
            self.restore_resume_completions_strict(
                &mut checkpoint,
                &zentra_dir,
                &resume_invalidated_completions,
            )?;
            resume_invalidated_completions.clear();
        }

        // After the threat model completes, post its findings as observations
        // for later scanners (SAST, API, IaC, Report).
        let raw = self.state_writer.read_findings_raw().unwrap_or_default();
        let threat_findings = crate::state::parse_findings(&raw)
            .into_iter()
            .filter(|f| f.scanner == "threat_model")
            .collect::<Vec<_>>();
        for f in &threat_findings {
            self.board.post(crate::agent::board::Observation {
                scanner: "threat_model".to_string(),
                category: "threat".to_string(),
                text: format!(
                    "{}: {}",
                    f.title,
                    f.description.chars().take(200).collect::<String>()
                ),
            });
        }

        // Phase 2: parallel scanners (SAST, SCA, API, IaC).
        // Skip scanners that the checkpoint records as completed.
        let parallel: Vec<ScannerType> = PARALLEL_SCANNERS
            .iter()
            .filter(|s| scanners.contains(s))
            .filter(|s| !checkpoint.is_completed(s.name()))
            .filter(|s| !rerun_targets.contains(s))
            .copied()
            .collect();

        if !parallel.is_empty() {
            let mut handles = Vec::new();
            let cancel_token = self.cancel_token.clone();
            for scanner_type in parallel {
                chat_status.insert(scanner_type, ChatScannerState::Running);
                self.update_chat_snapshot(
                    PhaseBoundary::AfterThreatModel,
                    &chat_status,
                    &checkpoint,
                    &chat_focus,
                );
                let provider = Arc::clone(&self.provider);
                let registry = Arc::clone(&self.tool_registry);
                let writer = Arc::clone(&self.state_writer);
                let tx = self.tx.clone();
                let ctx = context_opt.clone();
                let focus_ctx = self.focus_context.clone();
                let token = cancel_token.clone();
                let security = self.security.clone();
                let pack = self.pack.clone();
                let board = self.board.clone();
                let focus_members_for_scanner = chat_focus_members
                    .get(&scanner_type)
                    .cloned()
                    .unwrap_or_default();
                let chat_focus_for_scanner = (!focus_members_for_scanner.is_empty())
                    .then(|| chat_focus.get(&scanner_type).cloned())
                    .flatten();
                let incremental_scope = self
                    .incremental
                    .as_ref()
                    .and_then(|ic| incremental_scope_for(scanner_type, &ic.change_set));
                handles.push((
                    scanner_type,
                    focus_members_for_scanner,
                    tokio::spawn(async move {
                        ScannerAgent::new_with_contexts(
                            scanner_type,
                            provider,
                            registry,
                            writer,
                            tx,
                            ctx,
                            focus_ctx,
                            token,
                        )
                        .with_security(security)
                        .with_incremental_scope(incremental_scope)
                        .with_pack(pack)
                        .with_board(board)
                        .with_chat_focus(chat_focus_for_scanner)
                        .run()
                        .await
                    }),
                ));
            }
            for (scanner_type, focus_members_for_scanner, handle) in handles {
                match handle.await {
                    Ok(Ok(())) => {
                        if !self.cancel_token.is_cancelled() {
                            let terminal = self.checkpoint_mark_completed(
                                &mut checkpoint,
                                &zentra_dir,
                                scanner_type.name(),
                                &focus_members_for_scanner,
                            )?;
                            chat_status.insert(scanner_type, ChatScannerState::Completed);
                            self.update_chat_snapshot(
                                PhaseBoundary::AfterThreatModel,
                                &chat_status,
                                &checkpoint,
                                &chat_focus,
                            );
                            for action in terminal {
                                self.publish_chat_outcome(
                                    action.proposal_id,
                                    ChatActionOutcome::Applied {
                                        proposal_id: action.proposal_id,
                                        boundary: PhaseBoundary::AfterParallel,
                                    },
                                )
                                .await?;
                            }
                            if self.chat_runtime.is_some() {
                                checkpoint = self.shared_checkpoint()?;
                            }
                            self.update_chat_snapshot(
                                PhaseBoundary::AfterThreatModel,
                                &chat_status,
                                &checkpoint,
                                &chat_focus,
                            );
                        } else {
                            failed.push(scanner_type);
                            chat_status.insert(scanner_type, ChatScannerState::Failed);
                            self.update_chat_snapshot(
                                PhaseBoundary::AfterThreatModel,
                                &chat_status,
                                &checkpoint,
                                &chat_focus,
                            );
                        }
                    }
                    Ok(Err(_)) => {
                        failed.push(scanner_type);
                        chat_status.insert(scanner_type, ChatScannerState::Failed);
                        self.update_chat_snapshot(
                            PhaseBoundary::AfterThreatModel,
                            &chat_status,
                            &checkpoint,
                            &chat_focus,
                        );
                    }
                    Err(e) => {
                        crate::logging::error(
                            "scan",
                            format!("scanner={scanner_type:?} task failed: {e}"),
                        );
                        self.tx
                            .send(ScanEvent::Error {
                                scanner: scanner_type,
                                message: format!("Scanner task failed: {}", e),
                            })
                            .await
                            .ok();
                        self.tx
                            .send(ScanEvent::ScannerCompleted(scanner_type))
                            .await
                            .ok();
                        failed.push(scanner_type);
                        chat_status.insert(scanner_type, ChatScannerState::Failed);
                        self.update_chat_snapshot(
                            PhaseBoundary::AfterThreatModel,
                            &chat_status,
                            &checkpoint,
                            &chat_focus,
                        );
                    }
                }
            }
        }

        let boundary_failed_closed = self
            .apply_chat_boundary(
                PhaseBoundary::AfterParallel,
                ChatBoundaryContext {
                    scanners,
                    checkpoint: &mut checkpoint,
                    statuses: &chat_status,
                    focus: &mut chat_focus,
                    focus_members: &mut chat_focus_members,
                    reruns: &mut rerun_targets,
                    force_rerun: true,
                },
            )
            .await?;
        if boundary_failed_closed {
            if is_resume {
                resume_snapshot_failed_closed = true;
            }
            self.restore_resume_completions_strict(
                &mut checkpoint,
                &zentra_dir,
                &resume_invalidated_completions,
            )?;
            resume_invalidated_completions.clear();
        }
        // Close eligibility before the final checkpoint drain. A confirmation
        // persisted before this store is included below; one after it is
        // deferred by the coordinator and never becomes pending work.
        if let Some(runtime) = &self.chat_runtime {
            runtime.action_eligible.store(false, Ordering::Release);
            let final_actions = self.drain_chat_actions(scanners).await?;
            let plan = plan_confirmed_chat_actions(&final_actions, scanners)
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            chat_focus_members.clear();
            for target in plan.targets {
                match chat_focus.get_mut(&target.scanner) {
                    Some(existing) => Self::merge_lifetime_focus(existing, &target.focus)?,
                    None => {
                        chat_focus.insert(target.scanner, target.focus);
                    }
                }
                chat_focus_members.insert(target.scanner, target.proposal_ids);
                if !rerun_targets.contains(&target.scanner) {
                    rerun_targets.push(target.scanner);
                }
            }
            checkpoint = self.shared_checkpoint()?;
            if !self.update_chat_snapshot(
                PhaseBoundary::Finalized,
                &chat_status,
                &checkpoint,
                &chat_focus,
            ) {
                for action in final_actions {
                    self.publish_chat_outcome(
                        action.proposal_id,
                        ChatActionOutcome::Deferred {
                            proposal_id: action.proposal_id,
                            reason: "chat snapshot unavailable at final boundary".to_string(),
                        },
                    )
                    .await?;
                }
                rerun_targets.clear();
                if is_resume {
                    resume_snapshot_failed_closed = true;
                }
                self.restore_resume_completions_strict(
                    &mut checkpoint,
                    &zentra_dir,
                    &resume_invalidated_completions,
                )?;
                resume_invalidated_completions.clear();
            }
        }

        // Cancellation is deliberately resumable: actions remain in the
        // checkpoint and no rerun or Applied publication occurs.
        if !self.cancel_token.is_cancelled() {
            for scanner_type in PARALLEL_SCANNERS
                .iter()
                .copied()
                .filter(|scanner| rerun_targets.contains(scanner))
            {
                #[cfg(test)]
                self.trace_pipeline("rerun");
                let _ = self.invalidate_chat_targets_strict(
                    &mut checkpoint,
                    &zentra_dir,
                    &[scanner_type],
                )?;
                let rerun_members = chat_focus_members
                    .get(&scanner_type)
                    .cloned()
                    .unwrap_or_default();
                let staging = match self
                    .state_writer
                    .begin_findings_rerun(scanner_type.name(), &rerun_members)
                {
                    Ok(staging) => staging,
                    Err(error) => {
                        if !failed.contains(&scanner_type) {
                            failed.push(scanner_type);
                        }
                        chat_status.insert(scanner_type, ChatScannerState::Failed);
                        self.update_chat_snapshot(
                            PhaseBoundary::Finalized,
                            &chat_status,
                            &checkpoint,
                            &chat_focus,
                        );
                        crate::logging::warn(
                            "orchestrator",
                            format!(
                                "cannot stage {} findings before chat rerun: {error}",
                                scanner_type.name()
                            ),
                        );
                        continue;
                    }
                };
                chat_status.insert(scanner_type, ChatScannerState::Running);
                self.update_chat_snapshot(
                    PhaseBoundary::Finalized,
                    &chat_status,
                    &checkpoint,
                    &chat_focus,
                );
                let scope = self
                    .incremental
                    .as_ref()
                    .and_then(|ctx| incremental_scope_for(scanner_type, &ctx.change_set));
                let result = ScannerAgent::new_with_contexts(
                    scanner_type,
                    Arc::clone(&self.provider),
                    Arc::clone(&self.tool_registry),
                    Arc::clone(&self.state_writer),
                    self.tx.clone(),
                    context_opt.clone(),
                    self.focus_context.clone(),
                    self.cancel_token.clone(),
                )
                .with_security(self.security.clone())
                .with_incremental_scope(scope)
                .with_pack(self.pack.clone())
                .with_board(self.board.clone())
                .with_chat_focus(
                    (!rerun_members.is_empty())
                        .then(|| chat_focus.get(&scanner_type).cloned())
                        .flatten(),
                )
                .run()
                .await;
                match result {
                    Ok(()) if !self.cancel_token.is_cancelled() => {
                        if let Err(error) = self
                            .state_writer
                            .commit_findings_rerun_pending_progress(&staging)
                        {
                            self.state_writer.rollback_findings_rerun(&staging).map_err(|rollback| anyhow::anyhow!("cannot commit {} findings rerun: {error}; rollback failed: {rollback}", scanner_type.name()))?;
                            crate::logging::warn(
                                "orchestrator",
                                format!(
                                    "cannot commit {} findings rerun: {error}",
                                    scanner_type.name()
                                ),
                            );
                            failed.push(scanner_type);
                            chat_status.insert(scanner_type, ChatScannerState::Failed);
                            self.update_chat_snapshot(
                                PhaseBoundary::Finalized,
                                &chat_status,
                                &checkpoint,
                                &chat_focus,
                            );
                            continue;
                        }
                        let terminal = match self.checkpoint_mark_completed(
                            &mut checkpoint,
                            &zentra_dir,
                            scanner_type.name(),
                            &rerun_members,
                        ) {
                            Ok(terminal) => terminal,
                            Err(progress) => {
                                let error = self
                                    .rollback_after_checkpoint_progress_failure(&staging, progress)
                                    .expect_err("checkpoint compensation always returns its error");
                                return Err(error);
                            }
                        };
                        if let Err(error) = self.state_writer.finalize_findings_rerun(&staging) {
                            return Err(anyhow::anyhow!(
                                "checkpoint progress committed for {} rerun but journal finalization failed: {error}",
                                scanner_type.name()
                            ));
                        }
                        chat_status.insert(scanner_type, ChatScannerState::Completed);
                        failed.retain(|failed_scanner| *failed_scanner != scanner_type);
                        self.update_chat_snapshot(
                            PhaseBoundary::Finalized,
                            &chat_status,
                            &checkpoint,
                            &chat_focus,
                        );
                        for action in terminal {
                            self.publish_chat_outcome(
                                action.proposal_id,
                                ChatActionOutcome::Applied {
                                    proposal_id: action.proposal_id,
                                    boundary: PhaseBoundary::AfterParallel,
                                },
                            )
                            .await?;
                        }
                    }
                    _ => {
                        self.state_writer
                            .rollback_findings_rerun(&staging)
                            .map_err(|rollback| {
                                anyhow::anyhow!(
                                    "failed to roll back {} findings rerun: {rollback}",
                                    scanner_type.name()
                                )
                            })?;
                        if !failed.contains(&scanner_type) {
                            failed.push(scanner_type);
                        }
                        chat_status.insert(scanner_type, ChatScannerState::Failed);
                        self.update_chat_snapshot(
                            PhaseBoundary::Finalized,
                            &chat_status,
                            &checkpoint,
                            &chat_focus,
                        );
                    }
                }
            }
        }

        if !self.cancel_token.is_cancelled() && self.chat_runtime.is_some() {
            for action in self
                .shared_checkpoint()?
                .confirmed_chat_actions
                .into_iter()
                .filter(|action| action.remaining_scanners.is_empty())
            {
                self.publish_chat_outcome(
                    action.proposal_id,
                    ChatActionOutcome::Applied {
                        proposal_id: action.proposal_id,
                        boundary: PhaseBoundary::AfterParallel,
                    },
                )
                .await?;
            }
            checkpoint = self.shared_checkpoint()?;
        }

        // After Phase 2, post all findings so the report scanner can see the
        // full picture across every scanner.
        let raw = self.state_writer.read_findings_raw().unwrap_or_default();
        let all_findings = crate::state::parse_findings(&raw);
        for f in &all_findings {
            self.board.post(crate::agent::board::Observation {
                scanner: f.scanner.clone(),
                category: "finding".to_string(),
                text: format!(
                    "{}: {}",
                    f.title,
                    f.description.chars().take(200).collect::<String>()
                ),
            });
        }

        // Incremental reconciliation: merge fresh findings (just written by the
        // focused scanners) with the prior set, before correlation/report read them.
        let mut delta = None;
        if !is_resume {
            if let Some(ctx) = self.incremental.take() {
                #[cfg(test)]
                self.trace_pipeline("reconcile");
                let raw = self.state_writer.read_findings_raw().unwrap_or_default();
                let fresh = crate::state::parse_findings(&raw);
                let (merged, d) = reconcile(ctx.prior, fresh, &ctx.change_set);
                if let Err(e) = self.state_writer.rewrite_findings(&merged) {
                    crate::logging::warn(
                        "orchestrator",
                        format!("incremental reconcile: failed to rewrite findings: {e}"),
                    );
                }
                delta = Some(d);
            }
        }

        if self.cancel_token.is_cancelled() {
            return Ok(RunSummary {
                failed,
                delta,
                coverage: crate::agent::coverage::CoverageSummary::default(),
            });
        }

        // Phase 2.5: correlate/dedup findings before the report consumes them.
        // Best-effort - never fatal, and never drops findings on failure.
        // Never skipped on resume: it may need to process findings from re-run scanners.
        if scanners.contains(&ScannerType::Report) && !resume_snapshot_failed_closed {
            #[cfg(test)]
            self.trace_pipeline("correlate");
            let raw = self.state_writer.read_findings_raw().unwrap_or_default();
            let parsed = crate::state::parse_findings(&raw);
            if parsed.len() > 1 {
                let merged = crate::agent::correlation::correlate(
                    &self.provider,
                    parsed,
                    Some(&self.cancel_token),
                )
                .await;
                let _ = self.state_writer.rewrite_findings(&merged);
            }
        }

        if self.cancel_token.is_cancelled() {
            return Ok(RunSummary {
                failed,
                delta,
                coverage: crate::agent::coverage::CoverageSummary::default(),
            });
        }

        // Phase 2.6: screen the deduplicated set for reachability, so the report
        // consumes findings that carry a verdict. After correlation on purpose:
        // screening a duplicate twice would pay for the same issue twice.
        // Best-effort and annotate-only, like 2.5.
        // Never skipped on resume: it may need to process findings from re-run scanners.
        if scanners.contains(&ScannerType::Report) && !resume_snapshot_failed_closed {
            #[cfg(test)]
            self.trace_pipeline("screen");
            let raw = self.state_writer.read_findings_raw().unwrap_or_default();
            let parsed = crate::state::parse_findings(&raw);
            if !parsed.is_empty() {
                let screened = crate::agent::screening::screen(
                    &self.provider,
                    self.state_writer.project_root(),
                    parsed,
                    Some(&self.cancel_token),
                )
                .await;
                let _ = self.state_writer.rewrite_findings(&screened);
            }
        }

        if self.cancel_token.is_cancelled() {
            return Ok(RunSummary {
                failed,
                delta,
                coverage: crate::agent::coverage::CoverageSummary::default(),
            });
        }

        // Phase 3: Report - sequential, runs last
        if !checkpoint.is_completed(ScannerType::Report.name())
            && scanners.contains(&ScannerType::Report)
            && !resume_snapshot_failed_closed
        {
            #[cfg(test)]
            self.trace_pipeline("report");
            chat_status.insert(ScannerType::Report, ChatScannerState::Running);
            self.update_chat_snapshot(
                PhaseBoundary::Finalized,
                &chat_status,
                &checkpoint,
                &chat_focus,
            );
            if self
                .run_llm_scanner(ScannerType::Report, context_opt.as_deref())
                .await
                .is_ok()
                && !self.cancel_token.is_cancelled()
            {
                self.checkpoint_mark_completed(
                    &mut checkpoint,
                    &zentra_dir,
                    ScannerType::Report.name(),
                    &[],
                )?;
                chat_status.insert(ScannerType::Report, ChatScannerState::Completed);
                self.update_chat_snapshot(
                    PhaseBoundary::Finalized,
                    &chat_status,
                    &checkpoint,
                    &chat_focus,
                );
            } else {
                failed.push(ScannerType::Report);
                chat_status.insert(ScannerType::Report, ChatScannerState::Failed);
                self.update_chat_snapshot(
                    PhaseBoundary::Finalized,
                    &chat_status,
                    &checkpoint,
                    &chat_focus,
                );
            }
        }

        // Coverage ledger, written last so it reflects every scanner. Reports
        // only - a thin scan never fails the run here, it just stops looking
        // like a clean one.
        let candidates =
            crate::tools::fs_tools::source_file_paths(self.state_writer.project_root());
        let coverage = self.tool_registry.coverage_snapshot(candidates.len());
        let never_read = self.tool_registry.never_read_snapshot(&candidates);
        if let Err(e) = self
            .state_writer
            .write_coverage(&crate::agent::coverage::render_markdown(
                &coverage,
                &never_read,
            ))
        {
            crate::logging::warn("orchestrator", format!("failed to write coverage.md: {e}"));
        }

        // A complete scan leaves no checkpoint behind. A scan with failures
        // leaves the checkpoint so the operator can resume the missing scanners.
        let chat_actions_still_durable = self
            .chat_runtime
            .as_ref()
            .map(|runtime| &runtime.checkpoint)
            .map(|shared| match shared.lock() {
                Ok(checkpoint) => !checkpoint.confirmed_chat_actions.is_empty(),
                // Never erase resumable actions when the shared state cannot be
                // inspected safely.
                Err(_) => true,
            })
            .unwrap_or(false);
        if failed.is_empty()
            && !self.cancel_token.is_cancelled()
            && !chat_actions_still_durable
            && !resume_snapshot_failed_closed
        {
            Checkpoint::clear_strict(&zentra_dir).map_err(|error| {
                anyhow::anyhow!("scan completed but checkpoint could not be cleared: {error}")
            })?;
        }

        Ok(RunSummary {
            failed,
            delta,
            coverage,
        })
    }

    async fn run_llm_scanner(
        &self,
        scanner_type: ScannerType,
        context: Option<&str>,
    ) -> Result<()> {
        ScannerAgent::new_with_contexts(
            scanner_type,
            Arc::clone(&self.provider),
            Arc::clone(&self.tool_registry),
            Arc::clone(&self.state_writer),
            self.tx.clone(),
            context.map(str::to_string),
            self.focus_context.clone(),
            self.cancel_token.clone(),
        )
        .with_security(self.security.clone())
        .with_pack(self.pack.clone())
        .with_board(self.board.clone())
        .run()
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::chat::{ChatAction, ChatOutcomeAck, FocusFragment, FocusScope};
    use crate::provider::{
        AgentMessage, CompletionRequest, CompletionResponse, TokenUsage, ToolCall, ToolDefinition,
    };
    use crate::state::Severity;
    use async_trait::async_trait;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;
    use tokio::sync::Notify;

    struct NoopProvider;

    #[async_trait]
    impl LLMProvider for NoopProvider {
        async fn complete(&self, _: CompletionRequest) -> Result<CompletionResponse> {
            anyhow::bail!("not used")
        }
        async fn complete_with_tools(
            &self,
            _: &str,
            _: &[AgentMessage],
            _: &[ToolDefinition],
            _: u32,
            _: Option<&CancellationToken>,
        ) -> Result<CompletionResponse> {
            anyhow::bail!("not used")
        }
        fn context_window(&self) -> u32 {
            1
        }
        fn model_name(&self) -> &str {
            "noop"
        }
    }

    fn outcome_test_agent(
        root: &std::path::Path,
        checkpoint: Arc<Mutex<Checkpoint>>,
        outcome_tx: mpsc::Sender<ChatActionOutcomeEnvelope>,
    ) -> OrchestratorAgent {
        let (pending_tx, pending_actions) = mpsc::channel(1);
        drop(pending_tx);
        OrchestratorAgent::new(
            Arc::new(NoopProvider),
            Arc::new(ToolRegistry::new()),
            Arc::new(StateWriter::new(root).unwrap()),
            mpsc::channel(1).0,
            CancellationToken::new(),
        )
        .with_chat_runtime(OrchestratorChatRuntime {
            session_id: "test-session".to_string(),
            pending_actions,
            outcome_tx,
            checkpoint,
            snapshot: Arc::new(Mutex::new(ChatSnapshot::default())),
            action_eligible: Arc::new(AtomicBool::new(true)),
        })
    }

    fn change_set(impact: &[&str]) -> ChangeSet {
        ChangeSet {
            changed: vec![],
            impact: impact.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn scopes_sast_api_and_iac_but_not_supply_chain_or_others() {
        let cs = change_set(&["src/a.rs", "src/b.rs"]);
        let expected = Some(vec!["src/a.rs".to_string(), "src/b.rs".to_string()]);

        assert_eq!(incremental_scope_for(ScannerType::Sast, &cs), expected);
        assert_eq!(incremental_scope_for(ScannerType::ApiScan, &cs), expected);
        assert_eq!(incremental_scope_for(ScannerType::IacScan, &cs), expected);

        assert_eq!(incremental_scope_for(ScannerType::SupplyChain, &cs), None);
        assert_eq!(incremental_scope_for(ScannerType::ThreatModel, &cs), None);
        assert_eq!(incremental_scope_for(ScannerType::Report, &cs), None);
        assert_eq!(
            incremental_scope_for(ScannerType::FrameworkAnalysis, &cs),
            None
        );
    }

    #[test]
    fn category_table_only_targets_selected_phase_two_scanners() {
        let action = ChatAction::prioritize(
            crate::agent::chat::VulnerabilityCategory::AuthenticationAuthorization,
        );
        let confirmed = |selected: Vec<ScannerType>| {
            ConfirmedChatAction::new(uuid::Uuid::new_v4(), 1, action.clone(), selected).unwrap()
        };
        assert_eq!(
            plan_confirmed_chat_actions(
                &[confirmed(vec![ScannerType::Sast])],
                &[ScannerType::Sast]
            )
            .unwrap()
            .proposals[0]
                .scanners,
            vec![ScannerType::Sast]
        );
        assert!(plan_confirmed_chat_actions(
            &[confirmed(vec![ScannerType::SupplyChain])],
            &[ScannerType::SupplyChain]
        )
        .is_err());
        let supply_action = ChatAction::prioritize(
            crate::agent::chat::VulnerabilityCategory::DependencySupplyChain,
        );
        assert_eq!(
            plan_confirmed_chat_actions(
                &[ConfirmedChatAction::new(
                    uuid::Uuid::new_v4(),
                    1,
                    supply_action,
                    [ScannerType::SupplyChain]
                )
                .unwrap()],
                &[ScannerType::SupplyChain]
            )
            .unwrap()
            .proposals[0]
                .scanners,
            vec![ScannerType::SupplyChain]
        );
    }

    #[tokio::test]
    async fn publish_outcome_receiver_or_ack_drop_retains_durable_action() {
        let temp = tempfile::tempdir().unwrap();
        let mut action = ConfirmedChatAction::new(
            uuid::Uuid::new_v4(),
            1,
            ChatAction::focus_and_rerun(
                [ScannerType::Sast],
                FocusScope::new([FocusFragment::InputValidation], []).unwrap(),
            )
            .unwrap(),
            [ScannerType::Sast],
        )
        .unwrap();
        action.remaining_scanners.clear();
        let checkpoint = Arc::new(Mutex::new(Checkpoint {
            confirmed_chat_actions: vec![action.clone()],
            ..Checkpoint::default()
        }));
        let (closed_tx, closed_rx) = mpsc::channel(1);
        drop(closed_rx);
        let agent = outcome_test_agent(temp.path(), checkpoint.clone(), closed_tx);
        assert!(agent
            .publish_chat_outcome(
                action.proposal_id,
                ChatActionOutcome::Applied {
                    proposal_id: action.proposal_id,
                    boundary: PhaseBoundary::AfterParallel
                }
            )
            .await
            .is_err());
        assert_eq!(
            checkpoint.lock().unwrap().confirmed_chat_actions,
            vec![action.clone()]
        );

        let (ack_drop_tx, mut ack_drop_rx) = mpsc::channel(1);
        let agent = outcome_test_agent(temp.path(), checkpoint.clone(), ack_drop_tx);
        let receiver = tokio::spawn(async move {
            ack_drop_rx.recv().await;
        });
        assert!(agent
            .publish_chat_outcome(
                action.proposal_id,
                ChatActionOutcome::Applied {
                    proposal_id: action.proposal_id,
                    boundary: PhaseBoundary::AfterParallel
                }
            )
            .await
            .is_err());
        receiver.await.unwrap();
        assert_eq!(
            checkpoint.lock().unwrap().confirmed_chat_actions,
            vec![action]
        );
    }

    #[tokio::test]
    async fn boundary_drain_returns_without_waiting_when_channel_empty() {
        let temp = tempfile::tempdir().unwrap();
        let checkpoint = Arc::new(Mutex::new(Checkpoint::default()));
        let (pending_tx, pending_actions) = mpsc::channel(1);
        let (outcome_tx, _outcome_rx) = mpsc::channel(1);
        let mut agent = OrchestratorAgent::new(
            Arc::new(NoopProvider),
            Arc::new(ToolRegistry::new()),
            Arc::new(StateWriter::new(temp.path()).unwrap()),
            mpsc::channel(1).0,
            CancellationToken::new(),
        )
        .with_chat_runtime(OrchestratorChatRuntime {
            session_id: "test-session".to_string(),
            pending_actions,
            outcome_tx,
            checkpoint,
            snapshot: Arc::new(Mutex::new(ChatSnapshot::default())),
            action_eligible: Arc::new(AtomicBool::new(true)),
        });
        let drained = tokio::time::timeout(
            std::time::Duration::from_millis(25),
            agent.drain_chat_actions(&[ScannerType::Sast]),
        )
        .await
        .expect("empty receiver must not block")
        .unwrap();
        assert!(drained.is_empty());
        drop(pending_tx);
    }

    #[tokio::test]
    async fn mismatch_startup_fails_without_overwriting_shared_checkpoint() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join(".zentra")).unwrap();
        let shared = Checkpoint {
            scanner_set: vec!["sast".to_string()],
            ..Checkpoint::default()
        };
        let checkpoint = Arc::new(Mutex::new(shared.clone()));
        let (pending_tx, pending_actions) = mpsc::channel(1);
        drop(pending_tx);
        let (outcome_tx, _outcome_rx) = mpsc::channel(1);
        let result = OrchestratorAgent::new(
            Arc::new(NoopProvider),
            Arc::new(ToolRegistry::new()),
            Arc::new(StateWriter::new(temp.path()).unwrap()),
            mpsc::channel(1).0,
            CancellationToken::new(),
        )
        .with_resume(Some(Checkpoint {
            scanner_set: vec!["api_scan".to_string()],
            ..Checkpoint::default()
        }))
        .with_chat_runtime(OrchestratorChatRuntime {
            session_id: "test-session".to_string(),
            pending_actions,
            outcome_tx,
            checkpoint: checkpoint.clone(),
            snapshot: Arc::new(Mutex::new(ChatSnapshot::default())),
            action_eligible: Arc::new(AtomicBool::new(true)),
        })
        .run(&[ScannerType::Sast])
        .await;
        assert!(result.is_err());
        assert_eq!(*checkpoint.lock().unwrap(), shared);
    }

    #[test]
    fn snapshot_uses_refreshed_pending_count_after_outcome_removal() {
        let temp = tempfile::tempdir().unwrap();
        let action = ConfirmedChatAction::new(
            uuid::Uuid::new_v4(),
            1,
            ChatAction::focus_and_rerun(
                [ScannerType::Sast],
                FocusScope::new([FocusFragment::InputValidation], []).unwrap(),
            )
            .unwrap(),
            [ScannerType::Sast],
        )
        .unwrap();
        let checkpoint = Arc::new(Mutex::new(Checkpoint {
            confirmed_chat_actions: vec![action.clone()],
            ..Checkpoint::default()
        }));
        let (outcome_tx, _outcome_rx) = mpsc::channel(1);
        let agent = outcome_test_agent(temp.path(), checkpoint.clone(), outcome_tx);
        checkpoint
            .lock()
            .unwrap()
            .remove_confirmed_chat_action_strict(&temp.path().join(".zentra"), action.proposal_id)
            .unwrap();
        let refreshed = agent.shared_checkpoint().unwrap();
        let statuses = HashMap::new();
        let focus = HashMap::new();
        assert!(agent.update_chat_snapshot(
            PhaseBoundary::AfterParallel,
            &statuses,
            &refreshed,
            &focus
        ));
        let snapshot = agent
            .chat_runtime
            .as_ref()
            .unwrap()
            .snapshot
            .lock()
            .unwrap()
            .clone();
        assert_eq!(snapshot.pending_action_count, 0);
    }

    #[test]
    fn rerun_checkpoint_failure_reverts_committed_findings() {
        let temp = tempfile::tempdir().unwrap();
        let checkpoint = Arc::new(Mutex::new(Checkpoint::default()));
        let (outcome_tx, _outcome_rx) = mpsc::channel(1);
        let agent = outcome_test_agent(temp.path(), checkpoint, outcome_tx);
        let staging = agent
            .state_writer
            .begin_findings_rerun("sast", &[])
            .unwrap();
        agent
            .state_writer
            .commit_findings_rerun_pending_progress(&staging)
            .unwrap();
        assert!(temp.path().join(".zentra/detailed-findings.md").exists());

        assert!(agent
            .rollback_after_checkpoint_progress_failure(
                &staging,
                anyhow::anyhow!("checkpoint write failed")
            )
            .is_err());
        assert!(!temp.path().join(".zentra/detailed-findings.md").exists());
    }

    #[test]
    fn committed_journal_without_progress_restores_before_retry() {
        let temp = tempfile::tempdir().unwrap();
        let writer = StateWriter::open(temp.path(), true).unwrap();
        writer
            .write_finding(&test_finding("sast", "original"))
            .unwrap();
        let original = writer.read_findings_raw().unwrap();
        let staging = writer.begin_findings_rerun("sast", &[]).unwrap();
        writer
            .write_finding(&test_finding("sast", "replacement"))
            .unwrap();
        writer
            .commit_findings_rerun_pending_progress(&staging)
            .unwrap();

        writer
            .recover_interrupted_findings_rerun(&Checkpoint::default())
            .unwrap();
        assert_eq!(writer.read_findings_raw().unwrap(), original);
        assert!(writer.begin_findings_rerun("sast", &[]).is_ok());
    }

    #[tokio::test]
    async fn committed_journal_with_progress_preserves_before_recovery_applied() {
        let temp = tempfile::tempdir().unwrap();
        let mut action = focused_sast_action(1);
        action.remaining_scanners.clear();
        let checkpoint_value = Checkpoint {
            completed: ["sast"].into_iter().map(str::to_string).collect(),
            confirmed_chat_actions: vec![action.clone()],
            ..Checkpoint::default()
        };
        let checkpoint = Arc::new(Mutex::new(checkpoint_value.clone()));
        let (runtime, harness, _) = chat_runtime(temp.path(), checkpoint.clone());
        let (agent, _events) = test_agent(
            temp.path(),
            Arc::new(NoopProvider),
            runtime,
            CancellationToken::new(),
        );
        let writer = StateWriter::open(temp.path(), true).unwrap();
        writer
            .write_finding(&test_finding("sast", "original"))
            .unwrap();
        let staging = writer
            .begin_findings_rerun("sast", &[action.proposal_id])
            .unwrap();
        writer
            .write_finding(&test_finding("sast", "replacement"))
            .unwrap();
        writer
            .commit_findings_rerun_pending_progress(&staging)
            .unwrap();
        let committed = writer.read_findings_raw().unwrap();

        writer
            .recover_interrupted_findings_rerun(&checkpoint_value)
            .unwrap();
        assert_eq!(writer.read_findings_raw().unwrap(), committed);
        agent
            .publish_chat_outcome(
                action.proposal_id,
                ChatActionOutcome::Applied {
                    proposal_id: action.proposal_id,
                    boundary: PhaseBoundary::AfterParallel,
                },
            )
            .await
            .unwrap();
        assert!(checkpoint.lock().unwrap().confirmed_chat_actions.is_empty());
        assert!(
            matches!(harness.outcomes.lock().unwrap().as_slice(), [ChatActionOutcome::Applied { proposal_id, .. }] if *proposal_id == action.proposal_id)
        );
        drop(agent);
        drop(harness.pending_tx);
        harness.task.await.unwrap();
    }

    fn focused_sast_action(sequence: u64) -> ConfirmedChatAction {
        ConfirmedChatAction::new(
            uuid::Uuid::new_v4(),
            sequence,
            ChatAction::focus_and_rerun(
                [ScannerType::Sast],
                FocusScope::new([FocusFragment::InputValidation], []).unwrap(),
            )
            .unwrap(),
            [ScannerType::Sast],
        )
        .unwrap()
    }

    #[derive(Debug, Clone)]
    struct ProviderCall {
        label: &'static str,
        system: String,
    }

    /// A deliberately small real-provider harness. It identifies actual scanner
    /// runs from their fixed system prompts rather than short-circuiting the
    /// orchestrator or ScannerAgent.
    struct RecordedProvider {
        calls: Mutex<Vec<ProviderCall>>,
        framework_started: Option<Arc<Notify>>,
        release_framework: Option<Arc<Notify>>,
        sast_started: Option<Arc<Notify>>,
        release_sast: Option<Arc<Notify>>,
        sast_calls: AtomicUsize,
        fail_first_sast: AtomicBool,
        write_on_sast_success: AtomicBool,
    }

    impl RecordedProvider {
        fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                framework_started: None,
                release_framework: None,
                sast_started: None,
                release_sast: None,
                sast_calls: AtomicUsize::new(0),
                fail_first_sast: AtomicBool::new(false),
                write_on_sast_success: AtomicBool::new(false),
            }
        }

        fn label(system: &str) -> &'static str {
            for scanner in [
                ScannerType::FrameworkAnalysis,
                ScannerType::ThreatModel,
                ScannerType::Sast,
                ScannerType::SupplyChain,
                ScannerType::ApiScan,
                ScannerType::IacScan,
                ScannerType::Report,
            ] {
                if system.starts_with(&crate::scanners::system_prompt(scanner)) {
                    return scanner.name();
                }
            }
            if system.starts_with("You are a security finding de-duplication engine") {
                "correlation"
            } else if system.starts_with("You screen security findings for reachability") {
                "screening"
            } else {
                "unknown"
            }
        }

        fn scanner_systems(&self, scanner: ScannerType) -> Vec<String> {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|call| call.label == scanner.name())
                .map(|call| call.system.clone())
                .collect()
        }

        fn labels(&self) -> Vec<&'static str> {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .map(|call| call.label)
                .collect()
        }
    }

    #[async_trait]
    impl LLMProvider for RecordedProvider {
        async fn complete(&self, _: CompletionRequest) -> Result<CompletionResponse> {
            Ok(CompletionResponse {
                content: String::new(),
                tool_calls: Vec::new(),
                usage: TokenUsage::default(),
            })
        }

        async fn complete_with_tools(
            &self,
            system: &str,
            messages: &[AgentMessage],
            _: &[ToolDefinition],
            _: u32,
            _: Option<&CancellationToken>,
        ) -> Result<CompletionResponse> {
            let label = Self::label(system);
            self.calls.lock().unwrap().push(ProviderCall {
                label,
                system: system.to_string(),
            });
            if label == "framework" {
                if let Some(started) = &self.framework_started {
                    started.notify_waiters();
                }
                if let Some(release) = &self.release_framework {
                    release.notified().await;
                }
            }
            if label == "sast" {
                let invocation = self.sast_calls.fetch_add(1, Ordering::SeqCst) + 1;
                if invocation == 1 {
                    if let Some(started) = &self.sast_started {
                        started.notify_waiters();
                    }
                    if let Some(release) = &self.release_sast {
                        release.notified().await;
                    }
                    if self.fail_first_sast.load(Ordering::SeqCst) {
                        anyhow::bail!("scripted first SAST failure");
                    }
                }
                if self.write_on_sast_success.load(Ordering::SeqCst) && messages.len() == 1 {
                    return Ok(CompletionResponse {
                        content: "record replacement".to_string(),
                        tool_calls: vec![ToolCall {
                            id: format!("finding-{invocation}"),
                            name: "write_finding".to_string(),
                            arguments: serde_json::json!({
                                "severity": "high",
                                "title": "replacement target finding",
                                "description": "replacement",
                                "location": "src/lib.rs:1",
                                "recommendation": "fix it"
                            }),
                        }],
                        usage: TokenUsage::default(),
                    });
                }
            }
            let tool_calls = match label {
                "correlation" => vec![ToolCall {
                    id: "clusters".to_string(),
                    name: "report_clusters".to_string(),
                    arguments: serde_json::json!({"clusters": []}),
                }],
                "screening" => vec![ToolCall {
                    id: "screen".to_string(),
                    name: "report_screening".to_string(),
                    arguments: serde_json::json!({"verdicts": []}),
                }],
                _ => Vec::new(),
            };
            Ok(CompletionResponse {
                content: String::new(),
                tool_calls,
                usage: TokenUsage::default(),
            })
        }

        fn context_window(&self) -> u32 {
            128_000
        }

        fn model_name(&self) -> &str {
            "recorded-test"
        }
    }

    struct OutcomeHarness {
        pending_tx: mpsc::Sender<ConfirmedChatAction>,
        outcomes: Arc<Mutex<Vec<ChatActionOutcome>>>,
        task: tokio::task::JoinHandle<()>,
    }

    fn chat_runtime(
        root: &std::path::Path,
        checkpoint: Arc<Mutex<Checkpoint>>,
    ) -> (
        OrchestratorChatRuntime,
        OutcomeHarness,
        Arc<Mutex<ChatSnapshot>>,
    ) {
        let zentra = root.join(".zentra");
        std::fs::create_dir_all(&zentra).unwrap();
        let session_id = {
            let mut value = checkpoint.lock().unwrap();
            if value.session_id.is_empty() {
                value.session_id = "test-session".to_string();
                value.save_strict(&zentra).unwrap();
            }
            value.session_id.clone()
        };
        let (pending_tx, pending_actions) = mpsc::channel(8);
        let (outcome_tx, mut outcome_rx) = mpsc::channel::<ChatActionOutcomeEnvelope>(8);
        let outcomes = Arc::new(Mutex::new(Vec::new()));
        let recorded = outcomes.clone();
        let shared = checkpoint.clone();
        let task = tokio::spawn(async move {
            while let Some(envelope) = outcome_rx.recv().await {
                let result = (|| {
                    let mut checkpoint =
                        shared.lock().map_err(|_| ChatOutcomeFailure::Persistence)?;
                    let action = checkpoint
                        .confirmed_chat_actions
                        .iter()
                        .find(|action| action.proposal_id == envelope.expected.proposal_id)
                        .ok_or(ChatOutcomeFailure::MismatchedAction)?;
                    if action != &envelope.expected {
                        return Err(ChatOutcomeFailure::MismatchedAction);
                    }
                    if matches!(envelope.outcome, ChatActionOutcome::Applied { .. })
                        && !action.remaining_scanners.is_empty()
                    {
                        return Err(ChatOutcomeFailure::AppliedBeforeCompletion);
                    }
                    let proposal_id = action.proposal_id;
                    checkpoint
                        .remove_confirmed_chat_action_strict(&zentra, proposal_id)
                        .map_err(|_| ChatOutcomeFailure::Persistence)?;
                    Ok(ChatOutcomeAck::Committed)
                })();
                if result.is_ok() {
                    recorded.lock().unwrap().push(envelope.outcome.clone());
                }
                let _ = envelope.ack.send(result);
            }
        });
        let snapshot = Arc::new(Mutex::new(ChatSnapshot {
            session_id: session_id.clone(),
            ..ChatSnapshot::default()
        }));
        (
            OrchestratorChatRuntime {
                session_id: session_id.clone(),
                pending_actions,
                outcome_tx,
                checkpoint,
                snapshot: snapshot.clone(),
                action_eligible: Arc::new(AtomicBool::new(true)),
            },
            OutcomeHarness {
                pending_tx,
                outcomes,
                task,
            },
            snapshot,
        )
    }

    fn persist_and_notify(
        root: &std::path::Path,
        checkpoint: &Arc<Mutex<Checkpoint>>,
        tx: &mpsc::Sender<ConfirmedChatAction>,
        action: ConfirmedChatAction,
    ) {
        checkpoint
            .lock()
            .unwrap()
            .save_confirmed_chat_action_strict(&root.join(".zentra"), action.clone())
            .unwrap();
        tx.try_send(action).unwrap();
    }

    fn test_agent(
        root: &std::path::Path,
        provider: Arc<dyn LLMProvider>,
        runtime: OrchestratorChatRuntime,
        cancel: CancellationToken,
    ) -> (OrchestratorAgent, mpsc::Receiver<ScanEvent>) {
        let (tx, rx) = mpsc::channel(128);
        (
            OrchestratorAgent::new(
                provider,
                Arc::new(ToolRegistry::new()),
                Arc::new(StateWriter::new(root).unwrap()),
                tx,
                cancel,
            )
            .with_chat_runtime(runtime),
            rx,
        )
    }

    fn test_finding(scanner: &str, title: &str) -> Finding {
        Finding {
            scanner: scanner.to_string(),
            severity: Severity::High,
            title: title.to_string(),
            description: "test finding".to_string(),
            location: Some("src/lib.rs:1".to_string()),
            recommendation: "fix".to_string(),
            corroborated_by: Vec::new(),
            cwe: None,
            secondary_cwe: Vec::new(),
            cvss_vector: None,
            cvss_score: None,
            owasp: None,
            confidence: None,
            screening: None,
            evidence: None,
        }
    }

    #[tokio::test]
    async fn boundary_accumulates_initial_focus_without_rerun() {
        let temp = tempfile::tempdir().unwrap();
        let action = focused_sast_action(1);
        let checkpoint = Arc::new(Mutex::new(Checkpoint {
            confirmed_chat_actions: vec![action.clone()],
            ..Checkpoint::default()
        }));
        let (runtime, harness, _) = chat_runtime(temp.path(), checkpoint.clone());
        let provider = Arc::new(RecordedProvider::new());
        let (agent, _events) = test_agent(
            temp.path(),
            provider.clone(),
            runtime,
            CancellationToken::new(),
        );

        agent.run(&[ScannerType::Sast]).await.unwrap();

        let calls = provider.scanner_systems(ScannerType::Sast);
        assert_eq!(calls.len(), 1);
        assert!(calls[0].contains("## Chat Focus"));
        assert!(calls[0].contains(FocusFragment::InputValidation.prompt_fragment()));
        assert!(checkpoint.lock().unwrap().confirmed_chat_actions.is_empty());
        assert!(
            matches!(harness.outcomes.lock().unwrap().as_slice(), [ChatActionOutcome::Applied { proposal_id, .. }] if *proposal_id == action.proposal_id)
        );
        drop(harness.pending_tx);
        harness.task.await.unwrap();
    }

    #[tokio::test]
    async fn late_repeated_actions_coalesce_one_rerun_in_deterministic_order() {
        let temp = tempfile::tempdir().unwrap();
        let checkpoint = Arc::new(Mutex::new(Checkpoint::default()));
        let (runtime, harness, _) = chat_runtime(temp.path(), checkpoint.clone());
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let provider = Arc::new(RecordedProvider {
            sast_started: Some(started.clone()),
            release_sast: Some(release.clone()),
            ..RecordedProvider::new()
        });
        let (agent, _events) = test_agent(
            temp.path(),
            provider.clone(),
            runtime,
            CancellationToken::new(),
        );
        let run = tokio::spawn(async move { agent.run(&[ScannerType::Sast]).await });
        tokio::time::timeout(Duration::from_secs(1), started.notified())
            .await
            .expect("initial SAST reaches barrier");
        let first = focused_sast_action(2);
        let second = ConfirmedChatAction::new(
            uuid::Uuid::new_v4(),
            3,
            ChatAction::focus_and_rerun(
                [ScannerType::Sast],
                FocusScope::new([FocusFragment::AuthBoundary], []).unwrap(),
            )
            .unwrap(),
            [ScannerType::Sast],
        )
        .unwrap();
        persist_and_notify(temp.path(), &checkpoint, &harness.pending_tx, first.clone());
        persist_and_notify(
            temp.path(),
            &checkpoint,
            &harness.pending_tx,
            second.clone(),
        );
        release.notify_waiters();
        run.await.unwrap().unwrap();

        let calls = provider.scanner_systems(ScannerType::Sast);
        assert_eq!(calls.len(), 2, "exactly initial plus one coalesced rerun");
        assert!(!calls[0].contains("## Chat Focus"));
        assert!(calls[1].contains(FocusFragment::InputValidation.prompt_fragment()));
        assert!(calls[1].contains(FocusFragment::AuthBoundary.prompt_fragment()));
        assert!(checkpoint.lock().unwrap().confirmed_chat_actions.is_empty());
        let outcomes = harness.outcomes.lock().unwrap().clone();
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes
            .iter()
            .all(|outcome| matches!(outcome, ChatActionOutcome::Applied { .. })));
        drop(harness.pending_tx);
        harness.task.await.unwrap();
    }

    #[tokio::test]
    async fn late_rerun_preserves_initial_and_late_focus_but_advances_only_late() {
        let temp = tempfile::tempdir().unwrap();
        let initial = focused_sast_action(1);
        let late = ConfirmedChatAction::new(
            uuid::Uuid::new_v4(),
            2,
            ChatAction::focus_and_rerun(
                [ScannerType::Sast],
                FocusScope::new([FocusFragment::AuthBoundary], []).unwrap(),
            )
            .unwrap(),
            [ScannerType::Sast],
        )
        .unwrap();
        let checkpoint = Arc::new(Mutex::new(Checkpoint {
            confirmed_chat_actions: vec![initial.clone()],
            ..Checkpoint::default()
        }));
        let (runtime, harness, _) = chat_runtime(temp.path(), checkpoint.clone());
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let provider = Arc::new(RecordedProvider {
            sast_started: Some(started.clone()),
            release_sast: Some(release.clone()),
            ..RecordedProvider::new()
        });
        let (agent, _events) = test_agent(
            temp.path(),
            provider.clone(),
            runtime,
            CancellationToken::new(),
        );
        let run = tokio::spawn(async move { agent.run(&[ScannerType::Sast]).await });
        tokio::time::timeout(Duration::from_secs(1), started.notified())
            .await
            .expect("initial focused SAST reaches barrier");
        persist_and_notify(temp.path(), &checkpoint, &harness.pending_tx, late.clone());
        release.notify_waiters();
        run.await.unwrap().unwrap();

        let calls = provider.scanner_systems(ScannerType::Sast);
        assert_eq!(calls.len(), 2);
        assert!(calls[0].contains(FocusFragment::InputValidation.prompt_fragment()));
        assert!(!calls[0].contains(FocusFragment::AuthBoundary.prompt_fragment()));
        assert!(calls[1].contains(FocusFragment::InputValidation.prompt_fragment()));
        assert!(calls[1].contains(FocusFragment::AuthBoundary.prompt_fragment()));
        assert!(checkpoint.lock().unwrap().confirmed_chat_actions.is_empty());
        let outcomes = harness.outcomes.lock().unwrap().clone();
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.iter().any(|outcome| {
            matches!(outcome, ChatActionOutcome::Applied { proposal_id, .. } if *proposal_id == initial.proposal_id)
        }));
        assert!(outcomes.iter().any(|outcome| {
            matches!(outcome, ChatActionOutcome::Applied { proposal_id, .. } if *proposal_id == late.proposal_id)
        }));
        drop(harness.pending_tx);
        harness.task.await.unwrap();
    }

    #[tokio::test]
    async fn resume_partial_progress_invalidates_before_replay_and_runs_only_remaining() {
        let temp = tempfile::tempdir().unwrap();
        let mut action = ConfirmedChatAction::new(
            uuid::Uuid::new_v4(),
            1,
            ChatAction::focus_and_rerun(
                [ScannerType::Sast, ScannerType::ApiScan],
                FocusScope::new([FocusFragment::InputValidation], []).unwrap(),
            )
            .unwrap(),
            [ScannerType::Sast, ScannerType::ApiScan, ScannerType::Report],
        )
        .unwrap();
        action.remaining_scanners = vec![ScannerType::ApiScan];
        let checkpoint_value = Checkpoint {
            completed: ["sast", "api_scan", "report"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            scanner_set: vec![
                "api_scan".to_string(),
                "report".to_string(),
                "sast".to_string(),
            ],
            session_id: "resume-session".to_string(),
            confirmed_chat_actions: vec![action.clone()],
            ..Checkpoint::default()
        };
        let checkpoint = Arc::new(Mutex::new(checkpoint_value.clone()));
        let (runtime, harness, _) = chat_runtime(temp.path(), checkpoint.clone());
        let provider = Arc::new(RecordedProvider::new());
        let (agent, mut events) = test_agent(
            temp.path(),
            provider.clone(),
            runtime,
            CancellationToken::new(),
        );
        agent
            .with_resume(Some(checkpoint_value))
            .run(&[ScannerType::Sast, ScannerType::ApiScan, ScannerType::Report])
            .await
            .unwrap();

        let labels = provider.labels();
        assert_eq!(labels.iter().filter(|&&label| label == "sast").count(), 0);
        assert_eq!(
            labels.iter().filter(|&&label| label == "api_scan").count(),
            1,
            "calls: {labels:?}"
        );
        assert_eq!(labels.iter().filter(|&&label| label == "report").count(), 1);
        assert!(provider.scanner_systems(ScannerType::ApiScan)[0].contains("## Chat Focus"));
        assert!(checkpoint.lock().unwrap().confirmed_chat_actions.is_empty());
        let mut started = Vec::new();
        while let Ok(event) = events.try_recv() {
            if let ScanEvent::ScannerStarted(scanner) = event {
                started.push(scanner);
            }
        }
        assert_eq!(
            started,
            vec![ScannerType::Sast, ScannerType::ApiScan, ScannerType::Report]
        );
        assert!(
            matches!(harness.outcomes.lock().unwrap().as_slice(), [ChatActionOutcome::Applied { proposal_id, .. }] if *proposal_id == action.proposal_id)
        );
        drop(harness.pending_tx);
        harness.task.await.unwrap();
    }

    #[tokio::test]
    async fn restored_empty_progress_emits_applied_without_scanner_run() {
        let temp = tempfile::tempdir().unwrap();
        let mut action = focused_sast_action(1);
        action.remaining_scanners.clear();
        let checkpoint_value = Checkpoint {
            completed: ["sast"].into_iter().map(str::to_string).collect(),
            scanner_set: vec!["sast".to_string()],
            session_id: "resume-session".to_string(),
            confirmed_chat_actions: vec![action.clone()],
            ..Checkpoint::default()
        };
        let checkpoint = Arc::new(Mutex::new(checkpoint_value.clone()));
        let (runtime, harness, _) = chat_runtime(temp.path(), checkpoint.clone());
        let provider = Arc::new(RecordedProvider::new());
        let (agent, _events) = test_agent(
            temp.path(),
            provider.clone(),
            runtime,
            CancellationToken::new(),
        );
        agent
            .with_resume(Some(checkpoint_value))
            .run(&[ScannerType::Sast])
            .await
            .unwrap();
        assert!(provider.scanner_systems(ScannerType::Sast).is_empty());
        assert!(checkpoint.lock().unwrap().confirmed_chat_actions.is_empty());
        assert!(
            matches!(harness.outcomes.lock().unwrap().as_slice(), [ChatActionOutcome::Applied { proposal_id, .. }] if *proposal_id == action.proposal_id)
        );
        drop(harness.pending_tx);
        harness.task.await.unwrap();
    }

    #[tokio::test]
    async fn cancel_before_rerun_preserves_findings_and_progress_without_applied() {
        let temp = tempfile::tempdir().unwrap();
        let checkpoint = Arc::new(Mutex::new(Checkpoint::default()));
        let (runtime, harness, _) = chat_runtime(temp.path(), checkpoint.clone());
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let provider = Arc::new(RecordedProvider {
            sast_started: Some(started.clone()),
            release_sast: Some(release.clone()),
            ..RecordedProvider::new()
        });
        let cancel = CancellationToken::new();
        let (agent, _events) = test_agent(temp.path(), provider.clone(), runtime, cancel.clone());
        let writer = StateWriter::open(temp.path(), true).unwrap();
        writer
            .write_finding(&test_finding("sast", "seeded target"))
            .unwrap();
        writer
            .write_finding(&test_finding("api_scan", "carried finding"))
            .unwrap();
        let initial_findings = crate::state::parse_findings(&writer.read_findings_raw().unwrap());
        let run = tokio::spawn(async move { agent.run(&[ScannerType::Sast]).await });
        tokio::time::timeout(Duration::from_secs(1), started.notified())
            .await
            .expect("initial SAST reaches barrier");
        let action = focused_sast_action(1);
        persist_and_notify(
            temp.path(),
            &checkpoint,
            &harness.pending_tx,
            action.clone(),
        );
        cancel.cancel();
        release.notify_waiters();
        run.await.unwrap().unwrap();
        assert_eq!(provider.scanner_systems(ScannerType::Sast).len(), 1);
        assert_eq!(
            crate::state::parse_findings(&writer.read_findings_raw().unwrap())
                .iter()
                .map(|finding| (&finding.scanner, &finding.title))
                .collect::<Vec<_>>(),
            initial_findings
                .iter()
                .map(|finding| (&finding.scanner, &finding.title))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            checkpoint.lock().unwrap().confirmed_chat_actions[0].remaining_scanners,
            vec![ScannerType::Sast]
        );
        assert!(harness.outcomes.lock().unwrap().is_empty());
        drop(harness.pending_tx);
        harness.task.await.unwrap();
    }

    #[tokio::test]
    async fn snapshot_tracks_running_completed_failed_focus_and_finalized() {
        let temp = tempfile::tempdir().unwrap();
        let checkpoint = Arc::new(Mutex::new(Checkpoint {
            confirmed_chat_actions: vec![focused_sast_action(1)],
            ..Checkpoint::default()
        }));
        let (runtime, harness, snapshot) = chat_runtime(temp.path(), checkpoint);
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let provider = Arc::new(RecordedProvider {
            sast_started: Some(started.clone()),
            release_sast: Some(release.clone()),
            ..RecordedProvider::new()
        });
        let (agent, _events) = test_agent(temp.path(), provider, runtime, CancellationToken::new());
        let run = tokio::spawn(async move { agent.run(&[ScannerType::Sast]).await });
        tokio::time::timeout(Duration::from_secs(1), started.notified())
            .await
            .expect("SAST enters running state");
        let running = snapshot.lock().unwrap().clone();
        assert_eq!(running.boundary, PhaseBoundary::AfterThreatModel);
        assert!(running.scanner_status.iter().any(|status| {
            status.scanner == "sast" && matches!(status.status, ChatScannerState::Running)
        }));
        assert_eq!(
            running.focus_fragments,
            vec![FocusFragment::InputValidation]
        );
        assert_eq!(running.pending_action_count, 1);
        assert!(running.action_eligible);
        release.notify_waiters();
        run.await.unwrap().unwrap();
        let completed = snapshot.lock().unwrap().clone();
        assert_eq!(completed.boundary, PhaseBoundary::Finalized);
        assert!(!completed.action_eligible);
        assert_eq!(completed.pending_action_count, 0);
        assert!(completed.scanner_status.iter().any(|status| {
            status.scanner == "sast" && matches!(status.status, ChatScannerState::Completed)
        }));
        drop(harness.pending_tx);
        harness.task.await.unwrap();

        let failing_temp = tempfile::tempdir().unwrap();
        let (runtime, failing_harness, failing_snapshot) = chat_runtime(
            failing_temp.path(),
            Arc::new(Mutex::new(Checkpoint::default())),
        );
        let failing_provider = Arc::new(RecordedProvider {
            fail_first_sast: AtomicBool::new(true),
            ..RecordedProvider::new()
        });
        let (agent, _events) = test_agent(
            failing_temp.path(),
            failing_provider,
            runtime,
            CancellationToken::new(),
        );
        let summary = agent.run(&[ScannerType::Sast]).await.unwrap();
        assert_eq!(summary.failed, vec![ScannerType::Sast]);
        assert!(failing_snapshot
            .lock()
            .unwrap()
            .scanner_status
            .iter()
            .any(|status| {
                status.scanner == "sast" && matches!(status.status, ChatScannerState::Failed)
            }));
        drop(failing_harness.pending_tx);
        failing_harness.task.await.unwrap();
    }

    #[tokio::test]
    async fn poisoned_snapshot_defers_once_without_focus_or_rerun() {
        let temp = tempfile::tempdir().unwrap();
        let action = focused_sast_action(1);
        let checkpoint = Arc::new(Mutex::new(Checkpoint {
            confirmed_chat_actions: vec![action.clone()],
            ..Checkpoint::default()
        }));
        let (runtime, harness, snapshot) = chat_runtime(temp.path(), checkpoint.clone());
        let _ = std::panic::catch_unwind(|| {
            let _guard = snapshot.lock().unwrap();
            panic!("poison snapshot for fail-closed path");
        });
        let provider = Arc::new(RecordedProvider::new());
        let (agent, _events) = test_agent(
            temp.path(),
            provider.clone(),
            runtime,
            CancellationToken::new(),
        );
        agent.run(&[ScannerType::Sast]).await.unwrap();
        let calls = provider.scanner_systems(ScannerType::Sast);
        assert_eq!(calls.len(), 1);
        assert!(!calls[0].contains("## Chat Focus"));
        assert!(checkpoint.lock().unwrap().confirmed_chat_actions.is_empty());
        assert!(
            matches!(harness.outcomes.lock().unwrap().as_slice(), [ChatActionOutcome::Deferred { proposal_id, .. }] if *proposal_id == action.proposal_id)
        );
        drop(harness.pending_tx);
        harness.task.await.unwrap();
    }

    #[tokio::test]
    async fn poisoned_resume_snapshot_preserves_completed_findings_and_defers_once() {
        let temp = tempfile::tempdir().unwrap();
        let action = focused_sast_action(1);
        let checkpoint_value = Checkpoint {
            completed: ["sast", "report"].into_iter().map(str::to_string).collect(),
            scanner_set: vec!["report".to_string(), "sast".to_string()],
            session_id: "test-session".to_string(),
            confirmed_chat_actions: vec![action.clone()],
            ..Checkpoint::default()
        };
        let checkpoint = Arc::new(Mutex::new(checkpoint_value.clone()));
        let (runtime, harness, snapshot) = chat_runtime(temp.path(), checkpoint.clone());
        let _ = std::panic::catch_unwind(|| {
            let _guard = snapshot.lock().unwrap();
            panic!("poison resume snapshot");
        });
        let provider = Arc::new(RecordedProvider::new());
        let (agent, _events) = test_agent(
            temp.path(),
            provider.clone(),
            runtime,
            CancellationToken::new(),
        );
        let writer = StateWriter::open(temp.path(), true).unwrap();
        writer
            .write_finding(&test_finding("sast", "preserved target"))
            .unwrap();
        let before = writer.read_findings_raw().unwrap();
        agent
            .with_resume(Some(checkpoint_value))
            .run(&[ScannerType::Sast, ScannerType::Report])
            .await
            .unwrap();

        assert!(provider.scanner_systems(ScannerType::Sast).is_empty());
        assert!(provider.scanner_systems(ScannerType::Report).is_empty());
        assert_eq!(writer.read_findings_raw().unwrap(), before);
        {
            let current = checkpoint.lock().unwrap();
            assert_eq!(
                current.completed,
                ["sast", "report"].into_iter().map(str::to_string).collect()
            );
            assert!(current.confirmed_chat_actions.is_empty());
        }
        assert!(
            matches!(harness.outcomes.lock().unwrap().as_slice(), [ChatActionOutcome::Deferred { proposal_id, .. }] if *proposal_id == action.proposal_id)
        );
        drop(harness.pending_tx);
        harness.task.await.unwrap();
    }

    #[tokio::test]
    async fn poisoned_resume_with_incomplete_report_skips_all_final_passes() {
        let temp = tempfile::tempdir().unwrap();
        let action = ConfirmedChatAction::new(
            uuid::Uuid::new_v4(),
            1,
            ChatAction::focus_and_rerun(
                [ScannerType::Sast],
                FocusScope::new([FocusFragment::InputValidation], []).unwrap(),
            )
            .unwrap(),
            [ScannerType::Sast, ScannerType::Report],
        )
        .unwrap();
        let checkpoint_value = Checkpoint {
            completed: ["sast"].into_iter().map(str::to_string).collect(),
            scanner_set: vec!["report".to_string(), "sast".to_string()],
            session_id: "test-session".to_string(),
            confirmed_chat_actions: vec![action.clone()],
            ..Checkpoint::default()
        };
        let checkpoint = Arc::new(Mutex::new(checkpoint_value.clone()));
        let (runtime, harness, snapshot) = chat_runtime(temp.path(), checkpoint.clone());
        let _ = std::panic::catch_unwind(|| {
            let _guard = snapshot.lock().unwrap();
            panic!("poison incomplete-report resume snapshot");
        });
        let provider = Arc::new(RecordedProvider::new());
        let (agent, _events) = test_agent(
            temp.path(),
            provider.clone(),
            runtime,
            CancellationToken::new(),
        );
        let writer = StateWriter::open(temp.path(), true).unwrap();
        writer
            .write_finding(&test_finding("sast", "preserved target"))
            .unwrap();
        writer
            .write_finding(&test_finding("api_scan", "preserved companion"))
            .unwrap();
        let before = writer.read_findings_raw().unwrap();

        agent
            .with_resume(Some(checkpoint_value))
            .run(&[ScannerType::Sast, ScannerType::Report])
            .await
            .unwrap();

        assert!(provider.scanner_systems(ScannerType::Sast).is_empty());
        assert!(provider.scanner_systems(ScannerType::Report).is_empty());
        let labels = provider.labels();
        assert!(!labels.contains(&"correlation"));
        assert!(!labels.contains(&"screening"));
        assert_eq!(writer.read_findings_raw().unwrap(), before);
        {
            let current = checkpoint.lock().unwrap();
            assert!(current.is_completed("sast"));
            assert!(!current.is_completed("report"));
            assert!(current.confirmed_chat_actions.is_empty());
        }
        assert!(
            matches!(harness.outcomes.lock().unwrap().as_slice(), [ChatActionOutcome::Deferred { proposal_id, .. }] if *proposal_id == action.proposal_id)
        );
        drop(harness.pending_tx);
        harness.task.await.unwrap();

        let persisted = Checkpoint::load_strict(&temp.path().join(".zentra")).unwrap();
        assert!(persisted.is_completed("sast"));
        assert!(!persisted.is_completed("report"));
        assert!(persisted.confirmed_chat_actions.is_empty());
        assert_eq!(writer.read_findings_raw().unwrap(), before);

        let clean_checkpoint = Arc::new(Mutex::new(persisted.clone()));
        let (clean_runtime, clean_harness, _) = chat_runtime(temp.path(), clean_checkpoint);
        let clean_provider = Arc::new(RecordedProvider::new());
        let (clean_tx, _clean_events) = mpsc::channel(128);
        let clean_agent = OrchestratorAgent::new(
            clean_provider.clone(),
            Arc::new(ToolRegistry::new()),
            Arc::new(StateWriter::open(temp.path(), true).unwrap()),
            clean_tx,
            CancellationToken::new(),
        )
        .with_resume(Some(persisted))
        .with_chat_runtime(clean_runtime);
        clean_agent
            .run(&[ScannerType::Sast, ScannerType::Report])
            .await
            .unwrap();
        assert!(clean_provider.scanner_systems(ScannerType::Sast).is_empty());
        assert_eq!(clean_provider.scanner_systems(ScannerType::Report).len(), 1);
        let clean_labels = clean_provider.labels();
        assert_eq!(
            clean_labels
                .iter()
                .filter(|&&label| label == "correlation")
                .count(),
            1
        );
        assert_eq!(
            clean_labels
                .iter()
                .filter(|&&label| label == "screening")
                .count(),
            1
        );
        assert!(!temp.path().join(".zentra/checkpoint.json").exists());
        drop(clean_harness.pending_tx);
        clean_harness.task.await.unwrap();
    }

    #[tokio::test]
    async fn poisoned_snapshot_after_resume_invalidation_restores_completions_without_unfocused_work(
    ) {
        let temp = tempfile::tempdir().unwrap();
        let action = ConfirmedChatAction::new(
            uuid::Uuid::new_v4(),
            1,
            ChatAction::focus_and_rerun(
                [ScannerType::Sast],
                FocusScope::new([FocusFragment::InputValidation], []).unwrap(),
            )
            .unwrap(),
            [
                ScannerType::FrameworkAnalysis,
                ScannerType::Sast,
                ScannerType::Report,
            ],
        )
        .unwrap();
        let checkpoint_value = Checkpoint {
            completed: ["sast", "report"].into_iter().map(str::to_string).collect(),
            scanner_set: vec![
                "framework".to_string(),
                "report".to_string(),
                "sast".to_string(),
            ],
            session_id: "test-session".to_string(),
            confirmed_chat_actions: vec![action.clone()],
            ..Checkpoint::default()
        };
        let checkpoint = Arc::new(Mutex::new(checkpoint_value.clone()));
        let (runtime, harness, snapshot) = chat_runtime(temp.path(), checkpoint.clone());
        let framework_started = Arc::new(Notify::new());
        let release_framework = Arc::new(Notify::new());
        let provider = Arc::new(RecordedProvider {
            framework_started: Some(framework_started.clone()),
            release_framework: Some(release_framework.clone()),
            ..RecordedProvider::new()
        });
        let (agent, _events) = test_agent(
            temp.path(),
            provider.clone(),
            runtime,
            CancellationToken::new(),
        );
        let writer = StateWriter::open(temp.path(), true).unwrap();
        writer
            .write_finding(&test_finding("sast", "seeded target"))
            .unwrap();
        let before = writer.read_findings_raw().unwrap();
        let run = tokio::spawn(async move {
            agent
                .with_resume(Some(checkpoint_value))
                .run(&[
                    ScannerType::FrameworkAnalysis,
                    ScannerType::Sast,
                    ScannerType::Report,
                ])
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), framework_started.notified())
            .await
            .expect("framework reaches the post-invalidation barrier");
        {
            let current = checkpoint.lock().unwrap();
            assert!(!current.is_completed("sast"));
            assert!(!current.is_completed("report"));
        }
        assert_eq!(
            snapshot.lock().unwrap().boundary,
            PhaseBoundary::AfterFramework
        );
        let _ = std::panic::catch_unwind(|| {
            let _guard = snapshot.lock().unwrap();
            panic!("poison after resume invalidation");
        });
        release_framework.notify_waiters();
        run.await.unwrap().unwrap();

        {
            let current = checkpoint.lock().unwrap();
            assert!(current.is_completed("sast"));
            assert!(current.is_completed("report"));
            assert!(current.confirmed_chat_actions.is_empty());
        }
        assert_eq!(writer.read_findings_raw().unwrap(), before);
        assert!(provider.scanner_systems(ScannerType::Sast).is_empty());
        assert!(provider.scanner_systems(ScannerType::Report).is_empty());
        let labels = provider.labels();
        assert!(!labels.contains(&"correlation"));
        assert!(!labels.contains(&"screening"));
        assert!(
            matches!(harness.outcomes.lock().unwrap().as_slice(), [ChatActionOutcome::Deferred { proposal_id, .. }] if *proposal_id == action.proposal_id)
        );
        drop(harness.pending_tx);
        harness.task.await.unwrap();
    }

    #[tokio::test]
    async fn runtime_checkpoint_session_mismatch_executes_nothing_and_preserves_state() {
        let temp = tempfile::tempdir().unwrap();
        let checkpoint_value = Checkpoint {
            session_id: "checkpoint-session".to_string(),
            ..Checkpoint::default()
        };
        let checkpoint = Arc::new(Mutex::new(checkpoint_value.clone()));
        let (mut runtime, harness, _) = chat_runtime(temp.path(), checkpoint.clone());
        runtime.session_id = "runtime-session".to_string();
        let provider = Arc::new(RecordedProvider::new());
        let (agent, _events) = test_agent(
            temp.path(),
            provider.clone(),
            runtime,
            CancellationToken::new(),
        );
        assert!(agent.run(&[ScannerType::Sast]).await.is_err());
        assert!(provider.scanner_systems(ScannerType::Sast).is_empty());
        assert_eq!(*checkpoint.lock().unwrap(), checkpoint_value);
        drop(harness.pending_tx);
        harness.task.await.unwrap();
    }

    #[tokio::test]
    async fn runtime_snapshot_session_mismatch_executes_nothing_and_preserves_state() {
        let temp = tempfile::tempdir().unwrap();
        let checkpoint = Arc::new(Mutex::new(Checkpoint::default()));
        let (runtime, harness, snapshot) = chat_runtime(temp.path(), checkpoint.clone());
        snapshot.lock().unwrap().session_id = "other-session".to_string();
        let provider = Arc::new(RecordedProvider::new());
        let (agent, _events) = test_agent(
            temp.path(),
            provider.clone(),
            runtime,
            CancellationToken::new(),
        );
        let before = checkpoint.lock().unwrap().clone();
        assert!(agent.run(&[ScannerType::Sast]).await.is_err());
        assert!(provider.scanner_systems(ScannerType::Sast).is_empty());
        assert_eq!(*checkpoint.lock().unwrap(), before);
        drop(harness.pending_tx);
        harness.task.await.unwrap();
    }

    #[tokio::test]
    async fn rerun_success_clears_prior_failed_and_transactionally_replaces_target() {
        let temp = tempfile::tempdir().unwrap();
        let action = focused_sast_action(1);
        let checkpoint = Arc::new(Mutex::new(Checkpoint {
            confirmed_chat_actions: vec![action.clone()],
            ..Checkpoint::default()
        }));
        let (runtime, harness, _) = chat_runtime(temp.path(), checkpoint.clone());
        let provider = Arc::new(RecordedProvider {
            fail_first_sast: AtomicBool::new(true),
            write_on_sast_success: AtomicBool::new(true),
            ..RecordedProvider::new()
        });
        let (agent, _events) = test_agent(temp.path(), provider, runtime, CancellationToken::new());
        let writer = StateWriter::open(temp.path(), true).unwrap();
        writer
            .write_finding(&test_finding("sast", "old target finding"))
            .unwrap();
        writer
            .write_finding(&test_finding("api_scan", "other scanner finding"))
            .unwrap();
        let summary = agent.run(&[ScannerType::Sast]).await.unwrap();
        assert!(!summary.failed.contains(&ScannerType::Sast));
        let findings = crate::state::parse_findings(&writer.read_findings_raw().unwrap());
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.scanner == "sast")
                .map(|finding| finding.title.as_str())
                .collect::<Vec<_>>(),
            vec!["replacement target finding"]
        );
        assert!(findings
            .iter()
            .any(|finding| finding.title == "other scanner finding"));
        assert!(checkpoint.lock().unwrap().confirmed_chat_actions.is_empty());
        assert!(
            matches!(harness.outcomes.lock().unwrap().as_slice(), [ChatActionOutcome::Applied { proposal_id, .. }] if *proposal_id == action.proposal_id)
        );
        drop(harness.pending_tx);
        harness.task.await.unwrap();
    }

    #[tokio::test]
    async fn final_pipeline_order_and_count_is_reconcile_correlation_screen_report_once() {
        let temp = tempfile::tempdir().unwrap();
        let checkpoint = Arc::new(Mutex::new(Checkpoint {
            confirmed_chat_actions: vec![focused_sast_action(1)],
            ..Checkpoint::default()
        }));
        let (runtime, harness, _) = chat_runtime(temp.path(), checkpoint);
        let provider = Arc::new(RecordedProvider {
            write_on_sast_success: AtomicBool::new(true),
            ..RecordedProvider::new()
        });
        let trace = Arc::new(Mutex::new(Vec::new()));
        let (agent, _events) = test_agent(
            temp.path(),
            provider.clone(),
            runtime,
            CancellationToken::new(),
        );
        agent
            .with_incremental(
                vec![Finding {
                    location: Some("src/carried.rs:1".to_string()),
                    ..test_finding("api_scan", "carried")
                }],
                change_set(&["src/lib.rs"]),
            )
            .with_test_pipeline_trace(trace.clone())
            .run(&[ScannerType::Sast, ScannerType::Report])
            .await
            .unwrap();
        let labels = provider.labels();
        let first_pipeline = labels
            .iter()
            .position(|label| *label == "correlation")
            .unwrap_or_else(|| panic!("correlation call; calls: {labels:?}"));
        assert!(labels[..first_pipeline].contains(&"sast"));
        assert_eq!(
            labels
                .iter()
                .filter(|&&label| label == "correlation")
                .count(),
            1
        );
        assert_eq!(
            labels.iter().filter(|&&label| label == "screening").count(),
            1
        );
        assert_eq!(labels.iter().filter(|&&label| label == "report").count(), 1);
        assert_eq!(
            *trace.lock().unwrap(),
            vec!["reconcile", "correlate", "screen", "report"]
        );
        drop(harness.pending_tx);
        harness.task.await.unwrap();
    }

    #[test]
    fn proposal_confirmed_while_scanner_running_remains_for_one_focused_rerun() {
        let temp = tempfile::tempdir().unwrap();
        let zentra = temp.path().join(".zentra");
        std::fs::create_dir(&zentra).unwrap();
        let late = focused_sast_action(1);
        let mut checkpoint = Checkpoint {
            confirmed_chat_actions: vec![late.clone()],
            ..Checkpoint::default()
        };
        checkpoint.save_strict(&zentra).unwrap();
        // The initial SAST was spawned before this confirmation, so its exact
        // focus-membership list is empty and cannot consume the late action.
        assert!(checkpoint
            .complete_chat_scanner_strict(&zentra, "sast", &[])
            .unwrap()
            .is_empty());
        let rerun =
            plan_confirmed_chat_actions(&checkpoint.confirmed_chat_actions, &[ScannerType::Sast])
                .unwrap()
                .target(ScannerType::Sast)
                .unwrap()
                .clone();
        assert_eq!(rerun.proposal_ids, vec![late.proposal_id]);
        assert_eq!(
            checkpoint
                .complete_chat_scanner_strict(&zentra, "sast", &rerun.proposal_ids)
                .unwrap(),
            vec![checkpoint.confirmed_chat_actions[0].clone()]
        );
    }

    #[test]
    fn repeated_late_proposals_share_one_rerun_and_all_complete() {
        let temp = tempfile::tempdir().unwrap();
        let zentra = temp.path().join(".zentra");
        std::fs::create_dir(&zentra).unwrap();
        let first = focused_sast_action(1);
        let second = focused_sast_action(2);
        let mut checkpoint = Checkpoint {
            confirmed_chat_actions: vec![first.clone(), second.clone()],
            ..Checkpoint::default()
        };
        checkpoint.save_strict(&zentra).unwrap();
        let plan =
            plan_confirmed_chat_actions(&checkpoint.confirmed_chat_actions, &[ScannerType::Sast])
                .unwrap();
        let target = plan.target(ScannerType::Sast).unwrap();
        assert_eq!(
            target.proposal_ids,
            vec![first.proposal_id, second.proposal_id]
        );
        let complete = checkpoint
            .complete_chat_scanner_strict(&zentra, "sast", &target.proposal_ids)
            .unwrap();
        assert_eq!(complete.len(), 2);
        assert!(complete
            .iter()
            .all(|action| action.remaining_scanners.is_empty()));
    }

    #[test]
    fn initial_focus_action_still_completes_with_one_invocation() {
        let temp = tempfile::tempdir().unwrap();
        let zentra = temp.path().join(".zentra");
        std::fs::create_dir(&zentra).unwrap();
        let action = focused_sast_action(1);
        let mut checkpoint = Checkpoint {
            confirmed_chat_actions: vec![action.clone()],
            ..Checkpoint::default()
        };
        checkpoint.save_strict(&zentra).unwrap();
        let complete = checkpoint
            .complete_chat_scanner_strict(&zentra, "sast", &[action.proposal_id])
            .unwrap();
        assert_eq!(complete.len(), 1);
        assert!(complete[0].remaining_scanners.is_empty());
    }
}
