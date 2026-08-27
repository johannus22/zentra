//! Bounded single-flight coordinator for the isolated chat agent.

use crate::agent::chat::{
    ActionProposal, ChatCommand, ChatError, ChatEvent, ChatLifecycle, ChatRecord, ChatSnapshot,
    ChatStore, ChatTurn, ConfirmedChatAction, FocusScope, ProposalLifecycle, RequestLifecycle,
};
use crate::agent::chat_agent::{ChatAgent, ChatAgentResult};
use crate::agent::checkpoint::Checkpoint;
use crate::agent::ScannerType;
use crate::security::{AuditEvent, SecurityContext};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub const CHAT_COMMAND_CAPACITY: usize = 16;
pub const CHAT_EVENT_CAPACITY: usize = 32;
pub const MAX_QUEUED_CHAT_ASKS: usize = 15;
pub const MAX_PENDING_CHAT_ACTIONS: usize = 16;
/// A single bounded pump owns the receiver-facing event channel.  This lets
/// command/cancellation handling progress when a slow UI has filled it.
const CHAT_TERMINAL_EVENT_CAPACITY: usize = 64;

/// The only path from coordinator state transitions to the UI. Terminal
/// transitions enter a bounded FIFO; queue-position hints are deliberately
/// lossy and are the sole coalesced event class.
#[derive(Clone)]
struct EventDispatcher {
    tx: mpsc::Sender<ChatEvent>,
}

impl EventDispatcher {
    async fn terminal(&self, event: ChatEvent) {
        let _ = self.tx.send(event).await;
    }

    fn queued(&self, request_id: Uuid, position: usize) {
        let _ = self.tx.try_send(ChatEvent::RequestQueued {
            request_id,
            position,
        });
    }
}

pub fn channels() -> (
    mpsc::Sender<ChatCommand>,
    mpsc::Receiver<ChatCommand>,
    mpsc::Sender<ChatEvent>,
    mpsc::Receiver<ChatEvent>,
) {
    let (command_tx, command_rx) = mpsc::channel(CHAT_COMMAND_CAPACITY);
    let (event_tx, event_rx) = mpsc::channel(CHAT_EVENT_CAPACITY);
    (command_tx, command_rx, event_tx, event_rx)
}

pub struct ChatCoordinator {
    agent: ChatAgent,
    security: SecurityContext,
    store: ChatStore,
    snapshot: Arc<Mutex<ChatSnapshot>>,
    root: PathBuf,
    zentra_dir: PathBuf,
    selected: Vec<ScannerType>,
    incremental_paths: Option<Vec<crate::agent::chat::NormalizedRepoPath>>,
    checkpoint: Arc<Mutex<Checkpoint>>,
    pending_tx: mpsc::Sender<ConfirmedChatAction>,
    scan_cancel: CancellationToken,
    confirmation_sequence: u64,
}

impl ChatCoordinator {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        agent: ChatAgent,
        security: SecurityContext,
        store: ChatStore,
        snapshot: Arc<Mutex<ChatSnapshot>>,
        root: PathBuf,
        zentra_dir: PathBuf,
        selected: Vec<ScannerType>,
        incremental_paths: Option<Vec<crate::agent::chat::NormalizedRepoPath>>,
        checkpoint: Arc<Mutex<Checkpoint>>,
        pending_tx: mpsc::Sender<ConfirmedChatAction>,
        scan_cancel: CancellationToken,
    ) -> Self {
        Self {
            agent,
            security,
            store,
            snapshot,
            root,
            zentra_dir,
            selected,
            incremental_paths,
            checkpoint: checkpoint.clone(),
            pending_tx,
            scan_cancel,
            confirmation_sequence: checkpoint
                .lock()
                .ok()
                .and_then(|checkpoint| {
                    checkpoint
                        .confirmed_chat_actions
                        .iter()
                        .map(|a| a.confirmation_sequence)
                        .max()
                })
                .unwrap_or(0),
        }
    }

    /// Own the command receiver; a completion is spawned separately, so this
    /// loop can process Cancel/Confirm/Reject while the provider is in flight.
    pub async fn run(
        mut self,
        mut command_rx: mpsc::Receiver<ChatCommand>,
        event_tx: mpsc::Sender<ChatEvent>,
    ) {
        // Only this bounded, single task awaits the external receiver channel.
        // Terminal events retain FIFO delivery; best-effort queue notices may
        // be coalesced when the UI is behind.
        let external_event_tx = event_tx;
        let (event_tx, mut event_rx) = mpsc::channel(CHAT_TERMINAL_EVENT_CAPACITY);
        let events = EventDispatcher {
            tx: event_tx.clone(),
        };
        let event_pump = tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                if matches!(event, ChatEvent::RequestQueued { .. }) {
                    let _ = external_event_tx.try_send(event);
                } else if external_event_tx.send(event).await.is_err() {
                    break;
                }
            }
        });
        let mut queued: VecDeque<(Uuid, String)> = VecDeque::new();
        let mut turns: VecDeque<ChatTurn> = VecDeque::new();
        let mut proposals: HashMap<Uuid, ActionProposal> = HashMap::new();
        let (result_tx, mut result_rx) = mpsc::channel(1);
        let mut active: Option<(Uuid, u64, CancellationToken, JoinHandle<()>)> = None;
        let mut generation = 0u64;
        let mut expiry_tick = tokio::time::interval(std::time::Duration::from_secs(1));

        loop {
            if active.is_none() {
                if let Some((request_id, request)) = queued.pop_front() {
                    self.persist_request(
                        request_id,
                        RequestLifecycle::Running,
                        Some(request.clone()),
                        &events,
                    )
                    .await;
                    let snapshot = match self.snapshot() {
                        Ok(snapshot) => snapshot,
                        Err(reason) => {
                            events
                                .terminal(error(Some(request_id), ChatError::Security, &reason))
                                .await;
                            continue;
                        }
                    };
                    let request_cancel = self.scan_cancel.child_token();
                    let agent = self.agent.clone();
                    let history = turns.iter().cloned().collect();
                    let tx = result_tx.clone();
                    generation = generation.wrapping_add(1);
                    let task_generation = generation;
                    let task_cancel = request_cancel.clone();
                    let task = tokio::spawn(async move {
                        let result = agent
                            .run(request_id, request, snapshot, history, task_cancel)
                            .await;
                        let _ = tx.send((task_generation, result)).await;
                    });
                    active = Some((request_id, task_generation, request_cancel.clone(), task));
                }
            }

            tokio::select! {
                _ = expiry_tick.tick() => {
                    let now = chrono::Utc::now();
                    let expired: Vec<_> = proposals.values()
                        .filter(|proposal| proposal.expires_at <= now)
                        .map(|proposal| proposal.proposal_id)
                        .collect();
                    for proposal_id in expired {
                        if let Some(proposal) = proposals.remove(&proposal_id) {
                            self.persist_proposal(proposal_id, ProposalLifecycle::Expired, Some(proposal.action), &events).await;
                            events.terminal(ChatEvent::Deferred { proposal_id, reason: "proposal expired".to_string() }).await;
                        }
                    }
                }
                _ = self.scan_cancel.cancelled() => {
                    if let Some((request_id, _, cancel, task)) = active.take() {
                        cancel.cancel();
                        task.abort();
                        self.persist_request(request_id, RequestLifecycle::Cancelled, None, &events).await;
                        events.terminal(ChatEvent::Cancelled { request_id }).await;
                    }
                    while let Some((request_id, _)) = queued.pop_front() {
                        self.persist_request(request_id, RequestLifecycle::Cancelled, None, &events).await;
                        events.terminal(ChatEvent::Cancelled { request_id }).await;
                    }
                    self.drain_proposals(&mut proposals, ProposalLifecycle::Cancelled, &events).await;
                    break;
                }
                Some(command) = command_rx.recv() => {
                    match command {
                        ChatCommand::Ask { request_id, text } => {
                            if ChatCommand::ask(request_id, text.clone()).is_err() || active.as_ref().is_some_and(|(id, _, _, _)| *id == request_id) || queued.iter().any(|(id, _)| *id == request_id) || proposals.values().any(|proposal| proposal.request_id == request_id) {
                                let _ = events.terminal(error(Some(request_id), ChatError::InvalidProposal, "invalid or duplicate chat request ID")).await;
                                continue;
                            }
                            if active.is_some() && queued.len() >= MAX_QUEUED_CHAT_ASKS {
                                let _ = events.terminal(error(Some(request_id), ChatError::Backpressure, "chat request queue is full")).await;
                            } else {
                                let position = usize::from(active.is_some()) + queued.len();
                                self.persist_request(request_id, RequestLifecycle::Queued, Some(text.clone()), &events).await;
                                queued.push_back((request_id, text));
                                events.queued(request_id, position);
                            }
                        }
                        ChatCommand::Cancel { request_id } => {
                            if active.as_ref().is_some_and(|(id, _, _, _)| *id == request_id) {
                                if let Some((_, _, cancel, task)) = active.take() { cancel.cancel(); task.abort(); }
                                self.persist_request(request_id, RequestLifecycle::Cancelled, None, &events).await;
                                let _ = events.terminal(ChatEvent::Cancelled { request_id }).await;
                            } else if let Some(index) = queued.iter().position(|(id, _)| *id == request_id) {
                                queued.remove(index);
                                self.persist_request(request_id, RequestLifecycle::Cancelled, None, &events).await;
                                let _ = events.terminal(ChatEvent::Cancelled { request_id }).await;
                            }
                            let proposal_ids: Vec<_> = proposals.values().filter(|proposal| proposal.request_id == request_id).map(|proposal| proposal.proposal_id).collect();
                            for proposal_id in proposal_ids {
                                if let Some(proposal) = proposals.remove(&proposal_id) {
                                    self.persist_proposal(proposal_id, ProposalLifecycle::Cancelled, Some(proposal.action), &events).await;
                                }
                            }
                        }
                        ChatCommand::Reject { proposal_id } => {
                            if proposals.remove(&proposal_id).is_some() {
                                self.persist_proposal(proposal_id, ProposalLifecycle::Rejected, None, &events).await;
                            }
                        }
                        ChatCommand::Confirm { proposal_id } => {
                            if let Some(proposal) = proposals.get(&proposal_id).cloned() {
                                if self.confirm(proposal, &events).await { proposals.remove(&proposal_id); }
                            } else {
                                let _ = events.terminal(error(None, ChatError::InvalidProposal, "proposal is unknown, expired, or already resolved")).await;
                            }
                        }
                        ChatCommand::Close => {
                            if let Some((request_id, _, cancel, task)) = active.take() { cancel.cancel(); task.abort(); let _ = events.terminal(ChatEvent::Cancelled { request_id }).await; }
                            while let Some((request_id, _)) = queued.pop_front() { self.persist_request(request_id, RequestLifecycle::Cancelled, None, &events).await; events.terminal(ChatEvent::Cancelled { request_id }).await; }
                            self.drain_proposals(&mut proposals, ProposalLifecycle::Cancelled, &events).await;
                            break;
                        }
                    }
                }
                Some((result_generation, result)) = result_rx.recv() => {
                    let Some((active_id, active_generation, _, _)) = active.as_ref() else { continue };
                    let active_id = *active_id;
                    let result_request_id = result.as_ref().ok().map(|result| result.request_id);
                    if !result_matches_active(active_id, *active_generation, result_generation, result_request_id) { continue; }
                    match result {
                        Ok(result) if result.request_id == active_id => {
                            active.take();
                            self.handle_result(result, &mut proposals, &mut turns, &events).await;
                        }
                        Ok(_) => continue, // stale task output must not affect a new request
                        Err(error_result) => {
                            active.take();
                            self.persist_request(active_id, RequestLifecycle::Failed, None, &events).await;
                            let _ = events.terminal(error(Some(active_id), error_result.kind, &error_result.message)).await;
                        }
                    }
                }
                else => break,
            }
        }
        // The bounded pump owns delivery after coordinator shutdown. Dropping
        // the last internal sender lets it drain FIFO and exit naturally, while
        // dropping its JoinHandle detaches it so a stalled UI cannot hold scan
        // cancellation hostage.
        drop(events);
        drop(event_tx);
        drop(event_pump);
    }

    async fn handle_result(
        &self,
        result: ChatAgentResult,
        proposals: &mut HashMap<Uuid, ActionProposal>,
        turns: &mut VecDeque<ChatTurn>,
        event_tx: &EventDispatcher,
    ) {
        // A proposal is an all-or-nothing result. Do not publish its accompanying
        // prose or record a Proposed lifecycle until the *complete* plan is
        // admissible at this boundary.
        if let Some(proposal) = result.proposal.as_ref() {
            let failure = if proposals.len() >= MAX_PENDING_CHAT_ACTIONS {
                Some((
                    ChatError::Backpressure,
                    "proposal capacity reached".to_string(),
                ))
            } else {
                self.validate_proposal(proposal)
                    .err()
                    .map(|reason| (ChatError::InvalidProposal, reason))
            };
            if let Some((kind, reason)) = failure {
                self.persist_request(result.request_id, RequestLifecycle::Failed, None, event_tx)
                    .await;
                event_tx
                    .terminal(error(Some(result.request_id), kind, &reason))
                    .await;
                return;
            }
        }
        self.persist_request(
            result.request_id,
            if result.proposal.is_some() {
                RequestLifecycle::Proposed
            } else {
                RequestLifecycle::Answered
            },
            Some(result.answer.clone()),
            event_tx,
        )
        .await;
        event_tx
            .terminal(ChatEvent::Answer {
                request_id: result.request_id,
                text: result.answer.clone(),
            })
            .await;
        turns.push_back(ChatTurn {
            request_id: result.request_id,
            request: result.request,
            response: crate::logging::redact(&result.answer),
        });
        while turns.len() > crate::agent::chat::MAX_CHAT_TURNS {
            turns.pop_front();
        }
        if let Some(proposal) = result.proposal {
            self.persist_proposal(
                proposal.proposal_id,
                ProposalLifecycle::Proposed,
                Some(proposal.action.clone()),
                event_tx,
            )
            .await;
            proposals.insert(proposal.proposal_id, proposal.clone());
            event_tx.terminal(ChatEvent::Proposal { proposal }).await;
        }
    }

    async fn drain_proposals(
        &self,
        proposals: &mut HashMap<Uuid, ActionProposal>,
        state: ProposalLifecycle,
        event_tx: &EventDispatcher,
    ) {
        for (_, proposal) in std::mem::take(proposals) {
            self.persist_proposal(proposal.proposal_id, state, Some(proposal.action), event_tx)
                .await;
        }
    }

    async fn confirm(&mut self, proposal: ActionProposal, event_tx: &EventDispatcher) -> bool {
        if self.scan_cancel.is_cancelled() {
            self.defer_cancelled_proposal(&proposal, event_tx).await;
            return true;
        }
        if self
            .snapshot()
            .map(|snapshot| snapshot.boundary)
            .unwrap_or(crate::agent::chat::PhaseBoundary::Finalized)
            == crate::agent::chat::PhaseBoundary::Finalized
        {
            self.persist_proposal(
                proposal.proposal_id,
                ProposalLifecycle::Deferred,
                Some(proposal.action),
                event_tx,
            )
            .await;
            event_tx
                .terminal(ChatEvent::Deferred {
                    proposal_id: proposal.proposal_id,
                    reason: "the scan has reached its final boundary".to_string(),
                })
                .await;
            return true;
        }
        if let Err(error_value) = self.validate_proposal(&proposal) {
            self.persist_proposal(
                proposal.proposal_id,
                ProposalLifecycle::Rejected,
                Some(proposal.action),
                event_tx,
            )
            .await;
            event_tx
                .terminal(error(None, ChatError::InvalidProposal, &error_value))
                .await;
            return true;
        }
        let permit = match self.pending_tx.clone().try_reserve_owned() {
            Ok(permit) => permit,
            Err(_) => {
                event_tx
                    .terminal(error(
                        None,
                        ChatError::Backpressure,
                        "pending chat-action queue is full",
                    ))
                    .await;
                return false;
            }
        };
        // Reservation prevents publication races; this single critical section
        // revalidates against the exact durable action set and persists it with
        // no checkpoint-lock gap.
        let saved = (|| {
            let mut checkpoint = self.checkpoint.lock().map_err(|_| {
                (
                    ChatError::Persistence,
                    "checkpoint lock poisoned".to_string(),
                )
            })?;
            self.validate_proposal_with_checkpoint(&proposal, &checkpoint)
                .map_err(|error| (ChatError::InvalidProposal, error))?;
            let confirmation_sequence = checkpoint
                .confirmed_chat_actions
                .iter()
                .map(|action| action.confirmation_sequence)
                .max()
                .unwrap_or(self.confirmation_sequence)
                .max(self.confirmation_sequence)
                .saturating_add(1);
            let action = ConfirmedChatAction::new(
                proposal.proposal_id,
                confirmation_sequence,
                proposal.action.clone(),
                self.selected.clone(),
            )
            .map_err(|error_value| (ChatError::InvalidProposal, error_value.to_string()))?;
            checkpoint
                .save_confirmed_chat_action_strict(&self.zentra_dir, action.clone())
                .map_err(|error_value| (ChatError::Persistence, error_value.to_string()))?;
            Ok::<_, (ChatError, String)>((confirmation_sequence, action))
        })();
        let (confirmation_sequence, action) = match saved {
            Ok(saved) => saved,
            Err((kind, error_value)) => {
                event_tx.terminal(error(None, kind, &error_value)).await;
                return kind == ChatError::InvalidProposal;
            }
        };
        self.confirmation_sequence = confirmation_sequence;
        // The scan may have ended while the strict checkpoint write was in
        // progress. Do not publish new pending work after cancellation; the
        // durable record is intentionally left for the strict resume path.
        if self.scan_cancel.is_cancelled() {
            let _ = self
                .checkpoint
                .lock()
                .map_err(|_| ())
                .and_then(|mut checkpoint| {
                    checkpoint
                        .remove_confirmed_chat_action_strict(&self.zentra_dir, proposal.proposal_id)
                        .map(|_| ())
                        .map_err(|_| ())
                });
            self.defer_cancelled_proposal(&proposal, event_tx).await;
            return true;
        }
        permit.send(action);
        if let Ok(event) = AuditEvent::chat_action_confirmed(proposal.proposal_id, &proposal.action)
        {
            self.security.record(event);
        }
        self.persist_proposal(
            proposal.proposal_id,
            ProposalLifecycle::PendingBoundary,
            Some(proposal.action),
            event_tx,
        )
        .await;
        event_tx
            .terminal(ChatEvent::Confirmed {
                proposal_id: proposal.proposal_id,
            })
            .await;
        true
    }

    /// A proposal which races scan cancellation must be resolved visibly, even
    /// when cancellation is observed inside confirmation rather than by the
    /// outer event loop.  In particular, it must never remain retryable after
    /// its strict checkpoint record has been removed.
    async fn defer_cancelled_proposal(
        &self,
        proposal: &ActionProposal,
        event_tx: &EventDispatcher,
    ) {
        self.persist_proposal(
            proposal.proposal_id,
            ProposalLifecycle::Deferred,
            Some(proposal.action.clone()),
            event_tx,
        )
        .await;
        event_tx
            .terminal(ChatEvent::Deferred {
                proposal_id: proposal.proposal_id,
                reason: "scan cancelled before the action could be queued".to_string(),
            })
            .await;
    }

    fn validate_proposal(&self, proposal: &ActionProposal) -> Result<(), String> {
        let checkpoint = self
            .checkpoint
            .lock()
            .map_err(|_| "checkpoint lock poisoned".to_string())?;
        self.validate_proposal_with_checkpoint(proposal, &checkpoint)
    }

    fn validate_proposal_with_checkpoint(
        &self,
        proposal: &ActionProposal,
        checkpoint: &Checkpoint,
    ) -> Result<(), String> {
        proposal
            .validate(&self.selected)
            .map_err(|error_value| error_value.to_string())?;
        if let crate::agent::chat::ChatAction::FocusAndRerun { scope, .. } = &proposal.action {
            validate_scope(scope, &self.root, self.incremental_paths.as_deref())
                .map_err(|error_value| error_value.to_string())?;
        }
        let snapshot = self.snapshot()?;
        if !checkpoint.session_id.is_empty() && checkpoint.session_id != snapshot.session_id {
            return Err("chat session does not match checkpoint".to_string());
        }
        if !checkpoint.scanner_set.is_empty()
            && scanner_names(&self.selected)
                != checkpoint
                    .scanner_set
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>()
        {
            return Err("scanner set does not exactly match checkpoint".to_string());
        }
        let mut actions: Vec<&crate::agent::chat::ChatAction> = checkpoint
            .confirmed_chat_actions
            .iter()
            .map(|action| &action.action)
            .collect();
        actions.push(&proposal.action);
        crate::agent::chat::ChatAction::validate_coalesced_plan(&actions, &self.selected)
            .map_err(|error_value| error_value.to_string())?;
        Ok(())
    }

    fn snapshot(&self) -> Result<ChatSnapshot, String> {
        self.snapshot
            .lock()
            .map_err(|_| "chat snapshot lock poisoned".to_string())?
            .clone()
            .try_bounded()
            .map_err(|error| error.to_string())
    }

    async fn persist_request(
        &self,
        request_id: Uuid,
        state: RequestLifecycle,
        text: Option<String>,
        event_tx: &EventDispatcher,
    ) {
        self.persist(
            ChatRecord::new(
                match self.snapshot() {
                    Ok(snapshot) => snapshot.session_id,
                    Err(reason) => {
                        event_tx
                            .terminal(error(Some(request_id), ChatError::Security, &reason))
                            .await;
                        return;
                    }
                },
                Some(request_id),
                None,
                ChatLifecycle::Request { state },
                text,
                None,
            ),
            Some(request_id),
            event_tx,
        )
        .await;
    }
    async fn persist_proposal(
        &self,
        proposal_id: Uuid,
        state: ProposalLifecycle,
        action: Option<crate::agent::chat::ChatAction>,
        event_tx: &EventDispatcher,
    ) {
        self.persist(
            ChatRecord::new(
                match self.snapshot() {
                    Ok(snapshot) => snapshot.session_id,
                    Err(reason) => {
                        event_tx
                            .terminal(error(None, ChatError::Security, &reason))
                            .await;
                        return;
                    }
                },
                None,
                Some(proposal_id),
                ChatLifecycle::Proposal { state },
                None,
                action,
            ),
            None,
            event_tx,
        )
        .await;
    }
    async fn persist(
        &self,
        record: Result<ChatRecord, crate::agent::chat::ChatValidationError>,
        request_id: Option<Uuid>,
        event_tx: &EventDispatcher,
    ) {
        if record
            .and_then(|record| {
                self.store
                    .append(&record)
                    .map_err(|_| crate::agent::chat::ChatValidationError::TextLimit)
            })
            .is_err()
        {
            event_tx
                .terminal(error(
                    request_id,
                    ChatError::Persistence,
                    "chat transcript could not be persisted",
                ))
                .await;
        }
    }
}

fn result_matches_active(
    active_id: Uuid,
    active_generation: u64,
    result_generation: u64,
    result_request_id: Option<Uuid>,
) -> bool {
    active_generation == result_generation && result_request_id.is_none_or(|id| id == active_id)
}

fn validate_scope(
    scope: &FocusScope,
    root: &std::path::Path,
    incremental: Option<&[crate::agent::chat::NormalizedRepoPath]>,
) -> Result<(), crate::agent::chat::ChatValidationError> {
    scope.validate_within_root(root)?;
    if let Some(allowed) = incremental {
        scope.validate_subset_of(allowed)?;
    }
    Ok(())
}
fn scanner_names(scanners: &[ScannerType]) -> BTreeSet<String> {
    scanners
        .iter()
        .map(|scanner| scanner.name().to_string())
        .collect()
}
fn error(request_id: Option<Uuid>, kind: ChatError, message: &str) -> ChatEvent {
    let message = crate::logging::redact(message);
    let mut end = message
        .len()
        .min(crate::agent::chat::MAX_LIFECYCLE_MESSAGE_BYTES);
    while end > 0 && !message.is_char_boundary(end) {
        end -= 1;
    }
    ChatEvent::Error {
        request_id,
        kind,
        message: message[..end].to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::chat_agent::ChatAgent;
    use crate::provider::{
        AgentMessage, CompletionRequest, CompletionResponse, LLMProvider, TokenUsage, ToolCall,
        ToolDefinition,
    };
    use crate::security::{AuditLog, SecurityConfig};
    use anyhow::Result;
    use async_trait::async_trait;
    use std::collections::VecDeque;
    use tokio::sync::Notify;

    struct MockProvider(Mutex<VecDeque<CompletionResponse>>);
    #[async_trait]
    impl LLMProvider for MockProvider {
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
            self.0
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("no response"))
        }
        fn context_window(&self) -> u32 {
            32_000
        }
        fn model_name(&self) -> &str {
            "mock"
        }
    }

    struct BlockingProvider {
        started: Arc<Notify>,
    }
    #[async_trait]
    impl LLMProvider for BlockingProvider {
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
            self.started.notify_one();
            std::future::pending().await
        }
        fn context_window(&self) -> u32 {
            32_000
        }
        fn model_name(&self) -> &str {
            "blocking"
        }
    }

    #[tokio::test]
    async fn proposal_requires_local_confirm_before_it_becomes_pending() {
        let temp = tempfile::tempdir().unwrap();
        let zentra = temp.path().join(".zentra");
        std::fs::create_dir(&zentra).unwrap();
        let security = SecurityContext::new(
            SecurityConfig::trusted_local(),
            AuditLog::new(&zentra, "chat-test", false).unwrap(),
        );
        let call = ToolCall {
            id: "p".into(),
            name: "propose_scan_action".into(),
            arguments: serde_json::json!({"type":"focus_and_rerun","scanners":["sast"],"scope":{"fragments":["input_validation"],"paths":[]}}),
        };
        let provider: Arc<dyn LLMProvider> = Arc::new(MockProvider(Mutex::new(VecDeque::from([
            CompletionResponse {
                content: "proposal ready".into(),
                tool_calls: vec![call],
                usage: TokenUsage::default(),
            },
        ]))));
        let agent = ChatAgent::from_raw_provider(
            provider,
            Arc::new(crate::tools::ToolRegistry::new()),
            security.clone(),
            CancellationToken::new(),
        );
        let snapshot = Arc::new(Mutex::new(ChatSnapshot {
            session_id: "chat-test".into(),
            boundary: crate::agent::chat::PhaseBoundary::AfterFramework,
            selected_scanners: vec!["sast".into()],
            ..Default::default()
        }));
        let store = ChatStore::new(&zentra, "chat-test").unwrap();
        let checkpoint = Arc::new(Mutex::new(Checkpoint {
            session_id: "chat-test".into(),
            scanner_set: vec!["sast".into()],
            ..Default::default()
        }));
        let (pending_tx, mut pending_rx) = mpsc::channel(MAX_PENDING_CHAT_ACTIONS);
        let cancel = CancellationToken::new();
        let coordinator = ChatCoordinator::new(
            agent,
            security,
            store,
            snapshot,
            temp.path().to_path_buf(),
            zentra,
            vec![ScannerType::Sast],
            None,
            checkpoint,
            pending_tx,
            cancel.clone(),
        );
        let (command_tx, command_rx, event_tx, mut event_rx) = channels();
        let task = tokio::spawn(coordinator.run(command_rx, event_tx));
        let request_id = Uuid::new_v4();
        command_tx
            .send(ChatCommand::Ask {
                request_id,
                text: "focus input validation".into(),
            })
            .await
            .unwrap();
        let proposal_id = loop {
            match tokio::time::timeout(std::time::Duration::from_secs(1), event_rx.recv())
                .await
                .unwrap()
                .unwrap()
            {
                ChatEvent::Proposal { proposal } => break proposal.proposal_id,
                _ => continue,
            }
        };
        assert!(pending_rx.try_recv().is_err());
        command_tx
            .send(ChatCommand::Confirm { proposal_id })
            .await
            .unwrap();
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(1), event_rx.recv())
                .await
                .unwrap()
                .unwrap()
            {
                ChatEvent::Confirmed { proposal_id: id } if id == proposal_id => break,
                _ => continue,
            }
        }
        assert_eq!(pending_rx.recv().await.unwrap().proposal_id, proposal_id);
        cancel.cancel();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn full_external_event_channel_does_not_block_cancel_processing() {
        let temp = tempfile::tempdir().unwrap();
        let zentra = temp.path().join(".zentra");
        std::fs::create_dir(&zentra).unwrap();
        let security = SecurityContext::new(
            SecurityConfig::trusted_local(),
            AuditLog::new(&zentra, "chat-full-events", false).unwrap(),
        );
        let started = Arc::new(Notify::new());
        let agent = ChatAgent::from_raw_provider(
            Arc::new(BlockingProvider {
                started: started.clone(),
            }),
            Arc::new(crate::tools::ToolRegistry::new()),
            security.clone(),
            CancellationToken::new(),
        );
        let snapshot = Arc::new(Mutex::new(ChatSnapshot {
            session_id: "chat-full-events".into(),
            boundary: crate::agent::chat::PhaseBoundary::AfterFramework,
            selected_scanners: vec!["sast".into()],
            ..Default::default()
        }));
        let store = ChatStore::new(&zentra, "chat-full-events").unwrap();
        let checkpoint = Arc::new(Mutex::new(Checkpoint {
            session_id: "chat-full-events".into(),
            scanner_set: vec!["sast".into()],
            ..Default::default()
        }));
        let (pending_tx, _) = mpsc::channel(MAX_PENDING_CHAT_ACTIONS);
        let cancel = CancellationToken::new();
        let coordinator = ChatCoordinator::new(
            agent,
            security,
            store.clone(),
            snapshot,
            temp.path().to_path_buf(),
            zentra,
            vec![ScannerType::Sast],
            None,
            checkpoint,
            pending_tx,
            cancel,
        );
        let (command_tx, command_rx, event_tx, mut event_rx) = channels();
        let prefilled: Vec<_> = (0..CHAT_EVENT_CAPACITY).map(|_| Uuid::new_v4()).collect();
        for request_id in &prefilled {
            event_tx
                .send(ChatEvent::Cancelled {
                    request_id: *request_id,
                })
                .await
                .unwrap();
        }
        let task = tokio::spawn(coordinator.run(command_rx, event_tx));
        let request_id = Uuid::new_v4();
        command_tx
            .send(ChatCommand::Ask {
                request_id,
                text: "wait".into(),
            })
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), started.notified())
            .await
            .unwrap();
        command_tx
            .send(ChatCommand::Cancel { request_id })
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if std::fs::read_to_string(store.path())
                    .unwrap_or_default()
                    .contains("cancelled")
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        // Keep the receiver full while shutdown returns; the detached bounded
        // pump retains terminal delivery ownership.
        command_tx.send(ChatCommand::Close).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        let mut delivered = Vec::new();
        while let Some(event) =
            tokio::time::timeout(std::time::Duration::from_secs(1), event_rx.recv())
                .await
                .unwrap()
        {
            delivered.push(event);
        }
        assert_eq!(delivered.len(), CHAT_EVENT_CAPACITY + 1);
        for (event, request_id) in delivered.iter().take(CHAT_EVENT_CAPACITY).zip(prefilled) {
            assert!(matches!(event, ChatEvent::Cancelled { request_id: id } if *id == request_id));
        }
        assert!(
            matches!(delivered.last(), Some(ChatEvent::Cancelled { request_id: id }) if *id == request_id)
        );
    }

    fn test_coordinator(
        temp: &tempfile::TempDir,
        session: &str,
        selected: Vec<ScannerType>,
        checkpoint: Arc<Mutex<Checkpoint>>,
        snapshot: Arc<Mutex<ChatSnapshot>>,
        pending_capacity: usize,
    ) -> (
        ChatCoordinator,
        CancellationToken,
        mpsc::Receiver<ConfirmedChatAction>,
    ) {
        let zentra = temp.path().join(".zentra");
        std::fs::create_dir_all(&zentra).unwrap();
        let security = SecurityContext::new(
            SecurityConfig::trusted_local(),
            AuditLog::new(&zentra, session, false).unwrap(),
        );
        let agent = ChatAgent::from_raw_provider(
            Arc::new(MockProvider(Mutex::new(VecDeque::new()))),
            Arc::new(crate::tools::ToolRegistry::new()),
            security.clone(),
            CancellationToken::new(),
        );
        let store = ChatStore::new(&zentra, session).unwrap();
        let (pending_tx, pending_rx) = mpsc::channel(pending_capacity);
        let cancel = CancellationToken::new();
        (
            ChatCoordinator::new(
                agent,
                security,
                store,
                snapshot,
                temp.path().to_path_buf(),
                zentra,
                selected,
                None,
                checkpoint,
                pending_tx,
                cancel.clone(),
            ),
            cancel,
            pending_rx,
        )
    }

    fn test_snapshot(
        session: &str,
        boundary: crate::agent::chat::PhaseBoundary,
    ) -> Arc<Mutex<ChatSnapshot>> {
        Arc::new(Mutex::new(ChatSnapshot {
            session_id: session.into(),
            boundary,
            selected_scanners: vec!["sast".into()],
            ..Default::default()
        }))
    }

    fn test_checkpoint(session: &str) -> Arc<Mutex<Checkpoint>> {
        Arc::new(Mutex::new(Checkpoint {
            session_id: session.into(),
            scanner_set: vec!["sast".into()],
            ..Default::default()
        }))
    }

    fn proposal(request_id: Uuid, action: crate::agent::chat::ChatAction) -> ActionProposal {
        let now = chrono::Utc::now();
        ActionProposal {
            proposal_id: Uuid::new_v4(),
            request_id,
            action,
            created_at: now,
            expires_at: now + chrono::Duration::minutes(1),
            earliest_boundary: crate::agent::chat::PhaseBoundary::AfterFramework,
        }
    }

    fn sast_focus() -> crate::agent::chat::ChatAction {
        crate::agent::chat::ChatAction::focus_and_rerun(
            [ScannerType::Sast],
            FocusScope::new([crate::agent::chat::FocusFragment::InputValidation], []).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn late_old_generation_result_cannot_consume_new_active_request() {
        let old_request = Uuid::new_v4();
        let new_request = Uuid::new_v4();
        // Cancellation advances the active generation before the old worker's
        // already-queued completion is examined.
        assert!(!result_matches_active(new_request, 2, 1, Some(old_request)));
        assert!(result_matches_active(new_request, 2, 2, Some(new_request)));
    }

    #[tokio::test]
    async fn invalid_proposal_fails_before_answer_or_proposed_lifecycle() {
        let temp = tempfile::tempdir().unwrap();
        let session = "invalid-before-display";
        let (coordinator, _, _) = test_coordinator(
            &temp,
            session,
            vec![ScannerType::Sast],
            test_checkpoint(session),
            test_snapshot(session, crate::agent::chat::PhaseBoundary::AfterFramework),
            1,
        );
        let request_id = Uuid::new_v4();
        let invalid = proposal(
            request_id,
            crate::agent::chat::ChatAction::focus_and_rerun(
                [ScannerType::SupplyChain],
                FocusScope::new([crate::agent::chat::FocusFragment::DependencyManifest], [])
                    .unwrap(),
            )
            .unwrap(),
        );
        let (tx, mut rx) = mpsc::channel(4);
        let events = EventDispatcher { tx };
        let mut proposals = HashMap::new();
        let mut turns = VecDeque::new();
        coordinator
            .handle_result(
                ChatAgentResult {
                    request_id,
                    request: "bad proposal".into(),
                    answer: "must not be shown".into(),
                    proposal: Some(invalid),
                },
                &mut proposals,
                &mut turns,
                &events,
            )
            .await;
        assert!(proposals.is_empty());
        assert!(turns.is_empty());
        assert!(matches!(
            rx.recv().await,
            Some(ChatEvent::Error {
                kind: ChatError::InvalidProposal,
                ..
            })
        ));
        assert!(rx.try_recv().is_err());
        let transcript = std::fs::read_to_string(
            temp.path()
                .join(".zentra/chat")
                .join(format!("{session}.jsonl")),
        )
        .unwrap();
        assert!(transcript.contains("failed"));
        assert!(!transcript.contains("proposed"));
        assert!(!transcript.contains("must not be shown"));
    }

    #[tokio::test]
    async fn accepts_fifteen_queued_asks_fifo_then_backpressures_seventeenth() {
        let temp = tempfile::tempdir().unwrap();
        let session = "queue-limit";
        let checkpoint = test_checkpoint(session);
        let snapshot = test_snapshot(session, crate::agent::chat::PhaseBoundary::AfterFramework);
        let zentra = temp.path().join(".zentra");
        std::fs::create_dir(&zentra).unwrap();
        let security = SecurityContext::new(
            SecurityConfig::trusted_local(),
            AuditLog::new(&zentra, session, false).unwrap(),
        );
        let started = Arc::new(Notify::new());
        let agent = ChatAgent::from_raw_provider(
            Arc::new(BlockingProvider {
                started: started.clone(),
            }),
            Arc::new(crate::tools::ToolRegistry::new()),
            security.clone(),
            CancellationToken::new(),
        );
        let store = ChatStore::new(&zentra, session).unwrap();
        let (pending_tx, _) = mpsc::channel(MAX_PENDING_CHAT_ACTIONS);
        let cancel = CancellationToken::new();
        let coordinator = ChatCoordinator::new(
            agent,
            security,
            store,
            snapshot,
            temp.path().to_path_buf(),
            zentra,
            vec![ScannerType::Sast],
            None,
            checkpoint,
            pending_tx,
            cancel.clone(),
        );
        let (command_tx, command_rx, event_tx, mut event_rx) = channels();
        let task = tokio::spawn(coordinator.run(command_rx, event_tx));
        let ids: Vec<_> = (0..17).map(|_| Uuid::new_v4()).collect();
        command_tx
            .send(ChatCommand::Ask {
                request_id: ids[0],
                text: "active".into(),
            })
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), started.notified())
            .await
            .unwrap();
        for id in ids.iter().skip(1) {
            command_tx
                .send(ChatCommand::Ask {
                    request_id: *id,
                    text: "queued".into(),
                })
                .await
                .unwrap();
        }
        let mut queued = Vec::new();
        let mut backpressure = false;
        while queued.len() < 15 || !backpressure {
            match tokio::time::timeout(std::time::Duration::from_secs(1), event_rx.recv())
                .await
                .unwrap()
                .unwrap()
            {
                ChatEvent::RequestQueued { request_id, .. } if request_id != ids[0] => {
                    queued.push(request_id)
                }
                ChatEvent::Error {
                    request_id: Some(id),
                    kind: ChatError::Backpressure,
                    ..
                } if id == ids[16] => backpressure = true,
                _ => {}
            }
        }
        assert_eq!(queued, ids[1..16]);
        cancel.cancel();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn confirmation_retries_keep_proposal_when_pending_channel_is_full_or_closed() {
        for capacity in [1] {
            let temp = tempfile::tempdir().unwrap();
            let session = "pending-retry";
            let checkpoint = test_checkpoint(session);
            let snapshot =
                test_snapshot(session, crate::agent::chat::PhaseBoundary::AfterFramework);
            let (mut coordinator, _, mut pending_rx) = test_coordinator(
                &temp,
                session,
                vec![ScannerType::Sast],
                checkpoint.clone(),
                snapshot,
                capacity,
            );
            if capacity == 1 {
                coordinator
                    .pending_tx
                    .send(
                        ConfirmedChatAction::new(
                            Uuid::new_v4(),
                            1,
                            sast_focus(),
                            [ScannerType::Sast],
                        )
                        .unwrap(),
                    )
                    .await
                    .unwrap();
            }
            let p = proposal(Uuid::new_v4(), sast_focus());
            let (event_tx, mut rx) = mpsc::channel(4);
            let events = EventDispatcher { tx: event_tx };
            assert!(!coordinator.confirm(p.clone(), &events).await);
            assert!(matches!(
                rx.recv().await,
                Some(ChatEvent::Error {
                    kind: ChatError::Backpressure,
                    ..
                })
            ));
            assert!(checkpoint.lock().unwrap().confirmed_chat_actions.is_empty());
            assert!(pending_rx.try_recv().is_err() || capacity == 1);
        }
        let temp = tempfile::tempdir().unwrap();
        let session = "closed-pending";
        let checkpoint = test_checkpoint(session);
        let snapshot = test_snapshot(session, crate::agent::chat::PhaseBoundary::AfterFramework);
        let (mut coordinator, _, pending_rx) = test_coordinator(
            &temp,
            session,
            vec![ScannerType::Sast],
            checkpoint.clone(),
            snapshot,
            1,
        );
        drop(pending_rx);
        let p = proposal(Uuid::new_v4(), sast_focus());
        let (event_tx, mut rx) = mpsc::channel(4);
        let events = EventDispatcher { tx: event_tx };
        assert!(!coordinator.confirm(p, &events).await);
        assert!(matches!(
            rx.recv().await,
            Some(ChatEvent::Error {
                kind: ChatError::Backpressure,
                ..
            })
        ));
        assert!(checkpoint.lock().unwrap().confirmed_chat_actions.is_empty());
    }

    #[tokio::test]
    async fn confirmation_sequence_uses_durable_max_and_failed_write_does_not_consume_it() {
        let temp = tempfile::tempdir().unwrap();
        let session = "sequence";
        let checkpoint = test_checkpoint(session);
        checkpoint.lock().unwrap().confirmed_chat_actions.push(
            ConfirmedChatAction::new(Uuid::new_v4(), 9, sast_focus(), [ScannerType::Sast]).unwrap(),
        );
        let snapshot = test_snapshot(session, crate::agent::chat::PhaseBoundary::AfterFramework);
        let (mut coordinator, _, mut pending_rx) = test_coordinator(
            &temp,
            session,
            vec![ScannerType::Sast],
            checkpoint,
            snapshot,
            2,
        );
        let p = proposal(Uuid::new_v4(), sast_focus());
        let (event_tx, mut rx) = mpsc::channel(8);
        let events = EventDispatcher { tx: event_tx };
        assert!(coordinator.confirm(p, &events).await);
        assert!(matches!(rx.recv().await, Some(ChatEvent::Confirmed { .. })));
        assert_eq!(pending_rx.recv().await.unwrap().confirmation_sequence, 10);
    }

    #[tokio::test]
    async fn strict_checkpoint_failure_keeps_proposal_retryable_without_pending_action_or_sequence_gap(
    ) {
        let temp = tempfile::tempdir().unwrap();
        let session = "strict-retry";
        let checkpoint = test_checkpoint(session);
        let snapshot = test_snapshot(session, crate::agent::chat::PhaseBoundary::AfterFramework);
        let (mut coordinator, _, mut pending_rx) = test_coordinator(
            &temp,
            session,
            vec![ScannerType::Sast],
            checkpoint.clone(),
            snapshot,
            1,
        );
        let zentra = temp.path().join(".zentra");
        std::fs::remove_dir_all(&zentra).unwrap();
        std::fs::write(&zentra, "not a directory").unwrap();
        let p = proposal(Uuid::new_v4(), sast_focus());
        let (event_tx, mut rx) = mpsc::channel(8);
        let events = EventDispatcher { tx: event_tx };
        assert!(!coordinator.confirm(p.clone(), &events).await);
        assert!(matches!(
            rx.recv().await,
            Some(ChatEvent::Error {
                kind: ChatError::Persistence,
                ..
            })
        ));
        assert!(checkpoint.lock().unwrap().confirmed_chat_actions.is_empty());
        assert!(pending_rx.try_recv().is_err());
        std::fs::remove_file(&zentra).unwrap();
        std::fs::create_dir(&zentra).unwrap();
        assert!(coordinator.confirm(p, &events).await);
        assert!(matches!(rx.recv().await, Some(ChatEvent::Confirmed { .. })));
        assert_eq!(pending_rx.recv().await.unwrap().confirmation_sequence, 1);
    }

    #[tokio::test]
    async fn expiry_and_request_cancel_persist_and_remove_the_proposal() {
        let temp = tempfile::tempdir().unwrap();
        let session = "proposal-cancel";
        let checkpoint = test_checkpoint(session);
        let snapshot = test_snapshot(session, crate::agent::chat::PhaseBoundary::AfterFramework);
        let (coordinator, cancel, _) = test_coordinator(
            &temp,
            session,
            vec![ScannerType::Sast],
            checkpoint,
            snapshot,
            1,
        );
        let action = sast_focus();
        let request_id = Uuid::new_v4();
        let p = proposal(request_id, action);
        let store = coordinator.store.clone();
        let (event_tx, mut rx) = mpsc::channel(8);
        let events = EventDispatcher { tx: event_tx };
        coordinator
            .persist_proposal(
                p.proposal_id,
                ProposalLifecycle::Expired,
                Some(p.action.clone()),
                &events,
            )
            .await;
        events
            .terminal(ChatEvent::Deferred {
                proposal_id: p.proposal_id,
                reason: "proposal expired".into(),
            })
            .await;
        assert!(
            matches!(rx.recv().await, Some(ChatEvent::Deferred { proposal_id, .. }) if proposal_id == p.proposal_id)
        );
        assert!(std::fs::read_to_string(store.path())
            .unwrap()
            .contains("expired"));
        // The coordinator's cancellation path uses the same durable terminal lifecycle.
        coordinator
            .persist_proposal(
                p.proposal_id,
                ProposalLifecycle::Cancelled,
                Some(p.action),
                &events,
            )
            .await;
        assert!(std::fs::read_to_string(store.path())
            .unwrap()
            .contains("cancelled"));
        cancel.cancel();
    }

    #[tokio::test]
    async fn supply_chain_focus_requires_context_but_accepts_confirmed_category_context() {
        let temp = tempfile::tempdir().unwrap();
        let session = "supply-context";
        let checkpoint = Arc::new(Mutex::new(Checkpoint {
            session_id: session.into(),
            scanner_set: vec!["supply_chain".into()],
            ..Default::default()
        }));
        let snapshot = Arc::new(Mutex::new(ChatSnapshot {
            session_id: session.into(),
            boundary: crate::agent::chat::PhaseBoundary::AfterFramework,
            selected_scanners: vec!["supply_chain".into()],
            ..Default::default()
        }));
        let (coordinator, _, _) = test_coordinator(
            &temp,
            session,
            vec![ScannerType::SupplyChain],
            checkpoint.clone(),
            snapshot,
            2,
        );
        let supply = proposal(
            Uuid::new_v4(),
            crate::agent::chat::ChatAction::focus_and_rerun(
                [ScannerType::SupplyChain],
                FocusScope::new([crate::agent::chat::FocusFragment::InputValidation], []).unwrap(),
            )
            .unwrap(),
        );
        assert!(coordinator.validate_proposal(&supply).is_err());
        checkpoint.lock().unwrap().confirmed_chat_actions.push(
            ConfirmedChatAction::new(
                Uuid::new_v4(),
                1,
                crate::agent::chat::ChatAction::prioritize(
                    crate::agent::chat::VulnerabilityCategory::DependencySupplyChain,
                ),
                [ScannerType::SupplyChain],
            )
            .unwrap(),
        );
        assert!(coordinator.validate_proposal(&supply).is_ok());
    }

    #[tokio::test]
    async fn cancelled_confirmation_is_deferred_and_never_published() {
        let temp = tempfile::tempdir().unwrap();
        let session = "cancel-confirm";
        let checkpoint = test_checkpoint(session);
        let snapshot = test_snapshot(session, crate::agent::chat::PhaseBoundary::AfterFramework);
        let (mut coordinator, cancel, mut pending_rx) = test_coordinator(
            &temp,
            session,
            vec![ScannerType::Sast],
            checkpoint,
            snapshot,
            1,
        );
        let p = proposal(Uuid::new_v4(), sast_focus());
        let (event_tx, mut rx) = mpsc::channel(4);
        let events = EventDispatcher { tx: event_tx };
        cancel.cancel();
        assert!(coordinator.confirm(p.clone(), &events).await);
        assert!(
            matches!(rx.recv().await, Some(ChatEvent::Deferred { proposal_id, .. }) if proposal_id == p.proposal_id)
        );
        assert!(pending_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn poisoned_snapshot_fails_closed_before_provider_call() {
        let temp = tempfile::tempdir().unwrap();
        let session = "poisoned-snapshot";
        let snapshot = test_snapshot(session, crate::agent::chat::PhaseBoundary::AfterFramework);
        let poisoned = snapshot.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poisoned.lock().unwrap();
            panic!("poison");
        })
        .join();
        let checkpoint = test_checkpoint(session);
        let (coordinator, cancel, _) = test_coordinator(
            &temp,
            session,
            vec![ScannerType::Sast],
            checkpoint,
            snapshot,
            1,
        );
        let (tx, rx, event_tx, mut event_rx) = channels();
        let task = tokio::spawn(coordinator.run(rx, event_tx));
        tx.send(ChatCommand::Ask {
            request_id: Uuid::new_v4(),
            text: "no provider".into(),
        })
        .await
        .unwrap();
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(1), event_rx.recv())
                .await
                .unwrap(),
            Some(ChatEvent::Error {
                kind: ChatError::Security,
                ..
            })
        ));
        cancel.cancel();
        task.await.unwrap();
    }
}
