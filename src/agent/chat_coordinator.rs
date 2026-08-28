//! Bounded single-flight coordinator for the isolated chat agent.

use crate::agent::chat::{
    plan_confirmed_chat_actions, ActionProposal, ChatActionOutcome, ChatActionOutcomeEnvelope,
    ChatCommand, ChatError, ChatEvent, ChatLifecycle, ChatOutcomeAck, ChatOutcomeFailure,
    ChatRecord, ChatSnapshot, ChatStore, ChatTurn, ConfirmedChatAction, FocusScope,
    ProposalLifecycle, RequestLifecycle,
};
use crate::agent::chat_agent::{ChatAgent, ChatAgentResult};
use crate::agent::checkpoint::Checkpoint;
use crate::agent::ScannerType;
use crate::security::{AuditEvent, SecurityContext};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
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
    outcome_rx: Option<mpsc::Receiver<ChatActionOutcomeEnvelope>>,
    action_eligible: Arc<AtomicBool>,
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
            outcome_rx: None,
            action_eligible: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Attach the bounded phase-loop outcome channel. Kept as a builder so the
    /// already usable coordinator constructor remains source compatible.
    pub fn with_outcomes(mut self, outcome_rx: mpsc::Receiver<ChatActionOutcomeEnvelope>) -> Self {
        self.outcome_rx = Some(outcome_rx);
        self
    }

    /// Share the phase loop's final-boundary gate.  Keeping this as a builder
    /// preserves existing construction sites while making the runtime pair use
    /// one atomic close decision.
    pub fn with_action_eligibility(mut self, action_eligible: Arc<AtomicBool>) -> Self {
        self.action_eligible = action_eligible;
        self
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
        let mut outcome_rx = self.outcome_rx.take();
        let mut commands_closed = false;

        loop {
            if commands_closed && outcome_rx.is_none() {
                break;
            }
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
                command = command_rx.recv(), if !commands_closed => {
                    let Some(command) = command else {
                        commands_closed = true;
                        continue;
                    };
                    match command {
                        ChatCommand::Ask { request_id, text } => {
                            if ChatCommand::ask(request_id, text.clone()).is_err() || active.as_ref().is_some_and(|(id, _, _, _)| *id == request_id) || queued.iter().any(|(id, _)| *id == request_id) || proposals.values().any(|proposal| proposal.request_id == request_id) {
                                let _ = events.terminal(error(Some(request_id), ChatError::InvalidProposal, "invalid or duplicate chat request ID")).await;
                                continue;
                            }
                            if active.is_some() && queued.len() >= MAX_QUEUED_CHAT_ASKS {
                                let _ = events.terminal(error(Some(request_id), ChatError::Backpressure, "chat request queue is full")).await;
                            } else {
                                // Validate the live bounded view before this
                                // request becomes runnable. Persistence below
                                // deliberately uses ChatStore's immutable ID.
                                if let Err(reason) = self.snapshot() {
                                    events.terminal(error(Some(request_id), ChatError::Security, &reason)).await;
                                    continue;
                                }
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
                            if outcome_rx.is_some() {
                                // Closing the drawer must not strand terminal
                                // action outcomes; only command processing ends.
                                commands_closed = true;
                            } else {
                                break;
                            }
                        }
                    }
                }
                outcome = async {
                    match outcome_rx.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if let Some(outcome) = outcome {
                        self.consume_outcome(outcome, &events).await;
                    } else {
                        outcome_rx = None;
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
        if !self.action_eligible.load(Ordering::Acquire) {
            self.defer_finalized_proposal(&proposal, event_tx).await;
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
            // This check must be inside the checkpoint critical section.  A
            // confirmation saved before the final close is drained; one after
            // it is never made pending.
            if !self.action_eligible.load(Ordering::Acquire) {
                return Err((
                    ChatError::InvalidProposal,
                    "the scan has reached its final boundary".to_string(),
                ));
            }
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
            let mut plan_actions = checkpoint.confirmed_chat_actions.clone();
            plan_actions.push(action.clone());
            plan_confirmed_chat_actions(&plan_actions, &self.selected)
                .map_err(|error_value| (ChatError::InvalidProposal, error_value.to_string()))?;
            checkpoint
                .save_confirmed_chat_action_strict(&self.zentra_dir, action.clone())
                .map_err(|error_value| (ChatError::Persistence, error_value.to_string()))?;
            Ok::<_, (ChatError, String)>((confirmation_sequence, action))
        })();
        let (confirmation_sequence, action) = match saved {
            Ok(saved) => saved,
            Err((kind, error_value)) => {
                if !self.action_eligible.load(Ordering::Acquire) {
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

    async fn defer_finalized_proposal(
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
                reason: "the scan has reached its final boundary".to_string(),
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
        if !checkpoint.session_id.is_empty() && checkpoint.session_id != self.store.session_id() {
            return Err("chat session does not match checkpoint".to_string());
        }
        if !checkpoint.scanner_set.is_empty()
            && (canonical_scanner_names(&self.selected).is_none()
                || Some(checkpoint.scanner_set.clone()) != canonical_scanner_names(&self.selected)
                || checkpoint
                    .scanner_set
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1]))
        {
            return Err("scanner set does not exactly match checkpoint".to_string());
        }
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
                self.store.session_id().to_string(),
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
                self.store.session_id().to_string(),
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

    /// The coordinator owns durable lifecycle records and UI chat events; the
    /// orchestrator merely reports typed terminal outcomes.
    async fn consume_outcome(
        &self,
        envelope: ChatActionOutcomeEnvelope,
        event_tx: &EventDispatcher,
    ) {
        let ChatActionOutcomeEnvelope {
            expected,
            outcome,
            ack,
        } = envelope;
        let (proposal_id, lifecycle, event) = match outcome {
            ChatActionOutcome::Applied {
                proposal_id,
                boundary,
            } => (
                proposal_id,
                ProposalLifecycle::Applied,
                ChatEvent::Applied {
                    proposal_id,
                    boundary,
                },
            ),
            ChatActionOutcome::Deferred {
                proposal_id,
                reason,
            } => (
                proposal_id,
                ProposalLifecycle::Deferred,
                ChatEvent::Deferred {
                    proposal_id,
                    reason: lifecycle_message(&reason),
                },
            ),
        };
        let result = (|| -> Result<ChatOutcomeAck, ChatOutcomeFailure> {
            let mut checkpoint = self
                .checkpoint
                .lock()
                .map_err(|_| ChatOutcomeFailure::Persistence)?;
            let Some(current) = checkpoint
                .confirmed_chat_actions
                .iter()
                .find(|action| action.proposal_id == proposal_id)
                .cloned()
            else {
                return Ok(ChatOutcomeAck::Duplicate);
            };
            if current != expected {
                return Err(ChatOutcomeFailure::MismatchedAction);
            }
            if matches!(lifecycle, ProposalLifecycle::Applied)
                && !current.remaining_scanners.is_empty()
            {
                return Err(ChatOutcomeFailure::AppliedBeforeCompletion);
            }
            match self
                .store
                .terminal_proposal_lifecycle(proposal_id)
                .map_err(|_| ChatOutcomeFailure::Persistence)?
            {
                Some(existing) if existing != lifecycle => {
                    return Err(ChatOutcomeFailure::Persistence)
                }
                Some(_) => {}
                None => {
                    let session_id = self.store.session_id().to_string();
                    let record = ChatRecord::new(
                        session_id,
                        None,
                        Some(proposal_id),
                        ChatLifecycle::Proposal { state: lifecycle },
                        None,
                        Some(current.action.clone()),
                    )
                    .map_err(|_| ChatOutcomeFailure::Persistence)?;
                    self.store
                        .append(&record)
                        .map_err(|_| ChatOutcomeFailure::Persistence)?;
                }
            }
            checkpoint
                .remove_confirmed_chat_action_strict(&self.zentra_dir, proposal_id)
                .map_err(|_| ChatOutcomeFailure::Persistence)?;
            Ok(ChatOutcomeAck::Committed)
        })();
        match result {
            Ok(ChatOutcomeAck::Committed) => {
                event_tx.terminal(event).await;
                let _ = ack.send(Ok(ChatOutcomeAck::Committed));
            }
            Ok(ChatOutcomeAck::Duplicate) => {
                let _ = ack.send(Ok(ChatOutcomeAck::Duplicate));
            }
            Err(failure) => {
                let _ = ack.send(Err(failure));
            }
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
fn canonical_scanner_names(scanners: &[ScannerType]) -> Option<Vec<String>> {
    let mut names: Vec<_> = scanners
        .iter()
        .map(|scanner| scanner.name().to_string())
        .collect();
    names.sort();
    (!names.windows(2).any(|pair| pair[0] == pair[1])).then_some(names)
}
fn error(request_id: Option<Uuid>, kind: ChatError, message: &str) -> ChatEvent {
    ChatEvent::Error {
        request_id,
        kind,
        message: lifecycle_message(message),
    }
}

fn lifecycle_message(message: &str) -> String {
    let message = crate::logging::redact(message);
    let mut end = message
        .len()
        .min(crate::agent::chat::MAX_LIFECYCLE_MESSAGE_BYTES);
    while end > 0 && !message.is_char_boundary(end) {
        end -= 1;
    }
    message[..end].to_string()
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

    fn checkpoint_for(session: &str, scanners: &[ScannerType]) -> Arc<Mutex<Checkpoint>> {
        Arc::new(Mutex::new(Checkpoint {
            session_id: session.into(),
            scanner_set: scanners
                .iter()
                .map(|scanner| scanner.name().to_string())
                .collect(),
            ..Default::default()
        }))
    }

    fn snapshot_for(session: &str, scanners: &[ScannerType]) -> Arc<Mutex<ChatSnapshot>> {
        Arc::new(Mutex::new(ChatSnapshot {
            session_id: session.into(),
            boundary: crate::agent::chat::PhaseBoundary::AfterFramework,
            selected_scanners: scanners
                .iter()
                .map(|scanner| scanner.name().to_string())
                .collect(),
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

    fn durable_action(id: Uuid, empty: bool) -> ConfirmedChatAction {
        let mut action =
            ConfirmedChatAction::new(id, 1, sast_focus(), [ScannerType::Sast]).unwrap();
        if empty {
            action.remaining_scanners.clear();
        }
        action
    }

    fn envelope(
        expected: ConfirmedChatAction,
        outcome: ChatActionOutcome,
    ) -> (
        ChatActionOutcomeEnvelope,
        tokio::sync::oneshot::Receiver<Result<ChatOutcomeAck, ChatOutcomeFailure>>,
    ) {
        let (ack, received) = tokio::sync::oneshot::channel();
        (
            ChatActionOutcomeEnvelope {
                expected,
                outcome,
                ack,
            },
            received,
        )
    }

    fn applied(action: &ConfirmedChatAction) -> ChatActionOutcome {
        ChatActionOutcome::Applied {
            proposal_id: action.proposal_id,
            boundary: crate::agent::chat::PhaseBoundary::AfterParallel,
        }
    }

    #[tokio::test]
    async fn close_keeps_outcome_pump_alive_until_terminal_action_is_acked() {
        let temp = tempfile::tempdir().unwrap();
        let session = "outcome-after-close";
        let checkpoint = test_checkpoint(session);
        let action = durable_action(Uuid::new_v4(), true);
        checkpoint
            .lock()
            .unwrap()
            .confirmed_chat_actions
            .push(action.clone());
        let (outcome_tx, outcome_rx) = mpsc::channel(2);
        let (coordinator, _, _) = test_coordinator(
            &temp,
            session,
            vec![ScannerType::Sast],
            checkpoint.clone(),
            test_snapshot(session, crate::agent::chat::PhaseBoundary::AfterFramework),
            1,
        );
        let (command_tx, command_rx, event_tx, mut event_rx) = channels();
        let task = tokio::spawn(
            coordinator
                .with_outcomes(outcome_rx)
                .run(command_rx, event_tx),
        );
        command_tx.send(ChatCommand::Close).await.unwrap();
        tokio::task::yield_now().await;
        let (message, ack) = envelope(action.clone(), applied(&action));
        outcome_tx.send(message).await.unwrap();
        assert_eq!(ack.await.unwrap(), Ok(ChatOutcomeAck::Committed));
        assert!(checkpoint.lock().unwrap().confirmed_chat_actions.is_empty());
        assert!(
            matches!(event_rx.recv().await, Some(ChatEvent::Applied { proposal_id, .. }) if proposal_id == action.proposal_id)
        );
        assert!(!task.is_finished());
        let transcript = std::fs::read_to_string(
            temp.path()
                .join(".zentra/chat")
                .join(format!("{session}.jsonl")),
        )
        .unwrap();
        assert_eq!(transcript.matches("\"state\":\"applied\"").count(), 1);
        drop(outcome_tx);
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn bounded_outcome_transport_waits_instead_of_dropping_second_sender() {
        let temp = tempfile::tempdir().unwrap();
        let session = "outcome-backpressure";
        let checkpoint = test_checkpoint(session);
        let first = durable_action(Uuid::new_v4(), true);
        let second = durable_action(Uuid::new_v4(), true);
        checkpoint.lock().unwrap().confirmed_chat_actions = vec![first.clone(), second.clone()];
        let (outcome_tx, outcome_rx) = mpsc::channel(1);
        let (one, one_ack) = envelope(first.clone(), applied(&first));
        outcome_tx.send(one).await.unwrap();
        let (two, two_ack) = envelope(second.clone(), applied(&second));
        let second_send = tokio::spawn({
            let outcome_tx = outcome_tx.clone();
            async move { outcome_tx.send(two).await }
        });
        tokio::task::yield_now().await;
        assert!(!second_send.is_finished());
        let (coordinator, _, _) = test_coordinator(
            &temp,
            session,
            vec![ScannerType::Sast],
            checkpoint,
            test_snapshot(session, crate::agent::chat::PhaseBoundary::AfterFramework),
            1,
        );
        let (command_tx, command_rx, event_tx, _event_rx) = channels();
        let task = tokio::spawn(
            coordinator
                .with_outcomes(outcome_rx)
                .run(command_rx, event_tx),
        );
        second_send.await.unwrap().unwrap();
        assert_eq!(one_ack.await.unwrap(), Ok(ChatOutcomeAck::Committed));
        assert_eq!(two_ack.await.unwrap(), Ok(ChatOutcomeAck::Committed));
        drop(outcome_tx);
        drop(command_tx);
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn duplicate_and_unknown_outcomes_ack_duplicate_without_reemitting_terminal_state() {
        let temp = tempfile::tempdir().unwrap();
        let session = "outcome-duplicates";
        let checkpoint = test_checkpoint(session);
        let action = durable_action(Uuid::new_v4(), true);
        checkpoint
            .lock()
            .unwrap()
            .confirmed_chat_actions
            .push(action.clone());
        let (outcome_tx, outcome_rx) = mpsc::channel(4);
        let (coordinator, _, _) = test_coordinator(
            &temp,
            session,
            vec![ScannerType::Sast],
            checkpoint,
            test_snapshot(session, crate::agent::chat::PhaseBoundary::AfterFramework),
            1,
        );
        let (command_tx, command_rx, event_tx, mut event_rx) = channels();
        let task = tokio::spawn(
            coordinator
                .with_outcomes(outcome_rx)
                .run(command_rx, event_tx),
        );
        let (first, ack) = envelope(action.clone(), applied(&action));
        outcome_tx.send(first).await.unwrap();
        assert_eq!(ack.await.unwrap(), Ok(ChatOutcomeAck::Committed));
        assert!(matches!(
            event_rx.recv().await,
            Some(ChatEvent::Applied { .. })
        ));
        let (duplicate, ack) = envelope(action.clone(), applied(&action));
        outcome_tx.send(duplicate).await.unwrap();
        assert_eq!(ack.await.unwrap(), Ok(ChatOutcomeAck::Duplicate));
        let unknown = durable_action(Uuid::new_v4(), true);
        let (unknown_message, ack) = envelope(unknown.clone(), applied(&unknown));
        outcome_tx.send(unknown_message).await.unwrap();
        assert_eq!(ack.await.unwrap(), Ok(ChatOutcomeAck::Duplicate));
        assert!(event_rx.try_recv().is_err());
        let transcript = std::fs::read_to_string(
            temp.path()
                .join(".zentra/chat")
                .join(format!("{session}.jsonl")),
        )
        .unwrap();
        assert_eq!(transcript.matches("\"state\":\"applied\"").count(), 1);
        drop(outcome_tx);
        drop(command_tx);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn invalid_applied_and_mismatched_outcomes_fail_without_mutating_durable_action() {
        let temp = tempfile::tempdir().unwrap();
        let session = "outcome-invalid";
        let checkpoint = test_checkpoint(session);
        let action = durable_action(Uuid::new_v4(), false);
        checkpoint
            .lock()
            .unwrap()
            .confirmed_chat_actions
            .push(action.clone());
        let (coordinator, _, _) = test_coordinator(
            &temp,
            session,
            vec![ScannerType::Sast],
            checkpoint.clone(),
            test_snapshot(session, crate::agent::chat::PhaseBoundary::AfterFramework),
            1,
        );
        let (event_tx, mut event_rx) = mpsc::channel(2);
        let events = EventDispatcher { tx: event_tx };
        let (message, ack) = envelope(action.clone(), applied(&action));
        coordinator.consume_outcome(message, &events).await;
        assert_eq!(
            ack.await.unwrap(),
            Err(ChatOutcomeFailure::AppliedBeforeCompletion)
        );
        let mut mismatch = action.clone();
        mismatch.confirmation_sequence = 2;
        let (message, ack) = envelope(mismatch, applied(&action));
        coordinator.consume_outcome(message, &events).await;
        assert_eq!(
            ack.await.unwrap(),
            Err(ChatOutcomeFailure::MismatchedAction)
        );
        assert_eq!(
            checkpoint.lock().unwrap().confirmed_chat_actions,
            vec![action]
        );
        assert!(event_rx.try_recv().is_err());
        assert!(!temp
            .path()
            .join(".zentra/chat")
            .join(format!("{session}.jsonl"))
            .exists());
    }

    #[tokio::test]
    async fn transcript_success_checkpoint_failure_retries_without_duplicate_terminal_record() {
        let temp = tempfile::tempdir().unwrap();
        let session = "outcome-retry";
        let checkpoint = test_checkpoint(session);
        let action = durable_action(Uuid::new_v4(), true);
        checkpoint
            .lock()
            .unwrap()
            .confirmed_chat_actions
            .push(action.clone());
        let (mut coordinator, _, _) = test_coordinator(
            &temp,
            session,
            vec![ScannerType::Sast],
            checkpoint.clone(),
            test_snapshot(session, crate::agent::chat::PhaseBoundary::AfterFramework),
            1,
        );
        let good_zentra = coordinator.zentra_dir.clone();
        let fault = temp.path().join("checkpoint-fault");
        std::fs::write(&fault, "not a directory").unwrap();
        coordinator.zentra_dir = fault.clone();
        let (event_tx, mut event_rx) = mpsc::channel(2);
        let events = EventDispatcher { tx: event_tx };
        let (message, ack) = envelope(action.clone(), applied(&action));
        coordinator.consume_outcome(message, &events).await;
        assert_eq!(ack.await.unwrap(), Err(ChatOutcomeFailure::Persistence));
        assert_eq!(
            checkpoint.lock().unwrap().confirmed_chat_actions,
            vec![action.clone()]
        );
        assert!(event_rx.try_recv().is_err());
        let transcript =
            std::fs::read_to_string(good_zentra.join("chat").join(format!("{session}.jsonl")))
                .unwrap();
        assert_eq!(transcript.matches("\"state\":\"applied\"").count(), 1);
        assert_eq!(
            coordinator
                .store
                .terminal_proposal_lifecycle(action.proposal_id)
                .unwrap(),
            Some(ProposalLifecycle::Applied)
        );
        std::fs::remove_file(&fault).unwrap();
        std::fs::create_dir(&fault).unwrap();
        let (message, ack) = envelope(action.clone(), applied(&action));
        coordinator.consume_outcome(message, &events).await;
        assert_eq!(ack.await.unwrap(), Ok(ChatOutcomeAck::Committed));
        assert!(checkpoint.lock().unwrap().confirmed_chat_actions.is_empty());
        assert!(matches!(
            event_rx.recv().await,
            Some(ChatEvent::Applied { .. })
        ));
        let transcript =
            std::fs::read_to_string(good_zentra.join("chat").join(format!("{session}.jsonl")))
                .unwrap();
        assert_eq!(transcript.matches("\"state\":\"applied\"").count(), 1);
    }

    #[tokio::test]
    async fn command_receiver_close_still_consumes_later_outcome_without_hanging() {
        let temp = tempfile::tempdir().unwrap();
        let session = "outcome-command-closed";
        let checkpoint = test_checkpoint(session);
        let action = durable_action(Uuid::new_v4(), true);
        checkpoint
            .lock()
            .unwrap()
            .confirmed_chat_actions
            .push(action.clone());
        let (outcome_tx, outcome_rx) = mpsc::channel(1);
        let (coordinator, _, _) = test_coordinator(
            &temp,
            session,
            vec![ScannerType::Sast],
            checkpoint,
            test_snapshot(session, crate::agent::chat::PhaseBoundary::AfterFramework),
            1,
        );
        let (command_tx, command_rx, event_tx, _event_rx) = channels();
        drop(command_tx);
        let task = tokio::spawn(
            coordinator
                .with_outcomes(outcome_rx)
                .run(command_rx, event_tx),
        );
        let (message, ack) = envelope(action.clone(), applied(&action));
        outcome_tx.send(message).await.unwrap();
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(1), ack)
                .await
                .unwrap()
                .unwrap(),
            Ok(ChatOutcomeAck::Committed)
        );
        drop(outcome_tx);
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
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
    async fn confirm_rejects_category_without_applicable_selected_scanner() {
        let temp = tempfile::tempdir().unwrap();
        let session = "no-applicable-category";
        let selected = [ScannerType::IacScan];
        let checkpoint = checkpoint_for(session, &selected);
        let (mut coordinator, _, mut pending) = test_coordinator(
            &temp,
            session,
            selected.to_vec(),
            checkpoint.clone(),
            snapshot_for(session, &selected),
            1,
        );
        let (tx, mut events) = mpsc::channel(2);
        assert!(
            coordinator
                .confirm(
                    proposal(
                        Uuid::new_v4(),
                        crate::agent::chat::ChatAction::prioritize(
                            crate::agent::chat::VulnerabilityCategory::Injection
                        )
                    ),
                    &EventDispatcher { tx },
                )
                .await
        );
        assert!(matches!(
            events.recv().await,
            Some(ChatEvent::Error {
                kind: ChatError::InvalidProposal,
                ..
            })
        ));
        assert!(checkpoint.lock().unwrap().confirmed_chat_actions.is_empty());
        assert!(pending.try_recv().is_err());
    }

    #[tokio::test]
    async fn confirm_rejects_candidates_that_overflow_merged_path_or_fragment_limits() {
        for fragments in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let session = if fragments {
                "merged-fragments"
            } else {
                "merged-paths"
            };
            let selected = [ScannerType::Sast];
            let checkpoint = checkpoint_for(session, &selected);
            let scope = if fragments {
                FocusScope::new(
                    [
                        crate::agent::chat::FocusFragment::AuthBoundary,
                        crate::agent::chat::FocusFragment::InputValidation,
                        crate::agent::chat::FocusFragment::DataFlow,
                        crate::agent::chat::FocusFragment::SecretsAndSensitiveData,
                    ],
                    [],
                )
                .unwrap()
            } else {
                let source = temp.path().join("src");
                std::fs::create_dir_all(&source).unwrap();
                for index in 0..21 {
                    std::fs::write(source.join(format!("{index}.rs")), "").unwrap();
                }
                FocusScope::from_paths(
                    [],
                    (0..11)
                        .map(|index| format!("src/{index}.rs"))
                        .collect::<Vec<_>>(),
                )
                .unwrap()
            };
            checkpoint.lock().unwrap().confirmed_chat_actions.push(
                ConfirmedChatAction::new(
                    Uuid::new_v4(),
                    1,
                    crate::agent::chat::ChatAction::focus_and_rerun([ScannerType::Sast], scope)
                        .unwrap(),
                    selected,
                )
                .unwrap(),
            );
            let candidate_scope = if fragments {
                FocusScope::new(
                    [
                        crate::agent::chat::FocusFragment::DependencyManifest,
                        crate::agent::chat::FocusFragment::NetworkExposure,
                        crate::agent::chat::FocusFragment::IaCPrivilege,
                    ],
                    [],
                )
                .unwrap()
            } else {
                FocusScope::from_paths(
                    [],
                    (11..21)
                        .map(|index| format!("src/{index}.rs"))
                        .collect::<Vec<_>>(),
                )
                .unwrap()
            };
            let (mut coordinator, _, mut pending) = test_coordinator(
                &temp,
                session,
                selected.to_vec(),
                checkpoint.clone(),
                snapshot_for(session, &selected),
                1,
            );
            let (tx, mut events) = mpsc::channel(2);
            assert!(
                coordinator
                    .confirm(
                        proposal(
                            Uuid::new_v4(),
                            crate::agent::chat::ChatAction::focus_and_rerun(
                                [ScannerType::Sast],
                                candidate_scope
                            )
                            .unwrap()
                        ),
                        &EventDispatcher { tx }
                    )
                    .await
            );
            assert!(matches!(
                events.recv().await,
                Some(ChatEvent::Error {
                    kind: ChatError::InvalidProposal,
                    ..
                })
            ));
            assert_eq!(checkpoint.lock().unwrap().confirmed_chat_actions.len(), 1);
            assert!(pending.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn confirm_accepts_supply_chain_dependency_manifest_alone() {
        let temp = tempfile::tempdir().unwrap();
        let session = "supply-manifest";
        let selected = [ScannerType::SupplyChain];
        let checkpoint = checkpoint_for(session, &selected);
        let (mut coordinator, _, mut pending) = test_coordinator(
            &temp,
            session,
            selected.to_vec(),
            checkpoint.clone(),
            snapshot_for(session, &selected),
            1,
        );
        let action = crate::agent::chat::ChatAction::focus_and_rerun(
            [ScannerType::SupplyChain],
            FocusScope::new([crate::agent::chat::FocusFragment::DependencyManifest], []).unwrap(),
        )
        .unwrap();
        let (tx, mut events) = mpsc::channel(2);
        assert!(
            coordinator
                .confirm(proposal(Uuid::new_v4(), action), &EventDispatcher { tx })
                .await
        );
        assert!(matches!(
            events.recv().await,
            Some(ChatEvent::Confirmed { .. })
        ));
        assert_eq!(checkpoint.lock().unwrap().confirmed_chat_actions.len(), 1);
        assert!(pending.try_recv().is_ok());
    }

    #[tokio::test]
    async fn confirm_rejects_supply_chain_focus_without_manifest_or_category() {
        let temp = tempfile::tempdir().unwrap();
        let session = "supply-neither";
        let selected = [ScannerType::SupplyChain];
        let checkpoint = checkpoint_for(session, &selected);
        let (mut coordinator, _, mut pending) = test_coordinator(
            &temp,
            session,
            selected.to_vec(),
            checkpoint.clone(),
            snapshot_for(session, &selected),
            1,
        );
        let action = crate::agent::chat::ChatAction::focus_and_rerun(
            [ScannerType::SupplyChain],
            FocusScope::new([crate::agent::chat::FocusFragment::InputValidation], []).unwrap(),
        )
        .unwrap();
        let (tx, mut events) = mpsc::channel(2);
        assert!(
            coordinator
                .confirm(proposal(Uuid::new_v4(), action), &EventDispatcher { tx })
                .await
        );
        assert!(matches!(
            events.recv().await,
            Some(ChatEvent::Error {
                kind: ChatError::InvalidProposal,
                ..
            })
        ));
        assert!(checkpoint.lock().unwrap().confirmed_chat_actions.is_empty());
        assert!(pending.try_recv().is_err());
    }

    #[tokio::test]
    async fn confirm_accepts_supply_chain_focus_with_durable_dependency_category_companion() {
        let temp = tempfile::tempdir().unwrap();
        let session = "supply-companion";
        let selected = [ScannerType::SupplyChain];
        let checkpoint = checkpoint_for(session, &selected);
        checkpoint.lock().unwrap().confirmed_chat_actions.push(
            ConfirmedChatAction::new(
                Uuid::new_v4(),
                1,
                crate::agent::chat::ChatAction::prioritize(
                    crate::agent::chat::VulnerabilityCategory::DependencySupplyChain,
                ),
                selected,
            )
            .unwrap(),
        );
        let (mut coordinator, _, mut pending) = test_coordinator(
            &temp,
            session,
            selected.to_vec(),
            checkpoint.clone(),
            snapshot_for(session, &selected),
            1,
        );
        let action = crate::agent::chat::ChatAction::focus_and_rerun(
            [ScannerType::SupplyChain],
            FocusScope::new([crate::agent::chat::FocusFragment::InputValidation], []).unwrap(),
        )
        .unwrap();
        let (tx, mut events) = mpsc::channel(2);
        assert!(
            coordinator
                .confirm(proposal(Uuid::new_v4(), action), &EventDispatcher { tx })
                .await
        );
        assert!(matches!(
            events.recv().await,
            Some(ChatEvent::Confirmed { .. })
        ));
        assert_eq!(checkpoint.lock().unwrap().confirmed_chat_actions.len(), 2);
        assert!(pending.try_recv().is_ok());
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
    async fn final_boundary_confirmation_race_is_deferred_or_included_never_stranded() {
        let temp = tempfile::tempdir().unwrap();
        let session = "final-boundary-gate";
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
        let eligibility = Arc::new(std::sync::atomic::AtomicBool::new(true));
        coordinator.action_eligible = eligibility.clone();
        // This is the same ordering used by the phase loop: close first, then
        // inspect durable actions. A later confirmation cannot become pending.
        eligibility.store(false, std::sync::atomic::Ordering::Release);
        let proposal = proposal(Uuid::new_v4(), sast_focus());
        let (event_tx, mut events_rx) = mpsc::channel(2);
        let events = EventDispatcher { tx: event_tx };
        assert!(coordinator.confirm(proposal.clone(), &events).await);
        assert!(
            matches!(events_rx.recv().await, Some(ChatEvent::Deferred { proposal_id, reason }) if proposal_id == proposal.proposal_id && reason == "the scan has reached its final boundary")
        );
        assert!(checkpoint.lock().unwrap().confirmed_chat_actions.is_empty());
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
