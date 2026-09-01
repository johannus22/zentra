pub mod menu;
pub mod pentest_setup;
pub mod pentest_ui;
pub mod results;
pub mod scan_ui;
pub mod theme;

use crate::agent::chat::{ActionProposal, ChatEvent};
use crate::agent::{McpStatus, ScanEvent, ScannerType};
use crate::state::{Finding, Severity};
use std::collections::VecDeque;

pub const MAX_CHAT_TRANSCRIPT: usize = 80;
pub const MAX_CHAT_TEXT_BYTES: usize = crate::agent::chat::MAX_CHAT_TEXT_BYTES;
pub const MAX_PENDING_CHAT_ACTIONS: usize =
    crate::agent::chat_coordinator::MAX_PENDING_CHAT_ACTIONS;

/// Chat is always present when the scan has a chat channel. Focus determines
/// whether keys belong to scan navigation or the conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatFocus {
    Scan,
    Chat,
}

#[cfg(test)]
mod chat_tests {
    use super::*;
    use crate::agent::chat::{ChatAction, PhaseBoundary, VulnerabilityCategory};

    fn state() -> UiState {
        UiState::new(
            vec![ScannerType::Sast],
            "m".into(),
            10,
            vec![],
            String::new(),
            String::new(),
            String::new(),
        )
    }
    fn proposal() -> ActionProposal {
        let now = chrono::Utc::now();
        ActionProposal {
            proposal_id: uuid::Uuid::new_v4(),
            request_id: uuid::Uuid::new_v4(),
            action: ChatAction::prioritize(VulnerabilityCategory::Injection),
            created_at: now,
            expires_at: now + chrono::Duration::minutes(1),
            earliest_boundary: PhaseBoundary::AfterParallel,
        }
    }

    #[test]
    fn chat_events_are_bounded_redacted_and_do_not_touch_scan_state() {
        let mut state = state();
        state.apply_chat_event(ChatEvent::Answer {
            request_id: uuid::Uuid::new_v4(),
            text: "token=private-value".into(),
        });
        assert_eq!(state.findings.len(), 0);
        assert_eq!(state.total_tokens, 0);
        assert!(
            state.chat.transcript[0].text.contains("<redacted>")
                || state.chat.transcript[0].text.contains("***")
        );
        for i in 0..(MAX_CHAT_TRANSCRIPT + 3) {
            state.chat.push("Zentra", i.to_string());
        }
        assert_eq!(state.chat.transcript.len(), MAX_CHAT_TRANSCRIPT);
    }

    #[test]
    fn terminal_events_clear_only_the_visible_proposal() {
        let mut state = state();
        let proposal = proposal();
        let id = proposal.proposal_id;
        state.apply_chat_event(ChatEvent::Proposal { proposal });
        assert!(state.chat.current_proposal().is_some());
        state.apply_chat_event(ChatEvent::Deferred {
            proposal_id: id,
            reason: "later".into(),
        });
        assert!(state.chat.current_proposal().is_none());
    }

    #[test]
    fn proposals_auto_expand_fifo_and_unrelated_errors_do_not_clear_them() {
        let mut state = state();
        let first = proposal();
        let first_id = first.proposal_id;
        let second = proposal();
        let second_id = second.proposal_id;
        state.apply_chat_event(ChatEvent::Proposal { proposal: first });
        state.apply_chat_event(ChatEvent::Proposal { proposal: second });
        assert_eq!(state.chat.focus, ChatFocus::Scan);
        assert_eq!(state.chat.current_proposal().unwrap().proposal_id, first_id);
        state.apply_chat_event(ChatEvent::Error {
            request_id: None,
            kind: crate::agent::chat::ChatError::Provider,
            message: "unrelated failure".into(),
        });
        assert_eq!(state.chat.current_proposal().unwrap().proposal_id, first_id);
        state.apply_chat_event(ChatEvent::Deferred {
            proposal_id: first_id,
            reason: "later".into(),
        });
        assert_eq!(
            state.chat.current_proposal().unwrap().proposal_id,
            second_id
        );
    }

    #[test]
    fn terminal_text_is_redacted_and_control_safe() {
        let safe =
            sanitize_chat_text("\u{1b}[31mpassword=secret\u{1b}[0m\u{7f}\u{85} hello\n\tworld");
        assert!(!safe.contains('\u{1b}'));
        assert!(!safe.contains('\u{7f}'));
        assert!(!safe.contains('\u{85}'));
        assert!(!safe.contains("secret"));
        assert!(safe.contains("hello\n\tworld"));
    }

    #[test]
    fn confirmation_acknowledgement_keeps_head_until_matching_event() {
        let mut state = state();
        let first = proposal();
        let first_id = first.proposal_id;
        let first_request = first.request_id;
        let second = proposal();
        let second_id = second.proposal_id;
        state.apply_chat_event(ChatEvent::Proposal { proposal: first });
        state.apply_chat_event(ChatEvent::Proposal { proposal: second });
        state.chat.mark_confirming(first_id);
        assert!(state.chat.is_current_confirming());
        state.apply_chat_event(ChatEvent::Error {
            request_id: Some(uuid::Uuid::new_v4()),
            kind: crate::agent::chat::ChatError::Provider,
            message: "other".into(),
        });
        assert!(state.chat.is_current_confirming());
        state.apply_chat_event(ChatEvent::Error {
            request_id: Some(first_request),
            kind: crate::agent::chat::ChatError::Provider,
            message: "retry".into(),
        });
        assert!(!state.chat.is_current_confirming());
        assert_eq!(state.chat.current_proposal().unwrap().proposal_id, first_id);
        state.chat.mark_confirming(first_id);
        state.apply_chat_event(ChatEvent::Confirmed {
            proposal_id: first_id,
        });
        assert_eq!(
            state.chat.current_proposal().unwrap().proposal_id,
            second_id
        );
    }

    #[test]
    fn matching_applied_event_clears_head_and_promotes_next_proposal() {
        let mut state = state();
        let first = proposal();
        let first_id = first.proposal_id;
        let second = proposal();
        let second_id = second.proposal_id;
        state.apply_chat_event(ChatEvent::Proposal { proposal: first });
        state.apply_chat_event(ChatEvent::Proposal { proposal: second });
        state.apply_chat_event(ChatEvent::Applied {
            proposal_id: first_id,
            boundary: PhaseBoundary::AfterParallel,
        });
        assert_eq!(
            state.chat.current_proposal().unwrap().proposal_id,
            second_id
        );
    }

    #[test]
    fn input_is_utf8_safe_and_bounded() {
        let mut chat = ChatUiState::default();
        assert!(chat.insert_text("é🙂"));
        chat.backspace();
        assert_eq!(chat.input, "é");
        assert!(chat.insert_text(&"a".repeat(MAX_CHAT_TEXT_BYTES)));
        assert!(chat.input.len() <= MAX_CHAT_TEXT_BYTES);
    }

    #[test]
    fn coordinator_lifecycle_is_status_not_user_attribution() {
        let mut state = state();
        let request_id = uuid::Uuid::new_v4();
        state.apply_chat_event(ChatEvent::RequestQueued {
            request_id,
            position: 1,
        });
        assert_eq!(state.chat.queued, 1);
        assert_eq!(state.chat.status, "Queued");
        assert_eq!(state.chat.transcript[0].label, "Status");
        assert_eq!(state.chat.transcript[0].text, "Queued");
        assert!(!state.chat.transcript[0]
            .text
            .contains(&request_id.to_string()));
        state.apply_chat_event(ChatEvent::Answer {
            request_id: uuid::Uuid::new_v4(),
            text: "reply".into(),
        });
        assert_eq!(state.chat.queued, 0);
        assert_eq!(state.chat.transcript[1].label, "Zentra");
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatTranscriptEntry {
    pub label: String,
    pub text: String,
    /// Answers are stored in full immediately, while this UI-only count lets
    /// the terminal reveal them without ever changing the recorded text.
    pub revealed_chars: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct ChatUiState {
    pub focus: ChatFocus,
    pub input: String,
    /// A UTF-8 byte offset, always kept on a character boundary.
    pub cursor: usize,
    pub transcript: VecDeque<ChatTranscriptEntry>,
    /// Proposals are locally reviewable FIFO work, independent of durable
    /// coordinator pending actions. Only the head is ever actionable.
    pub proposals: VecDeque<ActionProposal>,
    pub queued: usize,
    pub pending: usize,
    pending_proposal_ids: VecDeque<uuid::Uuid>,
    confirming_proposal_ids: VecDeque<uuid::Uuid>,
    /// Set only by the renderer after the complete typed action fits in view.
    pub proposal_review_complete: bool,
    pub status: String,
    pub feedback: Option<String>,
    /// Number of newest transcript rows held below the viewport.
    pub transcript_scroll: usize,
}

impl Default for ChatUiState {
    fn default() -> Self {
        Self {
            focus: ChatFocus::Scan,
            input: String::new(),
            cursor: 0,
            transcript: VecDeque::new(),
            proposals: VecDeque::new(),
            queued: 0,
            pending: 0,
            pending_proposal_ids: VecDeque::new(),
            confirming_proposal_ids: VecDeque::new(),
            proposal_review_complete: false,
            status: "Ready".to_string(),
            feedback: None,
            transcript_scroll: 0,
        }
    }
}

impl ChatUiState {
    pub fn insert_text(&mut self, text: &str) -> bool {
        let remaining = MAX_CHAT_TEXT_BYTES.saturating_sub(self.input.len());
        let mut end = text.len().min(remaining);
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        if end == 0 && !text.is_empty() {
            self.feedback = Some("Message limit reached".to_string());
            return false;
        }
        self.input.insert_str(self.cursor, &text[..end]);
        self.cursor += end;
        if end != text.len() {
            self.feedback = Some("Message clipped at 4 KiB".to_string());
        }
        true
    }

    pub fn backspace(&mut self) -> bool {
        if self.cursor == 0 {
            return false;
        }
        let start = self.input[..self.cursor]
            .char_indices()
            .last()
            .map(|(i, _)| i)
            .unwrap_or(0);
        self.input.drain(start..self.cursor);
        self.cursor = start;
        true
    }

    pub fn clear_input(&mut self) {
        self.input.clear();
        self.cursor = 0;
    }

    pub fn current_proposal(&self) -> Option<&ActionProposal> {
        self.proposals.front()
    }

    pub fn take_current_proposal(&mut self) -> Option<ActionProposal> {
        let proposal = self.proposals.pop_front();
        if proposal.is_some() {
            self.proposal_review_complete = false;
        }
        proposal
    }

    pub fn mark_confirming(&mut self, proposal_id: uuid::Uuid) {
        if self.confirming_proposal_ids.len() < MAX_PENDING_CHAT_ACTIONS {
            self.confirming_proposal_ids.push_back(proposal_id);
        }
    }

    pub fn is_current_confirming(&self) -> bool {
        self.current_proposal().is_some_and(|proposal| {
            self.confirming_proposal_ids
                .iter()
                .any(|id| *id == proposal.proposal_id)
        })
    }

    fn clear_confirming_for_request(&mut self, request_id: uuid::Uuid) -> bool {
        let Some(proposal_id) = self.current_proposal().and_then(|proposal| {
            (proposal.request_id == request_id).then_some(proposal.proposal_id)
        }) else {
            return false;
        };
        let before = self.confirming_proposal_ids.len();
        self.confirming_proposal_ids.retain(|id| *id != proposal_id);
        before != self.confirming_proposal_ids.len()
    }

    fn push(&mut self, label: &str, text: String) {
        let mut text = sanitize_chat_text(&text);
        cap_utf8(&mut text, MAX_CHAT_TEXT_BYTES);
        self.transcript.push_back(ChatTranscriptEntry {
            label: label.to_string(),
            text,
            revealed_chars: (label == "Zentra").then_some(0),
        });
        while self.transcript.len() > MAX_CHAT_TRANSCRIPT {
            self.transcript.pop_front();
        }
        self.transcript_scroll = 0;
    }

    /// Reveal the newest unfinished assistant answer. The count is in chars,
    /// not bytes, so a tick can never slice a UTF-8 codepoint.
    pub fn advance_answer_reveal(&mut self) -> bool {
        let Some(entry) = self.transcript.iter_mut().rev().find(|entry| {
            entry
                .revealed_chars
                .is_some_and(|shown| shown < entry.text.chars().count())
        }) else {
            return false;
        };
        let total = entry.text.chars().count();
        let shown = entry.revealed_chars.unwrap_or(total);
        if shown >= total {
            return false;
        }
        // About fourteen frames for a long answer; short answers still feel
        // immediate. The cap prevents a single redraw from becoming costly.
        let step = (total / 14).clamp(8, 96);
        entry.revealed_chars = Some((shown + step).min(total));
        true
    }
}

/// Chat may originate outside the TUI. Redaction alone does not make terminal
/// control bytes safe, so remove them before state or rendering sees content.
pub fn sanitize_chat_text(input: &str) -> String {
    // Strip first so ANSI wrappers cannot break a secret-pattern match, then
    // redact the plain display text.
    crate::logging::redact(&strip_terminal_controls(input))
}

fn strip_terminal_controls(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' {
            match chars.next() {
                Some('[') => {
                    for next in chars.by_ref() {
                        if next.is_ascii() && ('@'..='~').contains(&next) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    let mut previous_was_escape = false;
                    for next in chars.by_ref() {
                        if next == '\u{7}' {
                            break;
                        }
                        if previous_was_escape && next == '\\' {
                            break;
                        }
                        previous_was_escape = next == '\u{1b}';
                    }
                }
                _ => {}
            }
            continue;
        }
        let code = ch as u32;
        if ch == '\n' || ch == '\t' {
            output.push(ch);
        } else if code < 0x20 || (0x7f..=0x9f).contains(&code) {
            continue;
        } else {
            output.push(ch);
        }
    }
    output
}

fn cap_utf8(value: &mut String, max: usize) {
    if value.len() > max {
        let mut end = max;
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        value.truncate(end);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanOutcome {
    Completed,
    Aborted,
    Reconfigure,
    ChangeProvider(String),
    BackToMenu,
}

pub struct PopupState {
    pub selected: usize,
}

impl Default for PopupState {
    fn default() -> Self {
        Self::new()
    }
}

impl PopupState {
    pub fn new() -> Self {
        Self { selected: 0 }
    }

    pub fn next(&mut self, item_count: usize) {
        if self.selected + 1 < item_count {
            self.selected += 1;
        }
    }

    pub fn prev(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanStatus {
    Queued,
    Waiting, // Report scanner: waits for all others
    Running,
    Done,
    Failed,
}

/// How a finished scan ended, for the completion banner and the activity line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanResult {
    /// Every scanner finished without error.
    Clean,
    /// Some scanners failed; the rest produced findings.
    PartialFailure { failed: usize },
    /// Every scanner failed. Nothing was produced, whatever the findings file says.
    AllFailed { failed: usize },
    /// The user stopped the run.
    Aborted,
}

#[derive(Debug, Clone)]
pub struct UiScanner {
    pub scanner_type: ScannerType,
    pub status: ScanStatus,
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
    pub info_count: u32,
    pub error: Option<String>,
    /// Distinct files this scanner read successfully. A set, so a re-read is not
    /// double counted and the panel matches `.zentra/coverage.md`.
    pub read_paths: std::collections::BTreeSet<String>,
}

impl UiScanner {
    fn new(scanner_type: ScannerType, is_report: bool) -> Self {
        Self {
            scanner_type,
            status: if is_report {
                ScanStatus::Waiting
            } else {
                ScanStatus::Queued
            },
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            info_count: 0,
            error: None,
            read_paths: std::collections::BTreeSet::new(),
        }
    }

    /// How many distinct files this scanner has read so far.
    pub fn files_read(&self) -> usize {
        self.read_paths.len()
    }

    pub fn add_finding(&mut self, severity: &Severity) {
        match severity {
            Severity::Critical => self.critical_count += 1,
            Severity::High => self.high_count += 1,
            Severity::Medium => self.medium_count += 1,
            Severity::Low => self.low_count += 1,
            Severity::Info => self.info_count += 1,
        }
    }
}

pub struct UiState {
    pub scanners: Vec<UiScanner>,
    pub findings: Vec<Finding>,
    pub activity: String,
    pub selected_idx: usize,
    pub peak_input_tokens: u32,
    pub total_tokens: u32,
    pub context_window: u32,
    pub model_info: String,
    pub branch: String,
    pub popup_open: bool,
    pub popup: PopupState,
    pub scan_done: bool,
    pub scan_aborted: bool,
    pub animation_index: usize,
    pub scan_start: std::time::Instant,
    pub scan_end: Option<std::time::Instant>,
    pub project_name: String,
    pub profiles: Vec<String>,
    pub provider_popup_open: bool,
    pub provider_popup: PopupState,
    pub provider_kind: String,
    pub mcp_status: Option<McpStatus>,
    pub theme: crate::tui::theme::Theme,
    pub chat: ChatUiState,
}

impl UiState {
    pub fn new(
        scanner_types: Vec<ScannerType>,
        model_info: String,
        context_window: u32,
        profiles: Vec<String>,
        branch: String,
        project_name: String,
        provider_kind: String,
    ) -> Self {
        let scanners = scanner_types
            .iter()
            .map(|&t| UiScanner::new(t, t == ScannerType::Report))
            .collect();
        Self {
            scanners,
            findings: Vec::new(),
            activity: String::new(),
            selected_idx: 0,
            peak_input_tokens: 0,
            total_tokens: 0,
            context_window,
            model_info,
            branch,
            popup_open: false,
            popup: PopupState::new(),
            scan_done: false,
            scan_aborted: false,
            animation_index: 0,
            scan_start: std::time::Instant::now(),
            scan_end: None,
            project_name,
            profiles,
            provider_popup_open: false,
            provider_popup: PopupState::new(),
            provider_kind,
            mcp_status: None,
            theme: crate::tui::theme::Theme::default(),
            chat: ChatUiState::default(),
        }
    }

    pub fn apply_event(&mut self, event: ScanEvent) {
        match event {
            ScanEvent::ScannerStarted(t) => {
                if let Some(s) = self.scanners.iter_mut().find(|s| s.scanner_type == t) {
                    s.status = ScanStatus::Running;
                }
            }
            ScanEvent::ScannerCompleted(t) => {
                if let Some(s) = self.scanners.iter_mut().find(|s| s.scanner_type == t) {
                    if s.status != ScanStatus::Failed {
                        s.status = ScanStatus::Done;
                    }
                }
            }
            ScanEvent::FindingAdded(f) => {
                if let Some(s) = self
                    .scanners
                    .iter_mut()
                    .find(|s| s.scanner_type.name() == f.scanner)
                {
                    s.add_finding(&f.severity);
                }
                self.findings.push(f);
                self.findings.sort_by_key(|f| f.severity.order());
                self.selected_idx = self.selected_idx.min(self.findings.len().saturating_sub(1));
            }
            ScanEvent::FileRead {
                scanner,
                path,
                outcome,
            } => {
                // Only a successful read is coverage. A too-large or failed read
                // is a hole, and `.zentra/coverage.md` tallies it separately.
                if matches!(outcome, crate::tools::fs_tools::ReadOutcome::Read { .. }) {
                    if let Some(s) = self.scanners.iter_mut().find(|s| s.scanner_type == scanner) {
                        s.read_paths.insert(path.replace('\\', "/"));
                    }
                }
            }
            ScanEvent::ToolCall { tool, arg, .. } => {
                let prefix = if self.provider_kind == "codex_cli" {
                    "↔"
                } else {
                    "→"
                };
                self.activity = if arg.is_empty() {
                    format!("{} {}", prefix, tool)
                } else {
                    format!("{} {}({})", prefix, tool, arg)
                };
            }
            ScanEvent::Error { scanner, message } => {
                if let Some(s) = self.scanners.iter_mut().find(|s| s.scanner_type == scanner) {
                    s.status = ScanStatus::Failed;
                    s.error = Some(message);
                }
            }
            ScanEvent::TokensUsed { input, output } => {
                self.total_tokens += input + output;
                if input > self.peak_input_tokens {
                    self.peak_input_tokens = input;
                }
            }
            ScanEvent::McpChannelStatus(status) => {
                self.mcp_status = Some(status);
            }
        }
    }

    /// Chat never enters the ScanEvent channel and never mutates scan progress,
    /// findings, coverage, or token accounting.
    pub fn apply_chat_event(&mut self, event: ChatEvent) {
        match event {
            ChatEvent::RequestQueued {
                request_id: _,
                position,
            } => {
                self.chat.queued = self.chat.queued.max(position);
                self.chat.status = "Queued".to_string();
                self.chat.push("Status", "Queued".to_string());
            }
            ChatEvent::Answer {
                request_id: _,
                text,
            } => {
                self.chat.queued = self.chat.queued.saturating_sub(1);
                self.chat.status = "Answered".to_string();
                self.chat.push("Zentra", text);
            }
            ChatEvent::Proposal { proposal } => {
                self.chat.queued = self.chat.queued.saturating_sub(1);
                self.chat.status = "Proposal ready — review locally".to_string();
                if self.chat.proposals.len() < MAX_PENDING_CHAT_ACTIONS {
                    self.chat.proposals.push_back(proposal);
                } else {
                    self.chat
                        .push("CHAT ERROR", "Proposal queue is full".to_string());
                }
            }
            ChatEvent::Confirmed { proposal_id } => {
                if let Some(index) = self
                    .chat
                    .confirming_proposal_ids
                    .iter()
                    .position(|id| *id == proposal_id)
                {
                    self.chat.confirming_proposal_ids.remove(index);
                    if self
                        .chat
                        .current_proposal()
                        .is_some_and(|proposal| proposal.proposal_id == proposal_id)
                    {
                        self.chat.take_current_proposal();
                    }
                    self.chat.pending += 1;
                    self.chat.pending_proposal_ids.push_back(proposal_id);
                    self.chat.status = "Pending next boundary".to_string();
                }
            }
            ChatEvent::Applied {
                proposal_id,
                boundary,
            } => {
                self.clear_terminal_proposal(proposal_id);
                self.remove_pending_proposal(proposal_id);
                self.chat.status = format!("Applied at {boundary:?}");
                self.chat
                    .push("Status", format!("Proposal applied at {boundary:?}"));
            }
            ChatEvent::Deferred {
                proposal_id,
                reason,
            } => {
                self.clear_terminal_proposal(proposal_id);
                self.remove_pending_proposal(proposal_id);
                self.chat.status = "Proposal deferred".to_string();
                self.chat.push("Status", reason);
            }
            ChatEvent::Cancelled { request_id } => {
                self.chat.queued = self.chat.queued.saturating_sub(1);
                self.chat.proposals.retain(|p| p.request_id != request_id);
                self.chat.status = "Request cancelled".to_string();
                self.chat.push("Status", "Request cancelled".to_string());
            }
            ChatEvent::Error {
                request_id,
                kind,
                message,
            } => {
                self.chat.queued = self.chat.queued.saturating_sub(1);
                if request_id.is_some_and(|id| self.chat.clear_confirming_for_request(id)) {
                    self.chat.status = "Confirmation failed — retry".to_string();
                } else {
                    self.chat.status = format!("{kind:?}");
                }
                self.chat.push("CHAT ERROR", message);
            }
        }
    }

    fn clear_terminal_proposal(&mut self, proposal_id: uuid::Uuid) {
        let was_current = self
            .chat
            .current_proposal()
            .is_some_and(|p| p.proposal_id == proposal_id);
        self.chat.proposals.retain(|p| p.proposal_id != proposal_id);
        self.chat
            .confirming_proposal_ids
            .retain(|id| *id != proposal_id);
        if was_current {
            self.chat.proposal_review_complete = false;
        }
    }

    fn remove_pending_proposal(&mut self, proposal_id: uuid::Uuid) {
        if let Some(index) = self
            .chat
            .pending_proposal_ids
            .iter()
            .position(|id| *id == proposal_id)
        {
            self.chat.pending_proposal_ids.remove(index);
            self.chat.pending = self.chat.pending.saturating_sub(1);
        }
    }

    pub fn all_done(&self) -> bool {
        self.scanners
            .iter()
            .all(|s| matches!(s.status, ScanStatus::Done | ScanStatus::Failed))
    }

    /// How many scanners ended in `Failed`.
    pub fn failed_count(&self) -> usize {
        self.scanners
            .iter()
            .filter(|s| s.status == ScanStatus::Failed)
            .count()
    }

    /// How the run actually ended.
    ///
    /// `all_done()` is true whether every scanner succeeded or every one failed,
    /// so the completion banner used to read as success either way — a
    /// rate-limited scan printed "Hacked in 2s" over an empty findings file.
    pub fn outcome(&self) -> ScanResult {
        if self.scan_aborted {
            return ScanResult::Aborted;
        }
        match self.failed_count() {
            0 => ScanResult::Clean,
            failed if failed == self.scanners.len() => ScanResult::AllFailed { failed },
            failed => ScanResult::PartialFailure { failed },
        }
    }

    pub fn select_next(&mut self) {
        if !self.findings.is_empty() && self.selected_idx < self.findings.len() - 1 {
            self.selected_idx += 1;
        }
    }

    pub fn select_prev(&mut self) {
        if self.selected_idx > 0 {
            self.selected_idx -= 1;
        }
    }

    pub fn selected_finding(&self) -> Option<&Finding> {
        self.findings.get(self.selected_idx)
    }

    pub fn total_findings(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.scanner != "framework")
            .count()
    }

    pub fn token_pct(&self) -> u16 {
        if self.context_window == 0 {
            return 0;
        }
        ((self.peak_input_tokens as f64 / self.context_window as f64) * 100.0).min(100.0) as u16
    }

    pub fn toggle_popup(&mut self) {
        self.popup_open = !self.popup_open;
        if self.popup_open {
            self.popup = PopupState::new();
        }
    }

    pub fn toggle_provider_popup(&mut self) {
        self.provider_popup_open = !self.provider_popup_open;
        if self.provider_popup_open {
            self.provider_popup = PopupState::new();
        }
    }

    pub fn mark_complete(&mut self) {
        if self.scan_end.is_some() {
            return;
        }
        self.scan_done = true;
        self.scan_end = Some(std::time::Instant::now());
    }

    pub fn abort_scan(&mut self) {
        if self.scan_done {
            return;
        }
        for s in &mut self.scanners {
            if s.status == ScanStatus::Running {
                s.status = ScanStatus::Failed;
            }
        }
        self.scan_aborted = true;
        self.scan_done = true;
        self.scan_end = Some(std::time::Instant::now());
    }

    pub fn elapsed_duration(&self) -> std::time::Duration {
        self.scan_end
            .map(|end| {
                end.checked_duration_since(self.scan_start)
                    .unwrap_or(std::time::Duration::ZERO)
            })
            .unwrap_or_else(|| self.scan_start.elapsed())
    }
}
