use crate::agent::chat::{ActionProposal, ChatAction, ChatCommand, ChatEvent};
use crate::agent::{McpStatus, ScanEvent, ScannerType};
use crate::tui::{sanitize_chat_text, ChatFocus, ScanOutcome, ScanResult, ScanStatus, UiState};
use anyhow::Result;
use crossterm::{
    event::{
        self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent,
        MouseEventKind,
    },
    execute,
};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph},
    Frame,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Format a token count compactly for the scan UI: `999`, `12.9k`, `13M`.
/// One decimal place, with a trailing `.0` dropped (so `13000` → `13k`).
fn fmt_tokens(n: u32) -> String {
    let n = n as f64;
    let (val, suffix) = if n < 1_000.0 {
        return format!("{}", n as u64);
    } else if n < 1_000_000.0 {
        (n / 1_000.0, "k")
    } else {
        (n / 1_000_000.0, "M")
    };
    let rounded = (val * 10.0).round() / 10.0;
    if rounded.fract().abs() < f64::EPSILON {
        format!("{}{}", rounded as u64, suffix)
    } else {
        format!("{:.1}{}", rounded, suffix)
    }
}

pub fn popup_items(scan_done: bool) -> Vec<&'static str> {
    let mut items = vec![
        "Change Provider and Restart Scan",
        "Add Provider",
        "Back to Menu",
    ];
    if !scan_done {
        items.insert(2, "Abort Scan");
    }
    items
}

pub const LOADING_FRAMES: &[char] = &['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

pub const ACTIVITY_VERBS: &[&str] = &[
    "Heraldiphosing",
    "Syronysynthesizing",
    "Gabonitificating",
    "Jeddifying",
    "Kodecrafteristicizing",
    "Jaredystimating",
    "Adding Salt",
    "Hacking",
    "Solodifying",
    "Zentranizing",
    "Connecting to Biringan Servers",
];

const SCANNER_PANEL_WIDTH: u16 = 34;
const FINDINGS_PANEL_MIN_WIDTH: u16 = 20;
const FAILED_PREVIEW_PREFIX: &str = "  └ ";
pub const CHAT_NARROW_WIDTH: u16 = 108;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChatHitRegions {
    pub scan: Option<Rect>,
    pub chat: Option<Rect>,
    pub input: Option<Rect>,
    pub confirm: Option<Rect>,
    pub reject: Option<Rect>,
    pub transcript: Option<Rect>,
    pub layout_valid: bool,
    pub transcript_max_scroll: usize,
    /// Proposal identity for every actionable control in this render.
    pub proposal_id: Option<uuid::Uuid>,
}

impl ChatHitRegions {
    fn contains(region: Option<Rect>, column: u16, row: u16) -> bool {
        region
            .is_some_and(|r| column >= r.x && column < r.right() && row >= r.y && row < r.bottom())
    }
}

struct MouseCaptureGuard;
impl MouseCaptureGuard {
    fn enable() -> std::io::Result<Self> {
        execute!(std::io::stdout(), event::EnableMouseCapture)?;
        Ok(Self)
    }
}
impl Drop for MouseCaptureGuard {
    fn drop(&mut self) {
        let _ = execute!(std::io::stdout(), event::DisableMouseCapture);
    }
}

/// UI-owned ends of the independent chat channels. The command lane creates
/// these with `chat_coordinator::channels()` and passes `Some(...)` to
/// `run_scan_ui_with_chat`; legacy callers keep using `run_scan_ui`.
pub struct ChatUiChannels {
    pub command_tx: mpsc::Sender<ChatCommand>,
    pub event_rx: mpsc::Receiver<ChatEvent>,
}

impl ChatUiChannels {
    /// Never wait during teardown: a busy coordinator must not hold the TUI.
    pub fn close(&self) {
        let _ = self.command_tx.try_send(ChatCommand::Close);
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run_scan_ui(
    rx: mpsc::Receiver<ScanEvent>,
    scanners: Vec<ScannerType>,
    model_info: String,
    context_window: u32,
    cancel_token: CancellationToken,
    profiles: Vec<String>,
    branch: String,
    project_name: String,
    provider_kind: String,
) -> Result<ScanOutcome> {
    run_scan_ui_with_chat(
        rx,
        scanners,
        model_info,
        context_window,
        cancel_token,
        profiles,
        branch,
        project_name,
        provider_kind,
        None,
    )
    .await
}

/// Chat-enabled scan UI. `None` preserves the prior scan-only experience.
#[allow(clippy::too_many_arguments)]
pub async fn run_scan_ui_with_chat(
    mut rx: mpsc::Receiver<ScanEvent>,
    scanners: Vec<ScannerType>,
    model_info: String,
    context_window: u32,
    cancel_token: CancellationToken,
    profiles: Vec<String>,
    branch: String,
    project_name: String,
    provider_kind: String,
    mut chat: Option<ChatUiChannels>,
) -> Result<ScanOutcome> {
    let mut terminal = ratatui::init();
    // Legacy scan-only sessions never alter mouse mode (or gain its failure path).
    let mouse_capture = if chat.is_some() {
        match MouseCaptureGuard::enable() {
            Ok(guard) => Some(guard),
            Err(error) => {
                ratatui::restore();
                return Err(error.into());
            }
        }
    } else {
        None
    };
    let result = run_loop(
        &mut terminal,
        &mut rx,
        scanners,
        model_info,
        context_window,
        cancel_token.clone(),
        profiles,
        branch,
        project_name,
        provider_kind,
        chat.as_mut(),
    )
    .await;
    drop(mouse_capture); // DisableMouseCapture precedes terminal restoration.
    ratatui::restore();
    if let Some(channels) = chat.as_ref() {
        channels.close();
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn run_loop(
    terminal: &mut ratatui::DefaultTerminal,
    rx: &mut mpsc::Receiver<ScanEvent>,
    scanners: Vec<ScannerType>,
    model_info: String,
    context_window: u32,
    cancel_token: CancellationToken,
    profiles: Vec<String>,
    branch: String,
    project_name: String,
    provider_kind: String,
    mut chat: Option<&mut ChatUiChannels>,
) -> Result<ScanOutcome> {
    let mut state = UiState::new(
        scanners,
        model_info,
        context_window,
        profiles,
        branch,
        project_name,
        provider_kind,
    );
    state.theme = crate::tui::theme::resolve(
        crate::config::GlobalConfig::load()
            .ok()
            .and_then(|g| g.theme)
            .as_deref(),
    );
    let mut input_ticker = tokio::time::interval(std::time::Duration::from_millis(25));
    let mut animation_ticker = tokio::time::interval(std::time::Duration::from_millis(80));
    let mut hit_regions = ChatHitRegions::default();

    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                state.apply_event(event);
            }
            event = async {
                match chat.as_deref_mut() {
                    Some(channels) => channels.event_rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                if let Some(event) = event { state.apply_chat_event(event); } else { chat = None; }
                // Drain the bounded chat queue without yielding scan rendering.
                if let Some(channels) = chat.as_deref_mut() { drain_chat_events(&mut state, &mut channels.event_rx); }
            }
            _ = input_ticker.tick() => {
                // Poll input without blocking. We deliberately avoid crossterm's
                // EventStream: on Windows its reader thread blocks in the native
                // console read and is not torn down on drop, leaking a thread per
                // scan that then contends with the menu's event::poll and makes
                // navigation sluggish.
                while event::poll(std::time::Duration::from_millis(0))? {
                    match event::read()? {
                    Event::Resize(_, _) => {
                        invalidate_chat_layout(&mut state, &mut hit_regions);
                        // Do not let a queued Enter/click use a pre-resize review.
                        break;
                    }
                    Event::Paste(text) => {
                        if !state.provider_popup_open && !state.popup_open {
                            if let Some(channels) = chat.as_deref_mut() {
                                if state.chat.focus == ChatFocus::Chat {
                                    // Paste follows the same bounded UTF-8 path as typing.
                                    let _ = channels; // channel presence enables chat input.
                                    state.chat.insert_text(&text);
                                }
                            }
                        }
                    }
                    Event::Key(key) => {
                        if key.kind != KeyEventKind::Press {
                            // ignore release / repeat events to prevent double-step
                        } else if is_global_abort_key(key) {
                            // This deliberately precedes every overlay and chat path.
                            cancel_token.cancel();
                            return Ok(ScanOutcome::Aborted);
                        } else if state.provider_popup_open {
                            match key.code {
                                KeyCode::Esc => state.toggle_provider_popup(),
                                KeyCode::Up => state.provider_popup.prev(),
                                KeyCode::Down => state.provider_popup.next(state.profiles.len()),
                                KeyCode::Enter => {
                                    if let Some(name) = state.profiles.get(state.provider_popup.selected) {
                                        cancel_token.cancel();
                                        return Ok(ScanOutcome::ChangeProvider(name.clone()));
                                    }
                                }
                                _ => {}
                            }
                        } else if state.popup_open {
                            match key.code {
                                KeyCode::Esc => state.toggle_popup(),
                                KeyCode::Up => state.popup.prev(),
                                KeyCode::Down => {
                                    let len = popup_items(state.scan_done).len();
                                    state.popup.next(len);
                                }
                                KeyCode::Enter => {
                                    let items = popup_items(state.scan_done);
                                    // Clamp selected in case list shrank (e.g. scan completed while popup was open)
                                    if state.popup.selected >= items.len() {
                                        state.popup.selected = items.len().saturating_sub(1);
                                    }
                                    match items.get(state.popup.selected).copied().unwrap_or("") {
                                        "Change Provider and Restart Scan" => {
                                            cancel_token.cancel();
                                            state.toggle_popup();
                                            state.toggle_provider_popup();
                                        }
                                        "Add Provider" => {
                                            return Ok(ScanOutcome::Reconfigure);
                                        }
                                        "Abort Scan" => {
                                            cancel_token.cancel();
                                            state.abort_scan();
                                            state.activity = "✗ Scan aborted — browse findings · q to exit".to_string();
                                            state.toggle_popup();
                                        }
                                        "Back to Menu" => {
                                            if !state.scan_done { cancel_token.cancel(); }
                                            return Ok(exit_outcome(&state));
                                        }
                                        _ => {}
                                    }
                                }
                                _ => {}
                            }
                        } else if handle_chat_key(&mut state, key, chat.as_deref_mut()) {
                            // Chat consumes only its own focused interaction.
                        } else {
                            match key.code {
                                KeyCode::Char('q') | KeyCode::Esc => {
                                    let outcome = exit_outcome(&state);
                                    if outcome == ScanOutcome::Aborted { cancel_token.cancel(); }
                                    return Ok(outcome);
                                }
                                KeyCode::Char('p') | KeyCode::Char('?') => state.toggle_popup(),
                                KeyCode::Down => state.select_next(),
                                KeyCode::Up => state.select_prev(),
                                _ => {}
                            }
                        }
                    }
                    Event::Mouse(mouse) if !state.provider_popup_open && !state.popup_open => {
                        if let Some(channels) = chat.as_deref_mut() {
                            let _ = handle_chat_mouse(&mut state, mouse, &mut hit_regions, channels);
                        }
                    }
                    _ => {}
                    }
                }
            }
            _ = animation_ticker.tick() => {
                state.animation_index = state.animation_index.wrapping_add(1);
                state.chat.advance_answer_reveal();
            }
        }

        // Detect scan completion after any event (Bug 4)
        if state.all_done() && !state.scan_done {
            state.mark_complete();
            state.activity = completion_hint(state.outcome());
        }

        terminal.draw(|f| render(f, &mut state, chat.is_some(), &mut hit_regions))?;
    }
}

pub fn invalidate_chat_layout(state: &mut UiState, hits: &mut ChatHitRegions) {
    state.chat.proposal_review_complete = false;
    *hits = ChatHitRegions::default();
}

/// Navigation after a naturally terminal scan must not cancel the completed
/// orchestrator task. Before that point the same keys are an explicit abort.
pub fn exit_outcome(state: &UiState) -> ScanOutcome {
    if state.scan_done && !state.scan_aborted {
        ScanOutcome::Completed
    } else {
        ScanOutcome::Aborted
    }
}

/// Kept pure so key precedence is testable without a crossterm terminal.
pub fn is_global_abort_key(key: KeyEvent) -> bool {
    key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c'))
}

/// Pull every currently available chat event without awaiting. This keeps a
/// burst of terminal lifecycle events in arrival order and never delays scan IO.
pub fn drain_chat_events(state: &mut UiState, rx: &mut mpsc::Receiver<ChatEvent>) {
    while let Ok(event) = rx.try_recv() {
        state.apply_chat_event(event);
    }
}

fn render(frame: &mut Frame, state: &mut UiState, chat_enabled: bool, hits: &mut ChatHitRegions) {
    *hits = ChatHitRegions::default();
    let area = frame.area();

    // Paint the whole frame with the theme background first.
    frame.render_widget(
        ratatui::widgets::Block::default()
            .style(ratatui::style::Style::default().bg(state.theme.bg)),
        frame.area(),
    );

    let chunks = Layout::vertical([
        Constraint::Length(7), // 4-line ASCII banner + model line + 2 borders
        Constraint::Min(6),
        Constraint::Length(1),
        Constraint::Length(8), // detail: 6 inner rows for title/loc/desc/fix
        Constraint::Length(1),
    ])
    .split(area);

    render_header(frame, chunks[0], state);
    if !chat_enabled {
        render_body(frame, chunks[1], state);
        render_activity(frame, chunks[2], state);
        render_detail(frame, chunks[3], state);
    } else if chat_uses_primary_pane(area.width, state.chat.focus) {
        // On narrow terminals Chat owns the complete work area. Rendering it
        // only in the old body row left an unusable, cramped drawer.
        let primary = Rect::new(
            chunks[1].x,
            chunks[1].y,
            chunks[1].width,
            chunks[3].bottom().saturating_sub(chunks[1].y),
        );
        render_chat_drawer(frame, primary, state, hits);
    } else {
        let main = Rect::new(
            chunks[1].x,
            chunks[1].y,
            chunks[1].width,
            chunks[3].bottom().saturating_sub(chunks[1].y),
        );
        if main.width <= 42 {
            let cols = Layout::horizontal([Constraint::Min(1), Constraint::Length(1)]).split(main);
            render_body(frame, cols[0], state);
            render_chat_drawer(frame, cols[1], state, hits);
            hits.scan = Some(cols[0]);
        } else {
            let chat_width = chat_pane_width(main.width);
            let cols = Layout::horizontal([
                Constraint::Min(40),
                Constraint::Length(2),
                Constraint::Length(chat_width),
            ])
            .split(main);
            let left = Layout::vertical([
                Constraint::Min(6),
                Constraint::Length(1),
                Constraint::Length(8),
            ])
            .split(cols[0]);
            render_body(frame, left[0], state);
            render_activity(frame, left[1], state);
            render_detail(frame, left[2], state);
            render_chat_drawer(frame, cols[2], state, hits);
            hits.scan = Some(cols[0]);
        }
    }
    render_keys(
        frame,
        chunks[4],
        state.popup_open,
        state.scan_done,
        &state.theme,
        chat_enabled.then_some(state.chat.focus),
    );

    if state.popup_open || state.provider_popup_open {
        *hits = ChatHitRegions::default();
        state.chat.proposal_review_complete = false;
    }
    if state.popup_open {
        render_popup(frame, area, &state.popup, state.scan_done, &state.theme);
    }
    if state.provider_popup_open {
        render_provider_popup(
            frame,
            area,
            &state.provider_popup,
            &state.profiles,
            &state.theme,
        );
    }
    if !state.popup_open && !state.provider_popup_open {
        hits.layout_valid = true;
    }
}

fn send_chat(state: &mut UiState, channels: &mut ChatUiChannels, command: ChatCommand) -> bool {
    match channels.command_tx.try_send(command) {
        Ok(()) => {
            state.chat.feedback = None;
            true
        }
        Err(mpsc::error::TrySendError::Full(_)) => {
            state.chat.feedback = Some("Chat is busy — try again shortly".to_string());
            false
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            state.chat.feedback = Some("Chat is unavailable".to_string());
            false
        }
    }
}

/// Mouse routing uses only regions produced by the latest render. Commands are
/// intentionally `try_send` through the same guarded path as keyboard input.
pub fn handle_chat_mouse(
    state: &mut UiState,
    mouse: MouseEvent,
    hits: &mut ChatHitRegions,
    channels: &mut ChatUiChannels,
) -> bool {
    let (x, y) = (mouse.column, mouse.row);
    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            if ChatHitRegions::contains(hits.scan, x, y) {
                state.chat.focus = ChatFocus::Scan;
                return true;
            }
            if ChatHitRegions::contains(hits.confirm, x, y) {
                if hits.layout_valid
                    && state.chat.proposal_review_complete
                    && !state.chat.is_current_confirming()
                    && hits.proposal_id == state.chat.current_proposal().map(|p| p.proposal_id)
                {
                    if let Some(proposal) = state.chat.current_proposal() {
                        let id = proposal.proposal_id;
                        if send_chat(state, channels, ChatCommand::Confirm { proposal_id: id }) {
                            state.chat.mark_confirming(id);
                            state.chat.status = "Confirming…".to_string();
                            invalidate_chat_layout(state, hits);
                        }
                    }
                }
                return true;
            }
            if ChatHitRegions::contains(hits.reject, x, y) {
                if hits.layout_valid
                    && !state.chat.is_current_confirming()
                    && hits.proposal_id == state.chat.current_proposal().map(|p| p.proposal_id)
                {
                    if let Some(proposal) = state.chat.current_proposal() {
                        let id = proposal.proposal_id;
                        if send_chat(state, channels, ChatCommand::Reject { proposal_id: id }) {
                            state.chat.take_current_proposal();
                            state.chat.status = "Proposal rejected".to_string();
                            state.chat.push("You", "Proposal rejected".to_string());
                            invalidate_chat_layout(state, hits);
                        }
                    }
                }
                return true;
            }
            if ChatHitRegions::contains(hits.chat, x, y)
                || ChatHitRegions::contains(hits.input, x, y)
            {
                state.chat.focus = ChatFocus::Chat;
                return true;
            }
            false
        }
        MouseEventKind::ScrollUp if ChatHitRegions::contains(hits.transcript, x, y) => {
            state.chat.transcript_scroll = state
                .chat
                .transcript_scroll
                .saturating_add(1)
                .min(hits.transcript_max_scroll);
            true
        }
        MouseEventKind::ScrollDown if ChatHitRegions::contains(hits.transcript, x, y) => {
            state.chat.transcript_scroll = state.chat.transcript_scroll.saturating_sub(1);
            true
        }
        _ => false,
    }
}

/// Routes only Chat-owned keys. Scan focus deliberately leaves scan shortcuts
/// alone; Chat focus consumes editing keys so text never triggers navigation.
pub fn handle_chat_key(
    state: &mut UiState,
    key: KeyEvent,
    channels: Option<&mut ChatUiChannels>,
) -> bool {
    let Some(channels) = channels else {
        return false;
    };
    // Ctrl+C remains the global scan-abort path. Do not close a live chat
    // coordinator while leaving the scan UI alive.
    if is_global_abort_key(key) {
        return false;
    }
    match key.code {
        KeyCode::Tab => {
            state.chat.focus = match state.chat.focus {
                ChatFocus::Scan => ChatFocus::Chat,
                ChatFocus::Chat => ChatFocus::Scan,
            };
            true
        }
        KeyCode::Char('c') if key.modifiers.is_empty() && state.chat.focus == ChatFocus::Scan => {
            state.chat.focus = ChatFocus::Chat;
            true
        }
        KeyCode::Esc
            if state.chat.focus == ChatFocus::Chat && state.chat.current_proposal().is_some() =>
        {
            if state.chat.is_current_confirming() {
                state.chat.status = "Confirmation in progress".to_string();
                state.chat.feedback = None;
                return true;
            }
            let id = state.chat.current_proposal().unwrap().proposal_id;
            if send_chat(state, channels, ChatCommand::Reject { proposal_id: id }) {
                state.chat.take_current_proposal();
                state.chat.status = "Proposal rejected".to_string();
                state.chat.push("YOU", "Proposal rejected".to_string());
            }
            true
        }
        KeyCode::Enter
            if state.chat.focus == ChatFocus::Chat && state.chat.current_proposal().is_some() =>
        {
            if state.chat.is_current_confirming() {
                state.chat.feedback = Some("Confirming…".to_string());
                return true;
            }
            if !state.chat.proposal_review_complete {
                state.chat.feedback =
                    Some("Resize to review the full action before confirming".to_string());
                return true;
            }
            let id = state.chat.current_proposal().unwrap().proposal_id;
            if send_chat(state, channels, ChatCommand::Confirm { proposal_id: id }) {
                state.chat.mark_confirming(id);
                state.chat.status = "Confirming…".to_string();
            }
            true
        }
        KeyCode::Esc if state.chat.focus == ChatFocus::Chat && !state.chat.input.is_empty() => {
            state.chat.clear_input();
            state.chat.feedback = None;
            true
        }
        KeyCode::Esc if state.chat.focus == ChatFocus::Chat => {
            state.chat.focus = ChatFocus::Scan;
            true
        }
        KeyCode::Enter if state.chat.focus == ChatFocus::Chat => {
            let text = state.chat.input.trim().to_string();
            if text.is_empty() {
                state.chat.feedback = Some("Type a question first".to_string());
                return true;
            }
            let request_id = uuid::Uuid::new_v4();
            if send_chat(
                state,
                channels,
                ChatCommand::Ask {
                    request_id,
                    text: text.clone(),
                },
            ) {
                state.chat.push("You", text);
                state.chat.clear_input();
                state.chat.queued += 1;
                state.chat.status = "Sending…".to_string();
            }
            true
        }
        KeyCode::Backspace if state.chat.focus == ChatFocus::Chat => {
            state.chat.backspace();
            true
        }
        KeyCode::Left if state.chat.focus == ChatFocus::Chat => {
            if state.chat.cursor > 0 {
                state.chat.cursor = state.chat.input[..state.chat.cursor]
                    .char_indices()
                    .last()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
            }
            true
        }
        KeyCode::Right if state.chat.focus == ChatFocus::Chat => {
            if state.chat.cursor < state.chat.input.len() {
                state.chat.cursor += state.chat.input[state.chat.cursor..]
                    .chars()
                    .next()
                    .unwrap()
                    .len_utf8();
            }
            true
        }
        KeyCode::Char(ch)
            if state.chat.focus == ChatFocus::Chat
                && (key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT) =>
        {
            state.chat.insert_text(&ch.to_string());
            true
        }
        _ if state.chat.focus == ChatFocus::Chat => true,
        _ => false,
    }
}

/// At narrow widths the focused pane gets the work area, while Chat remains
/// visible beside Scan when scan navigation is active.
pub fn chat_uses_primary_pane(width: u16, focus: ChatFocus) -> bool {
    width < CHAT_NARROW_WIDTH && focus == ChatFocus::Chat
}

/// Chat gets a deliberate near-half column on normal terminals, with a hard
/// cap that leaves the scanner and findings panes genuinely usable.
pub fn chat_pane_width(width: u16) -> u16 {
    ((width as u32 * 49 / 100) as u16)
        .clamp(38, 68)
        .min(width.saturating_sub(42))
}

fn cell_width(text: &str) -> usize {
    text.chars()
        .map(|ch| {
            if ch.is_ascii() || ('\u{2500}'..='\u{257f}').contains(&ch) {
                1
            } else {
                2
            }
        })
        .sum()
}

fn pad_cells(text: &str, width: usize) -> String {
    format!(
        "{text}{}",
        " ".repeat(width.saturating_sub(cell_width(text)))
    )
}

fn take_cells(text: &str, width: usize) -> String {
    let mut output = String::new();
    let mut used = 0;
    for ch in text.chars() {
        let cells = if ch.is_ascii() { 1 } else { 2 };
        if used + cells > width {
            break;
        }
        output.push(ch);
        used += cells;
    }
    output
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TranscriptSpeaker {
    You,
    Zentra,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TranscriptRowKind {
    BubbleBorder(TranscriptSpeaker),
    BubbleContent {
        speaker: TranscriptSpeaker,
        label: bool,
    },
    Separator,
    Status,
    Error,
}

#[derive(Clone, Debug)]
struct RenderedTranscriptRow {
    text: String,
    kind: TranscriptRowKind,
}

/// Rows as rendered: conversational entries are bounded bubbles with an inline
/// sender prefix; compact lifecycle rows remain deliberately unboxed.
pub fn transcript_rows(
    entries: &std::collections::VecDeque<crate::tui::ChatTranscriptEntry>,
    width: u16,
) -> Vec<String> {
    transcript_rendered_rows(entries, width)
        .into_iter()
        .map(|row| row.text)
        .collect()
}

fn transcript_rendered_rows(
    entries: &std::collections::VecDeque<crate::tui::ChatTranscriptEntry>,
    width: u16,
) -> Vec<RenderedTranscriptRow> {
    let width = width.max(1) as usize;
    let mut rows = Vec::new();
    let mut previous_was_message = false;
    for entry in entries {
        let conversational = matches!(entry.label.as_str(), "You" | "YOU" | "Zentra" | "ZENTRA");
        if conversational {
            if previous_was_message {
                rows.push(RenderedTranscriptRow {
                    text: "┄".repeat(width),
                    kind: TranscriptRowKind::Separator,
                });
            }
            let (speaker, label) = if entry.label.eq_ignore_ascii_case("you") {
                (TranscriptSpeaker::You, "You")
            } else {
                (TranscriptSpeaker::Zentra, "Zentra")
            };
            let visible = entry.revealed_chars.map_or_else(
                || entry.text.clone(),
                |count| entry.text.chars().take(count).collect(),
            );
            let user_indent = if speaker == TranscriptSpeaker::You {
                2.min(width.saturating_sub(3))
            } else {
                0
            };
            // indent + two borders + two padding cells + content <= viewport.
            let content_width = width.saturating_sub(user_indent + 4).max(1);
            let indent = " ".repeat(user_indent);
            rows.push(RenderedTranscriptRow {
                text: format!("{indent}╭{}╮", "─".repeat(content_width + 2)),
                kind: TranscriptRowKind::BubbleBorder(speaker),
            });
            let first = take_cells(&format!("{label}: "), content_width);
            let continuation = " ".repeat(cell_width(&first).min(content_width));
            // A label belongs to exactly one physical content row. Keeping
            // this independent of source-line/wrap indices also covers an
            // empty first source line and a first line that wraps immediately.
            let mut label_pending = true;
            for (source_index, source) in sanitize_chat_text(&visible).split('\n').enumerate() {
                let mut line = if source_index == 0 {
                    first.clone()
                } else {
                    continuation.clone()
                };
                let mut used = cell_width(&line);
                for ch in source.chars() {
                    let cells = if ch.is_ascii() { 1 } else { 2 };
                    if used + cells > content_width && used > 0 {
                        rows.push(RenderedTranscriptRow {
                            text: format!("{indent}│ {} │", pad_cells(&line, content_width)),
                            kind: TranscriptRowKind::BubbleContent {
                                speaker,
                                label: std::mem::replace(&mut label_pending, false),
                            },
                        });
                        line = continuation.clone();
                        used = cell_width(&line);
                    }
                    line.push(ch);
                    used += cells;
                }
                rows.push(RenderedTranscriptRow {
                    text: format!("{indent}│ {} │", pad_cells(&line, content_width)),
                    kind: TranscriptRowKind::BubbleContent {
                        speaker,
                        label: std::mem::replace(&mut label_pending, false),
                    },
                });
            }
            rows.push(RenderedTranscriptRow {
                text: format!("{indent}╰{}╯", "─".repeat(content_width + 2)),
                kind: TranscriptRowKind::BubbleBorder(speaker),
            });
        } else {
            let (label, prefix) = if entry.label == "CHAT ERROR" {
                ("Error", "! ")
            } else {
                ("Status", "· ")
            };
            let first = take_cells(&format!("{prefix}{label}: "), width);
            let indent = " ".repeat(cell_width(&first).min(width.saturating_sub(1)));
            let mut line = first.clone();
            let mut used = cell_width(&line);
            for ch in sanitize_chat_text(&entry.text).chars() {
                let cells = if ch.is_ascii() { 1 } else { 2 };
                if used + cells > width && used > 0 {
                    rows.push(RenderedTranscriptRow {
                        text: line,
                        kind: if label == "Error" {
                            TranscriptRowKind::Error
                        } else {
                            TranscriptRowKind::Status
                        },
                    });
                    line = indent.clone();
                    used = cell_width(&line);
                }
                line.push(ch);
                used += cells;
            }
            rows.push(RenderedTranscriptRow {
                text: line,
                kind: if label == "Error" {
                    TranscriptRowKind::Error
                } else {
                    TranscriptRowKind::Status
                },
            });
        }
        previous_was_message = conversational;
    }
    rows
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalReview {
    pub content: String,
    pub required_inner_lines: u16,
    pub complete: bool,
}

/// Fixed, typed rendering of a proposal. It is complete only when all bounded
/// canonical paths fit in the supplied review rectangle.
pub fn proposal_review(area: Rect, proposal: &ActionProposal) -> ProposalReview {
    let mut lines = vec![match &proposal.action {
        ChatAction::FocusAndRerun { scanners, scope } => {
            format!(
                "FOCUS & RERUN · {}",
                scanners
                    .iter()
                    .map(|scanner| scanner.name())
                    .collect::<Vec<_>>()
                    .join(", ")
            ) + &format!("\nFragments: {:?}", scope.fragments)
                + if scope.paths.is_empty() {
                    ""
                } else {
                    "\nPaths:"
                }
        }
        ChatAction::PrioritizeVulnerability { category } => format!("PRIORITIZE · {category:?}"),
    }];
    if let ChatAction::FocusAndRerun { scope, .. } = &proposal.action {
        lines.extend(scope.paths.iter().map(|path| format!("- {path}")));
    }
    lines.push(format!("Earliest: {:?}", proposal.earliest_boundary));
    let content = sanitize_chat_text(&lines.join("\n"));
    let width = area.width.saturating_sub(2).max(1) as usize;
    let required_inner_lines: u16 = content
        .lines()
        // Treat non-ASCII as two cells. This conservative estimate can require
        // a resize, but can never approve a clipped Unicode path.
        .map(|line| {
            line.chars()
                .map(|ch| if ch.is_ascii() { 1 } else { 2 })
                .sum::<usize>()
                .max(1)
                .div_ceil(width) as u16
        })
        .sum();
    let complete = area.width >= 18 && area.height >= required_inner_lines.saturating_add(2);
    ProposalReview {
        content,
        required_inner_lines,
        complete,
    }
}

fn render_chat_drawer(
    frame: &mut Frame,
    area: Rect,
    state: &mut UiState,
    hits: &mut ChatHitRegions,
) {
    hits.chat = Some(area);
    let proposal = state.chat.current_proposal().cloned();
    let fixed_rows = 10u16; // status, transcript floor, input, hint
    let available_review = area.height.saturating_sub(fixed_rows);
    let review = proposal.as_ref().map(|proposal| {
        proposal_review(
            Rect::new(area.x, area.y, area.width, available_review),
            proposal,
        )
    });
    state.chat.proposal_review_complete = review.as_ref().is_some_and(|review| review.complete);
    let chat = state.chat.clone();
    if area.width < 18 || area.height < 9 {
        state.chat.proposal_review_complete = false;
        frame.render_widget(
            Paragraph::new(if area.width <= 1 { "C" } else { "Chat\nResize" })
                .block(Block::default().borders(Borders::ALL).title(" CHAT ")),
            area,
        );
        return;
    }
    let proposal_height = review
        .as_ref()
        .map(|review| {
            review
                .required_inner_lines
                .saturating_add(2)
                .min(available_review)
        })
        .unwrap_or(0);
    let rows = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(4),
        Constraint::Length(proposal_height),
        Constraint::Length(3),
        Constraint::Length(1),
    ])
    .split(area);
    let focus = if chat.focus == ChatFocus::Chat {
        "FOCUSED"
    } else {
        "VIEW"
    };
    let meta = format!(
        "{focus} · {} · {} queued · {} pending",
        chat.status, chat.queued, chat.pending
    );
    frame.render_widget(
        Paragraph::new(meta)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" CHAT ")
                    .border_style(Style::default().fg(state.theme.accent)),
            )
            .style(Style::default().fg(state.theme.text)),
        rows[0],
    );
    let visible = rows[1].height.saturating_sub(2) as usize;
    let all_transcript_rows =
        transcript_rendered_rows(&chat.transcript, rows[1].width.saturating_sub(2));
    let max_scroll = all_transcript_rows.len().saturating_sub(visible);
    let scroll = state.chat.transcript_scroll.min(max_scroll);
    state.chat.transcript_scroll = scroll;
    let end = all_transcript_rows.len().saturating_sub(scroll);
    let start = end.saturating_sub(visible);
    let transcript: Vec<Line> = all_transcript_rows
        .iter()
        .skip(start)
        .take(end.saturating_sub(start))
        .map(|row| styled_transcript_row(row, &state.theme))
        .collect();
    frame.render_widget(
        Paragraph::new(transcript)
            .wrap(ratatui::widgets::Wrap { trim: true })
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" LIVE CONTEXT ")
                    .border_style(Style::default().fg(state.theme.border)),
            ),
        rows[1],
    );
    hits.transcript = Some(rows[1]);
    hits.transcript_max_scroll = max_scroll;
    if proposal_height > 0 {
        if let Some(review) = &review {
            let content = if review.complete {
                review.content.clone()
            } else {
                format!(
                    "{}\nResize to review all paths before confirming.",
                    review.content
                )
            };
            frame.render_widget(
                Paragraph::new(content)
                    .wrap(ratatui::widgets::Wrap { trim: true })
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(" PROPOSED ACTION ")
                            .border_style(Style::default().fg(state.theme.warning)),
                    )
                    .style(Style::default().fg(state.theme.text)),
                rows[2],
            );
        }
    }
    let prompt = if chat.focus == ChatFocus::Chat {
        let cursor_on =
            state.animation_index % 8 < 4 && !state.popup_open && !state.provider_popup_open;
        input_display(
            &chat.input,
            chat.cursor,
            rows[3].width.saturating_sub(4) as usize,
            cursor_on,
        )
    } else {
        "Press Tab or c to ask about this scan".to_string()
    };
    frame.render_widget(
        Paragraph::new(prompt).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" ASK ")
                .border_style(Style::default().fg(if chat.focus == ChatFocus::Chat {
                    state.theme.accent
                } else {
                    state.theme.border
                })),
        ),
        rows[3],
    );
    hits.input = Some(rows[3]);
    if proposal_height > 0 {
        let confirming = chat.is_current_confirming();
        let controls = Rect::new(
            rows[2].x.saturating_add(1),
            rows[2].bottom().saturating_sub(1),
            rows[2].width.saturating_sub(2),
            1,
        );
        const CONFIRM: &str = "[ Confirm ]";
        const REJECT: &str = "[ Reject ]";
        let controls_text = if confirming {
            "Confirming…".to_string()
        } else if state.chat.proposal_review_complete {
            format!("{CONFIRM}   {REJECT}")
        } else {
            format!("Confirm disabled   {REJECT}")
        };
        frame.render_widget(
            Paragraph::new(controls_text).style(Style::default().fg(if confirming {
                state.theme.text_dim
            } else {
                state.theme.warning
            })),
            controls,
        );
        if !confirming
            && state.chat.proposal_review_complete
            && controls.width >= cell_width(CONFIRM) as u16
        {
            hits.confirm = Some(Rect::new(
                controls.x,
                controls.y,
                cell_width(CONFIRM) as u16,
                1,
            ));
            hits.proposal_id = chat.current_proposal().map(|proposal| proposal.proposal_id);
        }
        let reject_x = controls
            .x
            .saturating_add(if state.chat.proposal_review_complete {
                (cell_width(CONFIRM) + 3) as u16
            } else {
                (cell_width("Confirm disabled") + 3) as u16
            });
        if !confirming && reject_x.saturating_add(cell_width(REJECT) as u16) <= controls.right() {
            hits.reject = Some(Rect::new(
                reject_x,
                controls.y,
                cell_width(REJECT) as u16,
                1,
            ));
            hits.proposal_id = chat.current_proposal().map(|proposal| proposal.proposal_id);
        }
    }
    let hint = chat
        .feedback
        .as_deref()
        .unwrap_or("Tab switch pane · Enter send · Esc clear/back");
    frame.render_widget(
        Paragraph::new(hint).style(Style::default().fg(state.theme.text_dim)),
        rows[4],
    );
}

fn styled_transcript_row(
    row: &RenderedTranscriptRow,
    theme: &crate::tui::theme::Theme,
) -> Line<'static> {
    let speaker_color = |speaker| match speaker {
        TranscriptSpeaker::You => theme.success,
        TranscriptSpeaker::Zentra => theme.accent,
    };
    if let TranscriptRowKind::BubbleContent {
        speaker,
        label: true,
    } = row.kind
    {
        let label = match speaker {
            TranscriptSpeaker::You => "You:",
            TranscriptSpeaker::Zentra => "Zentra:",
        };
        if let Some(at) = row.text.find(label) {
            let end = at + label.len();
            Line::from(vec![
                Span::styled(
                    row.text[..at].to_string(),
                    Style::default().fg(theme.border),
                ),
                Span::styled(
                    label.to_string(),
                    Style::default()
                        .fg(speaker_color(speaker))
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(row.text[end..].to_string(), Style::default().fg(theme.text)),
            ])
        } else {
            Line::from(Span::styled(
                row.text.clone(),
                Style::default().fg(theme.text),
            ))
        }
    } else {
        let color = match row.kind {
            TranscriptRowKind::BubbleBorder(speaker)
            | TranscriptRowKind::BubbleContent { speaker, .. } => speaker_color(speaker),
            TranscriptRowKind::Separator => theme.border,
            TranscriptRowKind::Status => theme.text_dim,
            TranscriptRowKind::Error => theme.error,
        };
        Line::from(Span::styled(row.text.clone(), Style::default().fg(color)))
    }
}

/// Render a clipped, byte-safe one-line input with a visible cursor glyph.
/// Keeping the tail nearest the edit point makes left/right editing legible on
/// small terminals without adding a separate horizontal-scroll state.
pub fn input_display(input: &str, cursor: usize, max_cells: usize, cursor_on: bool) -> String {
    let (input, cursor) = sanitize_input_display(input, cursor);
    let (before, after) = input.split_at(cursor);
    let marker = if cursor_on { "▏" } else { " " };
    let mut used = cell_width(marker);
    let mut kept = Vec::new();
    for ch in before.chars().rev() {
        let cells = if ch.is_ascii() { 1 } else { 2 };
        if used + cells > max_cells {
            break;
        }
        kept.push(ch);
        used += cells;
    }
    kept.reverse();
    let prefix: String = kept.into_iter().collect();
    let mut result = format!("> {prefix}{marker}");
    for ch in after.chars() {
        let cells = if ch.is_ascii() { 1 } else { 2 };
        if used + cells > max_cells {
            break;
        }
        result.push(ch);
        used += cells;
    }
    result
}

/// Produce a one-line terminal-safe view of raw edit state and map its UTF-8
/// cursor into that view. CSI/OSC and all C0/C1 controls are removed; ordinary
/// line breaks and tabs become a single visible space. State is untouched.
pub fn sanitize_input_display(input: &str, cursor: usize) -> (String, usize) {
    let mut raw_cursor = cursor.min(input.len());
    while raw_cursor > 0 && !input.is_char_boundary(raw_cursor) {
        raw_cursor -= 1;
    }
    let mut out = String::with_capacity(input.len());
    let mut display_cursor = 0;
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < input.len() {
        let ch = input[index..].chars().next().expect("valid boundary");
        index += ch.len_utf8();
        if ch == '\u{1b}' {
            if input[index..].starts_with('[') {
                index += 1;
                while index < input.len() {
                    let next = input[index..].chars().next().unwrap();
                    index += next.len_utf8();
                    if next.is_ascii() && ('@'..='~').contains(&next) {
                        break;
                    }
                }
            } else if input[index..].starts_with(']') {
                index += 1;
                while index < input.len() {
                    if bytes[index] == 0x07 {
                        index += 1;
                        break;
                    }
                    if bytes[index] == 0x1b && input[index + 1..].starts_with('\\') {
                        index += 2;
                        break;
                    }
                    let next = input[index..].chars().next().unwrap();
                    index += next.len_utf8();
                }
            }
        } else if ch == '\n' || ch == '\r' || ch == '\t' {
            out.push(' ');
        } else if !ch.is_control() {
            out.push(ch);
        }
        if index <= raw_cursor {
            display_cursor = out.len();
        }
    }
    let display_cursor = display_cursor.min(out.len());
    (out, display_cursor)
}

fn render_header(frame: &mut Frame, area: Rect, state: &UiState) {
    let cols = Layout::horizontal([Constraint::Min(40), Constraint::Length(22)]).split(area);

    let banner = if area.width >= 80 {
        " ____        _ \n|_  /___ _ _| |_ _ _ __ _\n / // -_) ' \\  _| '_/ _` |\n/___\\___|_||_\\__|_| \\__,_|"
    } else {
        "ZENTRA"
    };

    let pct = state.token_pct();
    let bar_width = 10usize;
    let filled = (pct as usize * bar_width / 100).min(bar_width);
    let bar = format!(
        "[{}{}] {}%",
        "█".repeat(filled),
        "░".repeat(bar_width - filled),
        pct
    );

    let mcp_badge = if state.provider_kind == "codex_cli" {
        match &state.mcp_status {
            None | Some(McpStatus::Active) => "  ◈ MCP channel active",
            Some(McpStatus::Done) => "  ✓ MCP done",
            Some(McpStatus::Disconnected) => "  ✗ disconnected",
        }
    } else {
        ""
    };

    let experimental_warning = if state.provider_kind == "codex_cli" {
        "\n⚠ Codex app-server is experimental (may change)"
    } else {
        ""
    };

    let left_text = format!(
        "{}\n{}{} · peak tok/agent: {} / {} {}  total tokens: {}{}",
        banner,
        state.model_info,
        mcp_badge,
        fmt_tokens(state.peak_input_tokens),
        fmt_tokens(state.context_window),
        bar,
        fmt_tokens(state.total_tokens),
        experimental_warning,
    );

    let left = Paragraph::new(left_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(state.theme.border))
                .style(Style::default().bg(state.theme.bg)),
        )
        .style(Style::default().fg(state.theme.accent));
    frame.render_widget(left, cols[0]);

    // Right panel: project name (green bold), branch (dark gray), version (dim)
    let project_display = state.project_name.chars().take(16).collect::<String>();
    let branch_display = state.branch.chars().take(14).collect::<String>();
    let right_content = ratatui::text::Text::from(vec![
        ratatui::text::Line::from(vec![ratatui::text::Span::styled(
            project_display,
            Style::default()
                .fg(state.theme.success)
                .add_modifier(Modifier::BOLD),
        )]),
        ratatui::text::Line::from(vec![ratatui::text::Span::styled(
            format!("⎇ {}", branch_display),
            Style::default().fg(state.theme.text_dim),
        )]),
        ratatui::text::Line::from(vec![ratatui::text::Span::styled(
            format!("v{}", env!("CARGO_PKG_VERSION")),
            Style::default().fg(state.theme.text_dim),
        )]),
    ]);
    let right = Paragraph::new(right_content)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(state.theme.border))
                .style(Style::default().bg(state.theme.bg)),
        )
        .alignment(ratatui::layout::Alignment::Right);
    frame.render_widget(right, cols[1]);
}

fn render_body(frame: &mut Frame, area: Rect, state: &mut UiState) {
    let [scanner_area, findings_area] = scan_body_chunks(area);

    render_scanners(frame, scanner_area, state);
    render_findings(frame, findings_area, state);
}

pub fn scan_body_chunks(area: Rect) -> [Rect; 2] {
    let chunks = Layout::horizontal([
        Constraint::Length(SCANNER_PANEL_WIDTH),
        Constraint::Min(FINDINGS_PANEL_MIN_WIDTH),
    ])
    .split(area);

    [chunks[0], chunks[1]]
}

pub fn failed_error_preview_width(scanner_area_width: u16) -> usize {
    scanner_area_width
        .saturating_sub(2)
        .saturating_sub(FAILED_PREVIEW_PREFIX.chars().count() as u16) as usize
}

pub fn clip_failed_error_preview(message: &str, max_chars: usize) -> String {
    let normalized = normalize_failed_error_preview(message);
    let char_count = normalized.chars().count();
    if char_count <= max_chars {
        return normalized;
    }
    if max_chars == 0 {
        return String::new();
    }
    if max_chars == 1 {
        return "…".to_string();
    }

    let mut clipped: String = normalized.chars().take(max_chars - 1).collect();
    clipped.push('…');
    clipped
}

fn normalize_failed_error_preview(message: &str) -> String {
    let mut normalized = String::with_capacity(message.len());
    let mut chars = message.chars().peekable();
    let mut last_was_space = true;

    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' {
            if matches!(chars.peek(), Some('[')) {
                chars.next();
                for ansi in chars.by_ref() {
                    if ('@'..='~').contains(&ansi) {
                        break;
                    }
                }
            }
            continue;
        }

        let next = if ch.is_control() { Some(' ') } else { Some(ch) };

        if let Some(next) = next {
            if next.is_whitespace() {
                if !last_was_space {
                    normalized.push(' ');
                    last_was_space = true;
                }
            } else {
                normalized.push(next);
                last_was_space = false;
            }
        }
    }

    normalized.trim().to_string()
}

fn render_scanners(frame: &mut Frame, area: Rect, state: &UiState) {
    use ratatui::text::Text;

    let items: Vec<ListItem> = state
        .scanners
        .iter()
        .map(|s| {
            let icon = match s.status {
                ScanStatus::Running => LOADING_FRAMES[state.animation_index % LOADING_FRAMES.len()],
                ScanStatus::Done => '✓',
                ScanStatus::Failed => '✗',
                ScanStatus::Queued | ScanStatus::Waiting => '○',
            };
            let color = match s.status {
                ScanStatus::Running => state.theme.warning,
                ScanStatus::Done => state.theme.success,
                ScanStatus::Failed => state.theme.error,
                _ => state.theme.text_dim,
            };
            // The suffix reads as "37f" for 37 files. Hidden at zero so a queued
            // scanner stays visually quiet. The panel is 34 columns and the
            // label uses 16, so this needs no layout change.
            let label = match s.files_read() {
                0 => format!("{} {:<14}", icon, s.scanner_type.label()),
                n => format!("{} {:<14}{:>4}f", icon, s.scanner_type.label(), n),
            };
            let style = Style::default().fg(color);

            // Build item — two lines for failed scanners with an error message
            let item_text = if s.status == ScanStatus::Failed {
                if let Some(ref err) = s.error {
                    let truncated =
                        clip_failed_error_preview(err, failed_error_preview_width(area.width));
                    Text::from(vec![
                        Line::from(vec![Span::styled(
                            label,
                            Style::default().fg(state.theme.error),
                        )]),
                        Line::from(vec![Span::styled(
                            format!("{}{}", FAILED_PREVIEW_PREFIX, truncated),
                            Style::default()
                                .fg(state.theme.text_dim)
                                .add_modifier(Modifier::ITALIC),
                        )]),
                    ])
                } else {
                    Text::from(Line::from(vec![Span::styled(
                        label,
                        Style::default().fg(state.theme.error),
                    )]))
                }
            } else {
                Text::from(Line::from(vec![Span::styled(label, style)]))
            };
            ListItem::new(item_text)
        })
        .collect();

    let total_crit: u32 = state.scanners.iter().map(|s| s.critical_count).sum();
    let total_high: u32 = state.scanners.iter().map(|s| s.high_count).sum();
    let total_med: u32 = state.scanners.iter().map(|s| s.medium_count).sum();
    let total_low: u32 = state.scanners.iter().map(|s| s.low_count).sum();

    let title = format!(
        "SCANNERS  {}C {}H {}M {}L",
        total_crit, total_high, total_med, total_low
    );
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(Style::default().fg(state.theme.border))
            .style(Style::default().bg(state.theme.bg)),
    );
    frame.render_widget(list, area);
}

fn render_findings(frame: &mut Frame, area: Rect, state: &mut UiState) {
    let inner_width = area.width.saturating_sub(2) as usize; // subtract left+right border
    let items: Vec<ListItem> = state
        .findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let sev_color = state.theme.severity_color(&f.severity);
            let sev = format!("{}", f.severity);
            let loc = f
                .location
                .as_deref()
                .unwrap_or("")
                .chars()
                .take(20)
                .collect::<String>();
            let fixed = 8 + 8 + loc.len(); // sev col + scanner col + loc col
            let title_width = inner_width.saturating_sub(fixed).max(10);
            let title = f.title.chars().take(title_width).collect::<String>();
            let line = Line::from(vec![
                Span::styled(
                    format!("{:<8}", sev),
                    Style::default().fg(sev_color).add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!(
                    "{:<8}",
                    f.scanner.chars().take(6).collect::<String>()
                )),
                Span::raw(format!("{:<width$}", title, width = title_width)),
                Span::styled(loc, Style::default().fg(state.theme.text_dim)),
            ]);
            let style = if i == state.selected_idx {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            ListItem::new(line).style(style)
        })
        .collect();

    let title = format!("FINDINGS — ALL ({})", state.total_findings());
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(Style::default().fg(state.theme.border))
            .style(Style::default().bg(state.theme.bg)),
    );
    let mut list_state = ListState::default();
    if !state.findings.is_empty() {
        list_state.select(Some(state.selected_idx));
    }
    frame.render_stateful_widget(list, area, &mut list_state);
}

/// Icon, colour, and label for a finished scan.
///
/// `all_done()` is true whether every scanner succeeded or every one failed, so
/// this used to read "Hacked in Ns" over an empty findings file whenever the
/// provider was down. The banner now states what happened.
pub fn completion_banner(
    outcome: ScanResult,
    elapsed_secs: u64,
    theme: &crate::tui::theme::Theme,
) -> (&'static str, ratatui::style::Color, String) {
    let duration = if elapsed_secs >= 60 {
        format!("{}m {}s", elapsed_secs / 60, elapsed_secs % 60)
    } else {
        format!("{elapsed_secs}s")
    };

    match outcome {
        ScanResult::Aborted => ("✗", theme.error, "Aborted".to_string()),
        ScanResult::AllFailed { failed } => {
            ("✗", theme.error, format!("All {failed} scanners failed"))
        }
        ScanResult::PartialFailure { failed } => (
            "⚠",
            theme.warning,
            format!("Done in {duration} · {failed} failed"),
        ),
        ScanResult::Clean => ("✓", theme.success, format!("Hacked in {duration}")),
    }
}

/// The hint shown beside the banner once the scan finishes.
pub fn completion_hint(outcome: ScanResult) -> String {
    match outcome {
        ScanResult::AllFailed { .. } => {
            "no findings were produced — check the scanner errors · q to exit".to_string()
        }
        ScanResult::PartialFailure { failed } => {
            format!("{failed} scanners produced no findings — browse the rest · q to exit")
        }
        _ => "browse findings · q to exit".to_string(),
    }
}

fn render_activity(frame: &mut Frame, area: Rect, state: &UiState) {
    let content = if state.scan_done {
        let (icon, icon_color, verb) = completion_banner(
            state.outcome(),
            state.elapsed_duration().as_secs(),
            &state.theme,
        );
        Line::from(vec![
            Span::styled(
                format!("{:<2}", icon),
                Style::default().fg(icon_color).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("{: <22}", verb),
                Style::default().fg(icon_color).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" {}", state.activity),
                Style::default()
                    .fg(state.theme.text_dim)
                    .add_modifier(Modifier::ITALIC),
            ),
        ])
    } else {
        let animation_speed = 85;
        let word_index = (state.animation_index / animation_speed) % ACTIVITY_VERBS.len();
        let current_verb = ACTIVITY_VERBS[word_index];
        let glow_color = state.theme.accent;
        Line::from(vec![
            Span::styled(
                format!(
                    "{:<2}",
                    LOADING_FRAMES[state.animation_index % LOADING_FRAMES.len()]
                ),
                Style::default()
                    .fg(state.theme.text_dim)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("{: <22}", current_verb),
                Style::default().fg(glow_color).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" {}", state.activity),
                Style::default()
                    .fg(state.theme.text_dim)
                    .add_modifier(Modifier::ITALIC),
            ),
        ])
    };
    frame.render_widget(Paragraph::new(content), area);
}

fn render_detail(frame: &mut Frame, area: Rect, state: &UiState) {
    let content = state
        .selected_finding()
        .map(|f| {
            let loc = f
                .location
                .as_deref()
                .map(|l| format!(" · {}", l))
                .unwrap_or_default();
            format!(
                "[{}] {}{}\n{}\nFIX: {}",
                f.severity, f.title, loc, f.description, f.recommendation
            )
        })
        .unwrap_or_default();

    let paragraph = Paragraph::new(content)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("DETAIL")
                .border_style(Style::default().fg(state.theme.border))
                .style(Style::default().bg(state.theme.bg).fg(state.theme.text)),
        )
        .wrap(ratatui::widgets::Wrap { trim: true });
    frame.render_widget(paragraph, area);
}

fn render_keys(
    frame: &mut Frame,
    area: Rect,
    popup_open: bool,
    scan_done: bool,
    theme: &crate::tui::theme::Theme,
    chat: Option<ChatFocus>,
) {
    let text = if popup_open {
        " ↑↓ navigate · Enter select · Esc close"
    } else if let Some(ChatFocus::Chat) = chat {
        " Chat focused · Enter send/confirm · Esc back · Tab scan"
    } else if chat.is_some() {
        " ↑↓ select finding · Tab/c focus chat · p menu · q back"
    } else if scan_done {
        " ↑↓ select finding · p menu · q back"
    } else {
        " ↑↓ navigate · p menu · q back"
    };
    let paragraph = Paragraph::new(text).style(Style::default().fg(theme.text_dim));
    frame.render_widget(paragraph, area);
}

fn render_popup(
    frame: &mut Frame,
    area: Rect,
    popup: &crate::tui::PopupState,
    scan_done: bool,
    theme: &crate::tui::theme::Theme,
) {
    let items_list = popup_items(scan_done);
    let popup_width = 46u16;
    let popup_height = (items_list.len() as u16) + 4;
    let popup_area = centered_rect(popup_width, popup_height, area);

    frame.render_widget(Clear, popup_area);

    let items: Vec<ListItem> = items_list
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let prefix = if i == popup.selected { "▶ " } else { "  " };
            let style = if i == popup.selected {
                Style::default()
                    .add_modifier(Modifier::BOLD)
                    .fg(theme.warning)
            } else {
                Style::default().fg(theme.text)
            };
            ListItem::new(format!("{}{}", prefix, label)).style(style)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title("  MENU  ")
            .title_style(Style::default().fg(theme.accent))
            .border_style(Style::default().fg(theme.border))
            .style(Style::default().bg(theme.surface)),
    );
    frame.render_widget(list, popup_area);
}

fn render_provider_popup(
    frame: &mut Frame,
    area: Rect,
    popup: &crate::tui::PopupState,
    profiles: &[String],
    theme: &crate::tui::theme::Theme,
) {
    if profiles.is_empty() {
        return;
    }
    let popup_width = 40u16;
    let popup_height = (profiles.len() as u16) + 4;
    let popup_area = centered_rect(popup_width, popup_height, area);

    frame.render_widget(Clear, popup_area);

    let items: Vec<ListItem> = profiles
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let prefix = if i == popup.selected { "▶ " } else { "  " };
            let style = if i == popup.selected {
                Style::default()
                    .add_modifier(Modifier::BOLD)
                    .fg(theme.warning)
            } else {
                Style::default().fg(theme.text)
            };
            ListItem::new(format!("{}{}", prefix, name)).style(style)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title("  SELECT PROVIDER  ")
            .title_style(Style::default().fg(theme.accent))
            .border_style(Style::default().fg(theme.border))
            .style(Style::default().bg(theme.surface)),
    );
    frame.render_widget(list, popup_area);
}

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    Rect::new(x, y, width.min(area.width), height.min(area.height))
}

/// One-line banner shown for an incremental rescan so it's never mistaken for a
/// fresh full scan. `baseline` is the full commit SHA (truncated to 8 chars).
pub fn incremental_banner(
    changed: usize,
    impacted: usize,
    carried: usize,
    baseline: &str,
) -> String {
    let short_end = baseline
        .char_indices()
        .nth(8)
        .map(|(i, _)| i)
        .unwrap_or(baseline.len());
    let short = &baseline[..short_end];
    format!(
        "Incremental rescan · baseline {short} · {changed} changed · {impacted} impacted · {carried} carried"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::ChatFocus;
    use ratatui::{backend::TestBackend, Terminal};

    fn render_for_test(state: &mut UiState, width: u16, height: u16) -> (ChatHitRegions, String) {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut hits = ChatHitRegions::default();
        terminal
            .draw(|frame| render(frame, state, true, &mut hits))
            .unwrap();
        let buffer = terminal.backend().buffer();
        let text = buffer.content.iter().map(|cell| cell.symbol()).collect();
        (hits, text)
    }

    fn test_proposal() -> ActionProposal {
        let now = chrono::Utc::now();
        ActionProposal {
            proposal_id: uuid::Uuid::new_v4(),
            request_id: uuid::Uuid::new_v4(),
            action: ChatAction::prioritize(crate::agent::chat::VulnerabilityCategory::Injection),
            created_at: now,
            expires_at: now + chrono::Duration::minutes(1),
            earliest_boundary: crate::agent::chat::PhaseBoundary::AfterParallel,
        }
    }

    #[test]
    fn fmt_tokens_abbreviates_as_expected() {
        assert_eq!(fmt_tokens(0), "0");
        assert_eq!(fmt_tokens(999), "999");
        assert_eq!(fmt_tokens(1_000), "1k");
        assert_eq!(fmt_tokens(12_900), "12.9k");
        assert_eq!(fmt_tokens(13_000), "13k");
        assert_eq!(fmt_tokens(200_000), "200k");
        assert_eq!(fmt_tokens(12_500_000), "12.5M");
        assert_eq!(fmt_tokens(13_000_000), "13M");
    }

    #[test]
    fn chat_focus_width_and_c_key_are_deliberate() {
        assert!(!chat_uses_primary_pane(
            CHAT_NARROW_WIDTH - 1,
            ChatFocus::Scan
        ));
        assert!(chat_uses_primary_pane(
            CHAT_NARROW_WIDTH - 1,
            ChatFocus::Chat
        ));
        assert!(!chat_uses_primary_pane(CHAT_NARROW_WIDTH, ChatFocus::Scan));
        let mut state = UiState::new(
            vec![],
            "m".into(),
            1,
            vec![],
            String::new(),
            String::new(),
            String::new(),
        );
        let (tx, _command_rx) = mpsc::channel(1);
        let (_event_tx, rx) = mpsc::channel(1);
        let mut channels = ChatUiChannels {
            command_tx: tx,
            event_rx: rx,
        };
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        assert!(handle_chat_key(
            &mut state,
            key(KeyCode::Char('c')),
            Some(&mut channels)
        ));
        assert_eq!(state.chat.focus, ChatFocus::Chat);
        handle_chat_key(&mut state, key(KeyCode::Char('c')), Some(&mut channels));
        assert_eq!(state.chat.focus, ChatFocus::Chat);
        handle_chat_key(&mut state, key(KeyCode::Char('c')), Some(&mut channels));
        assert_eq!(state.chat.focus, ChatFocus::Chat);
    }

    #[test]
    fn chat_width_is_near_half_with_a_scan_safe_cap() {
        assert_eq!(chat_pane_width(120), 58);
        assert_eq!(chat_pane_width(180), 68);
        assert!(chat_pane_width(100) <= 58);
    }

    #[test]
    fn bubbles_separate_messages_but_status_stays_a_compact_row() {
        let mut state = UiState::new(
            vec![],
            "m".into(),
            1,
            vec![],
            String::new(),
            String::new(),
            String::new(),
        );
        state.chat.push("You", "question".into());
        state.chat.push("Zentra", "answer".into());
        state.chat.advance_answer_reveal();
        state.chat.push("Status", "queued".into());
        let rows = transcript_rows(&state.chat.transcript, 36);
        assert!(rows.iter().any(|row| row.contains("╭")));
        assert!(rows.iter().any(|row| row.contains("You:")));
        assert!(rows.iter().any(|row| row.contains("Zentra:")));
        assert!(rows.iter().any(|row| row.starts_with('┄')));
        assert!(rows.iter().any(|row| row.starts_with("· Status:")));
    }

    #[test]
    fn answer_reveal_is_utf8_safe_and_long_answers_finish_quickly() {
        let mut state = UiState::new(
            vec![],
            "m".into(),
            1,
            vec![],
            String::new(),
            String::new(),
            String::new(),
        );
        state.chat.push("Zentra", "é界".repeat(300));
        for _ in 0..20 {
            state.chat.advance_answer_reveal();
        }
        let entry = state.chat.transcript.back().unwrap();
        assert_eq!(entry.revealed_chars, Some(entry.text.chars().count()));
        let visible: String = entry
            .text
            .chars()
            .take(entry.revealed_chars.unwrap())
            .collect();
        assert!(visible.is_char_boundary(visible.len()));
    }

    #[test]
    fn focused_input_has_a_blinking_cursor_and_unfocused_input_does_not() {
        assert!(input_display("é", "é".len(), 12, true).contains('▏'));
        assert!(!input_display("é", "é".len(), 12, false).contains('▏'));
    }

    #[test]
    fn input_display_strips_terminal_sequences_and_maps_utf8_cursor() {
        let raw = "é\u{1b}[31m\t界\u{1b}]title\u{7}x\n";
        let cursor = raw.find('界').unwrap() + '界'.len_utf8();
        let (safe, mapped) = sanitize_input_display(raw, cursor);
        assert_eq!(safe, "é 界x ");
        assert!(safe.is_char_boundary(mapped));
        assert_eq!(&safe[..mapped], "é 界");
        assert!(!input_display(raw, cursor, 30, true).contains('\u{1b}'));
    }

    #[test]
    fn test_backend_never_receives_raw_input_controls_or_modal_cursor() {
        let mut state = UiState::new(
            vec![],
            "m".into(),
            1,
            vec![],
            String::new(),
            String::new(),
            String::new(),
        );
        state.chat.focus = ChatFocus::Chat;
        state.chat.input = "ok\u{1b}[31m\nnext".into();
        state.chat.cursor = state.chat.input.len();
        state.animation_index = 0;
        let (_, visible) = render_for_test(&mut state, 120, 28);
        assert!(!visible.contains('\u{1b}'));
        assert!(visible.contains("ok next"));
        assert!(visible.contains('▏'));
        state.popup_open = true;
        let (_, modal) = render_for_test(&mut state, 120, 28);
        assert!(!modal.contains('▏'));
    }

    #[test]
    fn bubble_rows_are_exactly_viewport_width_and_keep_blank_lines() {
        let mut state = UiState::new(
            vec![],
            "m".into(),
            1,
            vec![],
            String::new(),
            String::new(),
            String::new(),
        );
        state.chat.push("You", "one\n\ntwo ".repeat(12));
        state.chat.push("Zentra", "reply ".repeat(24));
        state.chat.advance_answer_reveal();
        let rows = transcript_rendered_rows(&state.chat.transcript, 24);
        assert!(rows.iter().all(|row| cell_width(&row.text) <= 24));
        assert!(rows
            .iter()
            .any(|row| matches!(row.kind, TranscriptRowKind::Separator)));
        assert!(
            rows.iter()
                .filter(|row| matches!(row.kind, TranscriptRowKind::BubbleContent { .. }))
                .count()
                > 4
        );
    }

    #[test]
    fn speaker_style_metadata_is_not_confused_by_message_text() {
        let mut state = UiState::new(
            vec![],
            "m".into(),
            1,
            vec![],
            String::new(),
            String::new(),
            String::new(),
        );
        state.chat.push("You", "Zentra: quoted".into());
        state.chat.push("Zentra", "You: quoted".into());
        state.chat.advance_answer_reveal();
        let rows = transcript_rendered_rows(&state.chat.transcript, 36);
        let speakers: Vec<_> = rows
            .iter()
            .filter_map(|row| match row.kind {
                TranscriptRowKind::BubbleContent {
                    speaker,
                    label: true,
                } => Some(speaker),
                _ => None,
            })
            .collect();
        assert_eq!(
            speakers,
            vec![TranscriptSpeaker::You, TranscriptSpeaker::Zentra]
        );
    }

    #[test]
    fn long_wrapped_bubbles_render_one_label_and_safe_continuations() {
        for (speaker, label) in [("You", "You:"), ("Zentra", "Zentra:")] {
            let mut state = UiState::new(
                vec![],
                "m".into(),
                1,
                vec![],
                String::new(),
                String::new(),
                String::new(),
            );
            state.chat.push(speaker, "wrapped content ".repeat(40));
            while state.chat.advance_answer_reveal() {}
            let rows = transcript_rendered_rows(&state.chat.transcript, 26);
            assert_eq!(
                rows.iter()
                    .filter(|row| matches!(
                        row.kind,
                        TranscriptRowKind::BubbleContent { label: true, .. }
                    ))
                    .count(),
                1,
                "{speaker} label count"
            );
            assert!(rows.iter().all(|row| cell_width(&row.text) <= 26));
            assert!(rows.iter().any(|row| row.text.contains('╭')));
            assert!(rows.iter().any(|row| row.text.contains('╰')));
            assert!(
                rows.iter()
                    .filter(|row| matches!(row.kind, TranscriptRowKind::BubbleContent { .. }))
                    .count()
                    > 2
            );
            state.chat.transcript_scroll = usize::MAX;
            let (_, buffer) = render_for_test(&mut state, 120, 32);
            assert_eq!(
                buffer.matches(label).count(),
                1,
                "{speaker} rendered label count"
            );
            assert!(buffer.contains('│'));
        }
    }

    #[test]
    fn full_command_channel_is_local_feedback_not_a_block() {
        let mut state = UiState::new(
            vec![],
            "m".into(),
            1,
            vec![],
            String::new(),
            String::new(),
            String::new(),
        );
        state.chat.focus = ChatFocus::Chat;
        state.chat.insert_text("question");
        let (tx, _command_rx) = mpsc::channel(1);
        let (_event_tx, rx) = mpsc::channel(1);
        tx.try_send(ChatCommand::Close).unwrap();
        let mut channels = ChatUiChannels {
            command_tx: tx,
            event_rx: rx,
        };
        assert!(handle_chat_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            Some(&mut channels)
        ));
        assert_eq!(state.chat.input, "question");
        assert!(state.chat.feedback.as_deref().unwrap().contains("busy"));
    }

    #[test]
    fn escape_rejects_then_clears_then_returns_to_scan_focus() {
        use crate::agent::chat::{
            ActionProposal, ChatAction, PhaseBoundary, VulnerabilityCategory,
        };
        let mut state = UiState::new(
            vec![],
            "m".into(),
            1,
            vec![],
            String::new(),
            String::new(),
            String::new(),
        );
        state.chat.focus = ChatFocus::Chat;
        let now = chrono::Utc::now();
        let proposal = ActionProposal {
            proposal_id: uuid::Uuid::new_v4(),
            request_id: uuid::Uuid::new_v4(),
            action: ChatAction::prioritize(VulnerabilityCategory::Injection),
            created_at: now,
            expires_at: now + chrono::Duration::minutes(1),
            earliest_boundary: PhaseBoundary::AfterParallel,
        };
        let proposal_id = proposal.proposal_id;
        state.chat.proposals.push_back(proposal);
        let (tx, mut command_rx) = mpsc::channel(2);
        let (_event_tx, event_rx) = mpsc::channel(1);
        let mut channels = ChatUiChannels {
            command_tx: tx,
            event_rx,
        };
        let esc = KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE);
        assert!(handle_chat_key(&mut state, esc, Some(&mut channels)));
        assert!(
            matches!(command_rx.try_recv(), Ok(ChatCommand::Reject { proposal_id: id }) if id == proposal_id)
        );
        state.chat.insert_text("draft");
        assert!(handle_chat_key(&mut state, esc, Some(&mut channels)));
        assert!(state.chat.input.is_empty());
        assert!(handle_chat_key(&mut state, esc, Some(&mut channels)));
        assert_eq!(state.chat.focus, ChatFocus::Scan);
    }

    #[test]
    fn ctrl_c_falls_through_without_closing_chat() {
        let mut state = UiState::new(
            vec![],
            "m".into(),
            1,
            vec![],
            String::new(),
            String::new(),
            String::new(),
        );
        let (tx, mut command_rx) = mpsc::channel(1);
        let (_event_tx, event_rx) = mpsc::channel(1);
        let mut channels = ChatUiChannels {
            command_tx: tx,
            event_rx,
        };
        assert!(!handle_chat_key(
            &mut state,
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
            Some(&mut channels)
        ));
        assert!(command_rx.try_recv().is_err());
    }

    #[test]
    fn completed_navigation_is_not_an_abort_but_active_navigation_is() {
        let mut state = UiState::new(
            vec![],
            "m".into(),
            1,
            vec![],
            String::new(),
            String::new(),
            String::new(),
        );
        assert_eq!(exit_outcome(&state), ScanOutcome::Aborted);
        state.mark_complete();
        assert_eq!(exit_outcome(&state), ScanOutcome::Completed);
        state.abort_scan(); // completion is immutable, so retain the natural result.
        assert_eq!(exit_outcome(&state), ScanOutcome::Completed);
    }

    #[test]
    fn enter_does_not_confirm_a_proposal_while_scan_is_focused() {
        use crate::agent::chat::{
            ActionProposal, ChatAction, PhaseBoundary, VulnerabilityCategory,
        };
        let mut state = UiState::new(
            vec![],
            "m".into(),
            1,
            vec![],
            String::new(),
            String::new(),
            String::new(),
        );
        state.chat.focus = ChatFocus::Scan;
        let now = chrono::Utc::now();
        state.chat.proposals.push_back(ActionProposal {
            proposal_id: uuid::Uuid::new_v4(),
            request_id: uuid::Uuid::new_v4(),
            action: ChatAction::prioritize(VulnerabilityCategory::Injection),
            created_at: now,
            expires_at: now + chrono::Duration::minutes(1),
            earliest_boundary: PhaseBoundary::AfterParallel,
        });
        let (tx, mut command_rx) = mpsc::channel(1);
        let (_event_tx, event_rx) = mpsc::channel(1);
        let mut channels = ChatUiChannels {
            command_tx: tx,
            event_rx,
        };
        assert!(!handle_chat_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            Some(&mut channels)
        ));
        assert!(command_rx.try_recv().is_err());
        assert_eq!(state.chat.proposals.len(), 1);
    }

    #[test]
    fn confirm_send_keeps_head_and_suppresses_duplicates_until_acknowledged() {
        use crate::agent::chat::{
            ActionProposal, ChatAction, PhaseBoundary, VulnerabilityCategory,
        };
        let mut state = UiState::new(
            vec![],
            "m".into(),
            1,
            vec![],
            String::new(),
            String::new(),
            String::new(),
        );
        state.chat.focus = ChatFocus::Chat;
        state.chat.proposal_review_complete = true;
        let now = chrono::Utc::now();
        let proposal = ActionProposal {
            proposal_id: uuid::Uuid::new_v4(),
            request_id: uuid::Uuid::new_v4(),
            action: ChatAction::prioritize(VulnerabilityCategory::Injection),
            created_at: now,
            expires_at: now + chrono::Duration::minutes(1),
            earliest_boundary: PhaseBoundary::AfterParallel,
        };
        let proposal_id = proposal.proposal_id;
        state.chat.proposals.push_back(proposal);
        let (tx, mut command_rx) = mpsc::channel(2);
        let (_event_tx, event_rx) = mpsc::channel(1);
        let mut channels = ChatUiChannels {
            command_tx: tx,
            event_rx,
        };
        let enter = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
        assert!(handle_chat_key(&mut state, enter, Some(&mut channels)));
        assert!(
            matches!(command_rx.try_recv(), Ok(ChatCommand::Confirm { proposal_id: id }) if id == proposal_id)
        );
        assert_eq!(
            state.chat.current_proposal().unwrap().proposal_id,
            proposal_id
        );
        assert!(state.chat.is_current_confirming());
        assert!(handle_chat_key(
            &mut state,
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
            Some(&mut channels)
        ));
        assert_eq!(
            state.chat.current_proposal().unwrap().proposal_id,
            proposal_id
        );
        assert_eq!(state.chat.status, "Confirmation in progress");
        assert!(command_rx.try_recv().is_err());
        assert!(handle_chat_key(&mut state, enter, Some(&mut channels)));
        assert!(command_rx.try_recv().is_err());
    }

    #[test]
    fn proposal_review_requires_full_bounded_content_and_shift_types_input() {
        use crate::agent::chat::{ActionProposal, ChatAction, FocusScope, PhaseBoundary};
        let scope = FocusScope::from_paths(
            [],
            [
                "src/very/long/path/one.rs".into(),
                "src/very/long/path/two.rs".into(),
                "src/very/long/path/three.rs".into(),
            ],
        )
        .unwrap();
        let now = chrono::Utc::now();
        let proposal = ActionProposal {
            proposal_id: uuid::Uuid::new_v4(),
            request_id: uuid::Uuid::new_v4(),
            action: ChatAction::focus_and_rerun([ScannerType::Sast], scope).unwrap(),
            created_at: now,
            expires_at: now + chrono::Duration::minutes(1),
            earliest_boundary: PhaseBoundary::AfterParallel,
        };
        assert!(!proposal_review(Rect::new(0, 0, 18, 4), &proposal).complete);
        assert!(proposal_review(Rect::new(0, 0, 80, 30), &proposal).complete);
        let mut state = UiState::new(
            vec![],
            "m".into(),
            1,
            vec![],
            String::new(),
            String::new(),
            String::new(),
        );
        state.chat.focus = ChatFocus::Chat;
        let (tx, _command_rx) = mpsc::channel(1);
        let (_event_tx, event_rx) = mpsc::channel(1);
        let mut channels = ChatUiChannels {
            command_tx: tx,
            event_rx,
        };
        assert!(handle_chat_key(
            &mut state,
            KeyEvent::new(KeyCode::Char('?'), KeyModifiers::SHIFT),
            Some(&mut channels)
        ));
        assert!(handle_chat_key(
            &mut state,
            KeyEvent::new(KeyCode::Char('C'), KeyModifiers::SHIFT),
            Some(&mut channels)
        ));
        assert_eq!(state.chat.input, "?C");
    }

    #[test]
    fn ctrl_c_global_route_precedes_both_popup_states() {
        let ctrl_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(is_global_abort_key(ctrl_c));
        // The loop checks this predicate before either provider or scan popup.
        for (provider_popup, scan_popup) in [(true, false), (false, true)] {
            assert!(provider_popup || scan_popup);
            assert!(is_global_abort_key(ctrl_c));
        }
    }

    #[test]
    fn drain_chat_events_is_nonblocking_and_keeps_terminal_arrival_order() {
        let mut state = UiState::new(
            vec![],
            "m".into(),
            1,
            vec![],
            String::new(),
            String::new(),
            String::new(),
        );
        let (tx, mut rx) = mpsc::channel(3);
        let first = uuid::Uuid::new_v4();
        let second = uuid::Uuid::new_v4();
        tx.try_send(ChatEvent::Answer {
            request_id: first,
            text: "first".into(),
        })
        .unwrap();
        tx.try_send(ChatEvent::Answer {
            request_id: second,
            text: "second".into(),
        })
        .unwrap();
        drain_chat_events(&mut state, &mut rx);
        let text: Vec<_> = state
            .chat
            .transcript
            .iter()
            .map(|entry| entry.text.as_str())
            .collect();
        assert_eq!(text, vec!["first", "second"]);
        drain_chat_events(&mut state, &mut rx); // empty is a safe no-op
    }

    #[test]
    fn tab_and_escape_switch_focus_without_hiding_chat_or_leaking_typing() {
        let mut state = UiState::new(
            vec![],
            "m".into(),
            1,
            vec![],
            String::new(),
            String::new(),
            String::new(),
        );
        let (tx, _commands) = mpsc::channel(1);
        let (_events, event_rx) = mpsc::channel(1);
        let mut channels = ChatUiChannels {
            command_tx: tx,
            event_rx,
        };
        assert!(handle_chat_key(
            &mut state,
            KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE),
            Some(&mut channels)
        ));
        assert_eq!(state.chat.focus, ChatFocus::Chat);
        assert!(handle_chat_key(
            &mut state,
            KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
            Some(&mut channels)
        ));
        assert_eq!(state.chat.input, "q");
        assert!(handle_chat_key(
            &mut state,
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
            Some(&mut channels)
        ));
        assert_eq!(state.chat.focus, ChatFocus::Chat);
        assert!(state.chat.input.is_empty());
        assert!(handle_chat_key(
            &mut state,
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
            Some(&mut channels)
        ));
        assert_eq!(state.chat.focus, ChatFocus::Scan);
    }

    #[test]
    fn mouse_focus_and_wheel_use_only_fresh_regions() {
        let mut state = UiState::new(
            vec![],
            "m".into(),
            1,
            vec![],
            String::new(),
            String::new(),
            String::new(),
        );
        state.chat.push("You", "one".into());
        state.chat.push("Zentra", "two".into());
        let (tx, _commands) = mpsc::channel(1);
        let (_events, event_rx) = mpsc::channel(1);
        let mut channels = ChatUiChannels {
            command_tx: tx,
            event_rx,
        };
        let mut hits = ChatHitRegions {
            scan: Some(Rect::new(0, 0, 10, 10)),
            chat: Some(Rect::new(12, 0, 10, 10)),
            input: Some(Rect::new(12, 7, 10, 2)),
            transcript: Some(Rect::new(12, 2, 10, 4)),
            layout_valid: true,
            transcript_max_scroll: 1,
            ..Default::default()
        };
        let click = |column, row| MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column,
            row,
            modifiers: KeyModifiers::NONE,
        };
        assert!(handle_chat_mouse(
            &mut state,
            click(13, 8),
            &mut hits,
            &mut channels
        ));
        assert_eq!(state.chat.focus, ChatFocus::Chat);
        let wheel = MouseEvent {
            kind: MouseEventKind::ScrollUp,
            column: 13,
            row: 3,
            modifiers: KeyModifiers::NONE,
        };
        assert!(handle_chat_mouse(
            &mut state,
            wheel,
            &mut hits,
            &mut channels
        ));
        assert_eq!(state.chat.transcript_scroll, 1);
        assert!(!handle_chat_mouse(
            &mut state,
            click(99, 99),
            &mut ChatHitRegions::default(),
            &mut channels
        ));
    }

    #[test]
    fn mouse_proposal_controls_obey_review_and_confirming_guards() {
        use crate::agent::chat::{PhaseBoundary, VulnerabilityCategory};
        let mut state = UiState::new(
            vec![],
            "m".into(),
            1,
            vec![],
            String::new(),
            String::new(),
            String::new(),
        );
        let now = chrono::Utc::now();
        let proposal = ActionProposal {
            proposal_id: uuid::Uuid::new_v4(),
            request_id: uuid::Uuid::new_v4(),
            action: ChatAction::prioritize(VulnerabilityCategory::Injection),
            created_at: now,
            expires_at: now + chrono::Duration::minutes(1),
            earliest_boundary: PhaseBoundary::AfterParallel,
        };
        let id = proposal.proposal_id;
        state.chat.proposals.push_back(proposal);
        let (tx, mut commands) = mpsc::channel(2);
        let (_events, event_rx) = mpsc::channel(1);
        let mut channels = ChatUiChannels {
            command_tx: tx,
            event_rx,
        };
        let mut hits = ChatHitRegions {
            confirm: Some(Rect::new(1, 1, 4, 1)),
            reject: Some(Rect::new(6, 1, 4, 1)),
            layout_valid: true,
            proposal_id: Some(id),
            ..Default::default()
        };
        let click = |column| MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column,
            row: 1,
            modifiers: KeyModifiers::NONE,
        };
        handle_chat_mouse(&mut state, click(2), &mut hits, &mut channels);
        assert!(commands.try_recv().is_err()); // clipped review cannot confirm
        state.chat.proposal_review_complete = true;
        handle_chat_mouse(&mut state, click(2), &mut hits, &mut channels);
        assert!(
            matches!(commands.try_recv(), Ok(ChatCommand::Confirm { proposal_id }) if proposal_id == id)
        );
        handle_chat_mouse(&mut state, click(7), &mut hits, &mut channels);
        assert!(commands.try_recv().is_err()); // confirming also disables reject
    }

    #[test]
    fn rendered_controls_have_exact_non_overlapping_cell_hitboxes() {
        let mut base = UiState::new(
            vec![],
            "m".into(),
            1,
            vec![],
            String::new(),
            String::new(),
            String::new(),
        );
        base.chat.focus = ChatFocus::Chat;
        base.chat.proposals.push_back(test_proposal());
        let (hits, buffer) = render_for_test(&mut base, 140, 32);
        let confirm = hits.confirm.expect("complete review renders Confirm");
        let reject = hits.reject.expect("Reject is rendered");
        let proposal = base.chat.current_proposal().unwrap().clone();
        assert!(buffer.contains("[ Confirm ]") && buffer.contains("[ Reject ]"));
        assert!(confirm.right() <= reject.x);
        for x in confirm.x..confirm.right() {
            let mut state = UiState::new(
                vec![],
                "m".into(),
                1,
                vec![],
                String::new(),
                String::new(),
                String::new(),
            );
            state.chat.focus = ChatFocus::Chat;
            state.chat.proposals.push_back(proposal.clone());
            state.chat.proposal_review_complete = true;
            let (tx, mut commands) = mpsc::channel(1);
            let (_events, event_rx) = mpsc::channel(1);
            let mut channels = ChatUiChannels {
                command_tx: tx,
                event_rx,
            };
            let mut click_hits = hits;
            handle_chat_mouse(
                &mut state,
                MouseEvent {
                    kind: MouseEventKind::Down(MouseButton::Left),
                    column: x,
                    row: confirm.y,
                    modifiers: KeyModifiers::NONE,
                },
                &mut click_hits,
                &mut channels,
            );
            assert!(
                matches!(commands.try_recv(), Ok(ChatCommand::Confirm { .. })),
                "confirm cell {x}"
            );
        }
        for x in reject.x..reject.right() {
            let mut state = UiState::new(
                vec![],
                "m".into(),
                1,
                vec![],
                String::new(),
                String::new(),
                String::new(),
            );
            state.chat.focus = ChatFocus::Chat;
            state.chat.proposals.push_back(proposal.clone());
            state.chat.proposal_review_complete = true;
            let (tx, mut commands) = mpsc::channel(1);
            let (_events, event_rx) = mpsc::channel(1);
            let mut channels = ChatUiChannels {
                command_tx: tx,
                event_rx,
            };
            let mut click_hits = hits;
            handle_chat_mouse(
                &mut state,
                MouseEvent {
                    kind: MouseEventKind::Down(MouseButton::Left),
                    column: x,
                    row: reject.y,
                    modifiers: KeyModifiers::NONE,
                },
                &mut click_hits,
                &mut channels,
            );
            assert!(
                matches!(commands.try_recv(), Ok(ChatCommand::Reject { .. })),
                "reject cell {x}"
            );
        }
    }

    #[test]
    fn render_keeps_chat_visible_and_hit_regions_fresh_at_tiny_sizes() {
        for width in 1..=60 {
            let mut state = UiState::new(
                vec![],
                "m".into(),
                1,
                vec![],
                String::new(),
                String::new(),
                String::new(),
            );
            let (hits, buffer) = render_for_test(&mut state, width, 18);
            assert!(hits.chat.is_some(), "chat rail at width {width}");
            assert!(!buffer.trim().is_empty());
        }
        let mut state = UiState::new(
            vec![],
            "m".into(),
            1,
            vec![],
            String::new(),
            String::new(),
            String::new(),
        );
        state.chat.proposals.push_back(test_proposal());
        let (wide, _) = render_for_test(&mut state, 140, 32);
        assert!(wide.confirm.is_some());
        let (tiny, _) = render_for_test(&mut state, 8, 8);
        assert!(tiny.confirm.is_none() && tiny.reject.is_none() && tiny.input.is_none());
    }

    #[test]
    fn rendered_transcript_wraps_by_rows_and_wheel_clamps_to_viewport() {
        let mut state = UiState::new(
            vec![],
            "m".into(),
            1,
            vec![],
            String::new(),
            String::new(),
            String::new(),
        );
        state.chat.push(
            "You",
            "a very long answer that must wrap across rendered rows ".repeat(8),
        );
        state.chat.push(
            "Zentra",
            "another long reply that must also wrap across the viewport ".repeat(8),
        );
        let rows = transcript_rows(&state.chat.transcript, 12);
        assert!(rows.len() > 2);
        let (mut hits, buffer) = render_for_test(&mut state, 110, 18);
        assert!(hits.transcript_max_scroll > 0);
        assert!(buffer.contains("LIVE CONTEXT"));
        let (tx, _commands) = mpsc::channel(1);
        let (_events, event_rx) = mpsc::channel(1);
        let mut channels = ChatUiChannels {
            command_tx: tx,
            event_rx,
        };
        let area = hits.transcript.unwrap();
        for _ in 0..100 {
            handle_chat_mouse(
                &mut state,
                MouseEvent {
                    kind: MouseEventKind::ScrollUp,
                    column: area.x,
                    row: area.y,
                    modifiers: KeyModifiers::NONE,
                },
                &mut hits,
                &mut channels,
            );
        }
        assert_eq!(state.chat.transcript_scroll, hits.transcript_max_scroll);
    }

    #[test]
    fn test_backend_renders_sender_labels_and_permanent_chat_title() {
        let mut state = UiState::new(
            vec![],
            "m".into(),
            1,
            vec![],
            String::new(),
            String::new(),
            String::new(),
        );
        state.chat.push("You", "question".into());
        state.chat.push("Zentra", "answer".into());
        state.chat.push("Status", "queued".into());
        let (hits, buffer) = render_for_test(&mut state, 140, 32);
        assert!(hits.chat.is_some() && buffer.contains("CHAT"));
        assert!(buffer.contains("You") && buffer.contains("Zentra") && buffer.contains("Status"));
    }

    #[test]
    fn resize_invalidation_blocks_stale_confirmation_and_c_types_in_chat() {
        let mut state = UiState::new(
            vec![],
            "m".into(),
            1,
            vec![],
            String::new(),
            String::new(),
            String::new(),
        );
        state.chat.focus = ChatFocus::Chat;
        state.chat.proposals.push_back(test_proposal());
        let (mut hits, _) = render_for_test(&mut state, 140, 32);
        assert!(state.chat.proposal_review_complete && hits.confirm.is_some());
        invalidate_chat_layout(&mut state, &mut hits);
        let (tx, mut commands) = mpsc::channel(1);
        let (_events, event_rx) = mpsc::channel(1);
        let mut channels = ChatUiChannels {
            command_tx: tx,
            event_rx,
        };
        assert!(handle_chat_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            Some(&mut channels)
        ));
        assert!(commands.try_recv().is_err());
        assert!(!handle_chat_mouse(
            &mut state,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: 1,
                row: 1,
                modifiers: KeyModifiers::NONE
            },
            &mut hits,
            &mut channels
        ));
        assert!(handle_chat_key(
            &mut state,
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE),
            Some(&mut channels)
        ));
        assert_eq!(state.chat.input, "c");
    }

    #[test]
    fn reject_double_click_cannot_touch_promoted_fifo_proposal() {
        let mut state = UiState::new(
            vec![],
            "m".into(),
            1,
            vec![],
            String::new(),
            String::new(),
            String::new(),
        );
        state.chat.focus = ChatFocus::Chat;
        let first = test_proposal();
        let first_id = first.proposal_id;
        let second = test_proposal();
        let second_id = second.proposal_id;
        state.chat.proposals.push_back(first);
        state.chat.proposals.push_back(second);
        let (mut hits, _) = render_for_test(&mut state, 140, 32);
        let reject = hits.reject.unwrap();
        let (tx, mut commands) = mpsc::channel(2);
        let (_events, event_rx) = mpsc::channel(1);
        let mut channels = ChatUiChannels {
            command_tx: tx,
            event_rx,
        };
        let click = || MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: reject.x,
            row: reject.y,
            modifiers: KeyModifiers::NONE,
        };
        assert!(handle_chat_mouse(
            &mut state,
            click(),
            &mut hits,
            &mut channels
        ));
        assert!(
            matches!(commands.try_recv(), Ok(ChatCommand::Reject { proposal_id }) if proposal_id == first_id)
        );
        assert_eq!(
            state.chat.current_proposal().unwrap().proposal_id,
            second_id
        );
        assert!(!handle_chat_mouse(
            &mut state,
            click(),
            &mut hits,
            &mut channels
        ));
        assert!(commands.try_recv().is_err());
        assert_eq!(
            state.chat.current_proposal().unwrap().proposal_id,
            second_id
        );
    }

    #[test]
    fn viewport_growth_persists_scroll_clamp_before_scroll_down() {
        let mut state = UiState::new(
            vec![],
            "m".into(),
            1,
            vec![],
            String::new(),
            String::new(),
            String::new(),
        );
        state
            .chat
            .push("Zentra", "wrapped transcript row ".repeat(30));
        state.chat.focus = ChatFocus::Chat;
        let (mut small, _) = render_for_test(&mut state, 80, 24);
        let area = small.transcript.unwrap();
        let (tx, _commands) = mpsc::channel(1);
        let (_events, event_rx) = mpsc::channel(1);
        let mut channels = ChatUiChannels {
            command_tx: tx,
            event_rx,
        };
        for _ in 0..100 {
            let _ = handle_chat_mouse(
                &mut state,
                MouseEvent {
                    kind: MouseEventKind::ScrollUp,
                    column: area.x,
                    row: area.y,
                    modifiers: KeyModifiers::NONE,
                },
                &mut small,
                &mut channels,
            );
        }
        let old = state.chat.transcript_scroll;
        let (mut grown, _) = render_for_test(&mut state, 140, 40);
        assert!(state.chat.transcript_scroll <= grown.transcript_max_scroll);
        assert!(state.chat.transcript_scroll <= old);
        let grown_area = grown.transcript.unwrap();
        let before = state.chat.transcript_scroll;
        let _ = handle_chat_mouse(
            &mut state,
            MouseEvent {
                kind: MouseEventKind::ScrollDown,
                column: grown_area.x,
                row: grown_area.y,
                modifiers: KeyModifiers::NONE,
            },
            &mut grown,
            &mut channels,
        );
        assert_eq!(state.chat.transcript_scroll, before.saturating_sub(1));
    }

    #[test]
    fn tiny_width_popups_render_after_compact_chat_layout() {
        for provider in [false, true] {
            let mut state = UiState::new(
                vec![],
                "m".into(),
                1,
                vec!["profile".into()],
                String::new(),
                String::new(),
                String::new(),
            );
            if provider {
                state.provider_popup_open = true;
            } else {
                state.popup_open = true;
            }
            state.chat.proposal_review_complete = true;
            let (hits, buffer) = render_for_test(&mut state, 20, 18);
            assert!(!hits.layout_valid && hits.chat.is_none());
            assert!(!state.chat.proposal_review_complete);
            assert!(!buffer.trim().is_empty());
        }
    }
}
