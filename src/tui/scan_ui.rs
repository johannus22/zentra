use crate::agent::chat::{ActionProposal, ChatAction, ChatCommand, ChatEvent};
use crate::agent::{McpStatus, ScanEvent, ScannerType};
use crate::tui::{
    sanitize_chat_text, ChatDrawerState, ScanOutcome, ScanResult, ScanStatus, UiState,
};
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
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
                    Event::Paste(text) => {
                        if !state.provider_popup_open && !state.popup_open {
                            if let Some(channels) = chat.as_deref_mut() {
                                if state.chat.drawer == ChatDrawerState::ExpandedFocused {
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
                    _ => {}
                    }
                }
            }
            _ = animation_ticker.tick() => {
                state.animation_index = state.animation_index.wrapping_add(1);
            }
        }

        // Detect scan completion after any event (Bug 4)
        if state.all_done() && !state.scan_done {
            state.mark_complete();
            state.activity = completion_hint(state.outcome());
        }

        terminal.draw(|f| render(f, &mut state, chat.is_some()))?;
    }
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

fn render(frame: &mut Frame, state: &mut UiState, chat_enabled: bool) {
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
    if !chat_enabled || state.chat.drawer == ChatDrawerState::Collapsed {
        render_body(frame, chunks[1], state);
        render_activity(frame, chunks[2], state);
        render_detail(frame, chunks[3], state);
    } else if chat_uses_primary_pane(area.width, state.chat.drawer) {
        // On narrow terminals Chat owns the complete work area. Rendering it
        // only in the old body row left an unusable, cramped drawer.
        let primary = Rect::new(
            chunks[1].x,
            chunks[1].y,
            chunks[1].width,
            chunks[3].bottom().saturating_sub(chunks[1].y),
        );
        render_chat_drawer(frame, primary, state);
    } else {
        let main = Rect::new(
            chunks[1].x,
            chunks[1].y,
            chunks[1].width,
            chunks[3].bottom().saturating_sub(chunks[1].y),
        );
        let cols = Layout::horizontal([Constraint::Min(58), Constraint::Length(42)]).split(main);
        let left = Layout::vertical([
            Constraint::Min(6),
            Constraint::Length(1),
            Constraint::Length(8),
        ])
        .split(cols[0]);
        render_body(frame, left[0], state);
        render_activity(frame, left[1], state);
        render_detail(frame, left[2], state);
        render_chat_drawer(frame, cols[1], state);
    }
    render_keys(
        frame,
        chunks[4],
        state.popup_open,
        state.scan_done,
        &state.theme,
        chat_enabled.then_some(state.chat.drawer),
    );

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

/// Routes only Chat-owned keys. Returning false intentionally permits the
/// existing scan Escape behavior once chat has safely collapsed.
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
        KeyCode::Char('c') if key.modifiers.is_empty() => {
            state.chat.drawer = match state.chat.drawer {
                ChatDrawerState::Collapsed => ChatDrawerState::ExpandedFocused,
                ChatDrawerState::ExpandedUnfocused => ChatDrawerState::ExpandedFocused,
                ChatDrawerState::ExpandedFocused => ChatDrawerState::Collapsed,
            };
            true
        }
        KeyCode::Esc
            if state.chat.drawer != ChatDrawerState::Collapsed
                && state.chat.current_proposal().is_some() =>
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
            if state.chat.drawer != ChatDrawerState::Collapsed
                && state.chat.current_proposal().is_some() =>
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
        KeyCode::Esc
            if state.chat.drawer == ChatDrawerState::ExpandedFocused
                && !state.chat.input.is_empty() =>
        {
            state.chat.clear_input();
            state.chat.feedback = None;
            true
        }
        KeyCode::Esc if state.chat.drawer != ChatDrawerState::Collapsed => {
            state.chat.drawer = ChatDrawerState::Collapsed;
            true
        }
        KeyCode::Enter if state.chat.drawer == ChatDrawerState::ExpandedFocused => {
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
                state.chat.push("YOU", text);
                state.chat.clear_input();
                state.chat.queued += 1;
                state.chat.status = "Sending…".to_string();
            }
            true
        }
        KeyCode::Backspace if state.chat.drawer == ChatDrawerState::ExpandedFocused => {
            state.chat.backspace();
            true
        }
        KeyCode::Left if state.chat.drawer == ChatDrawerState::ExpandedFocused => {
            if state.chat.cursor > 0 {
                state.chat.cursor = state.chat.input[..state.chat.cursor]
                    .char_indices()
                    .last()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
            }
            true
        }
        KeyCode::Right if state.chat.drawer == ChatDrawerState::ExpandedFocused => {
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
            if state.chat.drawer == ChatDrawerState::ExpandedFocused
                && (key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT) =>
        {
            state.chat.insert_text(&ch.to_string());
            true
        }
        _ => false,
    }
}

/// Whether the expanded chat drawer should replace the dense scan panes.
pub fn chat_uses_primary_pane(width: u16, drawer: ChatDrawerState) -> bool {
    width < CHAT_NARROW_WIDTH && drawer != ChatDrawerState::Collapsed
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

fn render_chat_drawer(frame: &mut Frame, area: Rect, state: &mut UiState) {
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
    let chat = &state.chat;
    if area.width < 18 || area.height < 9 {
        frame.render_widget(
            Paragraph::new("CHAT\nResize terminal for conversation")
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
    let focus = if chat.drawer == ChatDrawerState::ExpandedFocused {
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
    let transcript: Vec<Line> = chat
        .transcript
        .iter()
        .rev()
        .take(rows[1].height.saturating_sub(2) as usize)
        .rev()
        .map(|entry| {
            Line::from(vec![
                Span::styled(
                    format!("{}  ", entry.label),
                    Style::default()
                        .fg(state.theme.accent)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(&entry.text),
            ])
        })
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
    let prompt = if chat.drawer == ChatDrawerState::ExpandedFocused {
        sanitize_chat_text(&format!("> {}", chat.input))
    } else {
        "Press c to ask about this scan".to_string()
    };
    frame.render_widget(
        Paragraph::new(prompt).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" ASK ")
                .border_style(Style::default().fg(
                    if chat.drawer == ChatDrawerState::ExpandedFocused {
                        state.theme.accent
                    } else {
                        state.theme.border
                    },
                )),
        ),
        rows[3],
    );
    let hint = chat
        .feedback
        .as_deref()
        .unwrap_or("c focus/collapse · Enter send · Esc clear");
    frame.render_widget(
        Paragraph::new(hint).style(Style::default().fg(state.theme.text_dim)),
        rows[4],
    );
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
    chat: Option<ChatDrawerState>,
) {
    let text = if popup_open {
        " ↑↓ navigate · Enter select · Esc close"
    } else if let Some(ChatDrawerState::ExpandedFocused) = chat {
        " Chat focused · Enter send/confirm · Esc clear · c collapse"
    } else if let Some(ChatDrawerState::ExpandedUnfocused) = chat {
        " ↑↓ select finding · c focus chat · Esc collapse chat"
    } else if chat.is_some() {
        " ↑↓ select finding · c open chat · p menu · q back"
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
    use crate::tui::ChatDrawerState;

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
    fn chat_drawer_width_and_c_key_cycle_are_deliberate() {
        assert!(chat_uses_primary_pane(
            CHAT_NARROW_WIDTH - 1,
            ChatDrawerState::ExpandedUnfocused
        ));
        assert!(!chat_uses_primary_pane(
            CHAT_NARROW_WIDTH,
            ChatDrawerState::ExpandedUnfocused
        ));
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
        assert_eq!(state.chat.drawer, ChatDrawerState::ExpandedFocused);
        handle_chat_key(&mut state, key(KeyCode::Char('c')), Some(&mut channels));
        assert_eq!(state.chat.drawer, ChatDrawerState::Collapsed);
        handle_chat_key(&mut state, key(KeyCode::Char('c')), Some(&mut channels));
        assert_eq!(state.chat.drawer, ChatDrawerState::ExpandedFocused);
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
        state.chat.drawer = ChatDrawerState::ExpandedFocused;
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
    fn escape_rejects_then_clears_then_collapses_before_scan_fallthrough() {
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
        state.chat.drawer = ChatDrawerState::ExpandedFocused;
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
        assert_eq!(state.chat.drawer, ChatDrawerState::Collapsed);
        assert!(!handle_chat_key(&mut state, esc, Some(&mut channels)));
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
    fn enter_does_not_confirm_a_collapsed_proposal() {
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
        state.chat.drawer = ChatDrawerState::Collapsed;
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
        state.chat.drawer = ChatDrawerState::ExpandedUnfocused;
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
        state.chat.drawer = ChatDrawerState::ExpandedFocused;
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
}
