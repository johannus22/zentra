use crate::agent::{McpStatus, ScanEvent, ScannerType};
use crate::tui::{ScanOutcome, ScanResult, ScanStatus, UiState};
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
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

#[allow(clippy::too_many_arguments)]
pub async fn run_scan_ui(
    mut rx: mpsc::Receiver<ScanEvent>,
    scanners: Vec<ScannerType>,
    model_info: String,
    context_window: u32,
    cancel_token: CancellationToken,
    profiles: Vec<String>,
    branch: String,
    project_name: String,
    provider_kind: String,
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
    )
    .await;
    ratatui::restore();
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
            _ = input_ticker.tick() => {
                // Poll input without blocking. We deliberately avoid crossterm's
                // EventStream: on Windows its reader thread blocks in the native
                // console read and is not torn down on drop, leaking a thread per
                // scan that then contends with the menu's event::poll and makes
                // navigation sluggish.
                while event::poll(std::time::Duration::from_millis(0))? {
                    if let Event::Key(key) = event::read()? {
                        if key.kind != KeyEventKind::Press {
                            // ignore release / repeat events to prevent double-step
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
                                            cancel_token.cancel();
                                            return Ok(ScanOutcome::BackToMenu);
                                        }
                                        _ => {}
                                    }
                                }
                                _ => {}
                            }
                        } else {
                            match key.code {
                                KeyCode::Char('q') | KeyCode::Esc => {
                                    cancel_token.cancel();
                                    return Ok(ScanOutcome::BackToMenu);
                                }
                                KeyCode::Char('p') | KeyCode::Char('?') => state.toggle_popup(),
                                KeyCode::Down => state.select_next(),
                                KeyCode::Up => state.select_prev(),
                                _ => {}
                            }
                        }
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

        terminal.draw(|f| render(f, &mut state))?;
    }
}

fn render(frame: &mut Frame, state: &mut UiState) {
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
    render_body(frame, chunks[1], state);
    render_activity(frame, chunks[2], state);
    render_detail(frame, chunks[3], state);
    render_keys(
        frame,
        chunks[4],
        state.popup_open,
        state.scan_done,
        &state.theme,
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
                while let Some(ansi) = chars.next() {
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
        ScanResult::AllFailed { failed } => (
            "✗",
            theme.error,
            format!("All {failed} scanners failed"),
        ),
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
) {
    let text = if popup_open {
        " ↑↓ navigate · Enter select · Esc close"
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

#[cfg(test)]
mod tests {
    use super::fmt_tokens;

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
