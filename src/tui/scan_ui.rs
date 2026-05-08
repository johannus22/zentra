use crate::agent::{ScanEvent, ScannerType};
use crate::tui::{ScanOutcome, ScanStatus, UiState};
use anyhow::Result;
use crossterm::event::{Event, EventStream, KeyCode, KeyEventKind};
use futures::StreamExt;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph},
    Frame,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

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
    "Heraldizzing", 
    "Gingerizing", 
    "Jekloysizing", 
    "Jedding", 
    "Kodecrafting", 
    "Jaredizing", 
    "Adding Salt", 
    "ML BangBangizing",
    "Gabottizzizing"
];

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
) -> Result<ScanOutcome> {
    let mut terminal = ratatui::init();
    let result = run_loop(
        &mut terminal, &mut rx, scanners, model_info, context_window, cancel_token.clone(), profiles, branch, project_name,
    ).await;
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
) -> Result<ScanOutcome> {
    let mut state = UiState::new(scanners, model_info, context_window, profiles, branch, project_name);
    let mut keys = EventStream::new();
    let mut ticker = tokio::time::interval(std::time::Duration::from_millis(80));
    let mut animation_ticker = tokio::time::interval(std::time::Duration::from_millis(80));

    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                state.apply_event(event);
            }
            Some(Ok(evt)) = keys.next() => {
                if let Event::Key(key) = evt {
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
            _ = ticker.tick() => {}
            _ = animation_ticker.tick() => {
                state.animation_index = state.animation_index.wrapping_add(1);
            }
        }

        // Detect scan completion after any event (Bug 4)
        if state.all_done() && !state.scan_done {
            state.mark_complete();
            state.activity = "✓ Scan complete — browse findings · q to exit".to_string();
        }

        terminal.draw(|f| render(f, &mut state))?;
    }
}

fn render(frame: &mut Frame, state: &mut UiState) {
    let area = frame.area();
    let chunks = Layout::vertical([
        Constraint::Length(7),   // 4-line ASCII banner + model line + 2 borders
        Constraint::Min(6),
        Constraint::Length(1),
        Constraint::Length(8),   // detail: 6 inner rows for title/loc/desc/fix
        Constraint::Length(1),
    ])
    .split(area);

    render_header(frame, chunks[0], state);
    render_body(frame, chunks[1], state);
    render_activity(frame, chunks[2], state);
    render_detail(frame, chunks[3], state);
    render_keys(frame, chunks[4], state.popup_open, state.scan_done);

    if state.popup_open {
        render_popup(frame, area, &state.popup, state.scan_done);
    }
    if state.provider_popup_open {
        render_provider_popup(frame, area, &state.provider_popup, &state.profiles);
    }
}

fn render_header(frame: &mut Frame, area: Rect, state: &UiState) {
    let cols = Layout::horizontal([
        Constraint::Min(40),
        Constraint::Length(22),
    ])
    .split(area);

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

    let left_text = format!(
        "{}\n{} · peak: {} / {} {}  total: {}",
        banner,
        state.model_info,
        state.peak_input_tokens,
        state.context_window,
        bar,
        state.total_tokens,
    );

    let left = Paragraph::new(left_text)
        .block(Block::default().borders(Borders::ALL))
        .style(Style::default().fg(Color::Cyan));
    frame.render_widget(left, cols[0]);

    // Right panel: project name (green bold), branch (dark gray), version (dim)
    let project_display = state.project_name.chars().take(16).collect::<String>();
    let branch_display = state.branch.chars().take(14).collect::<String>();
    let right_content = ratatui::text::Text::from(vec![
        ratatui::text::Line::from(vec![
            ratatui::text::Span::styled(
                project_display,
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            ),
        ]),
        ratatui::text::Line::from(vec![
            ratatui::text::Span::styled(
                format!("⎇ {}", branch_display),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        ratatui::text::Line::from(vec![
            ratatui::text::Span::styled(
                format!("v{}", env!("CARGO_PKG_VERSION")),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
    ]);
    let right = Paragraph::new(right_content)
        .block(Block::default().borders(Borders::ALL))
        .alignment(ratatui::layout::Alignment::Right);
    frame.render_widget(right, cols[1]);
}

fn render_body(frame: &mut Frame, area: Rect, state: &mut UiState) {
    let chunks = Layout::horizontal([
        Constraint::Length(26),
        Constraint::Min(20),
    ])
    .split(area);

    render_scanners(frame, chunks[0], state);
    render_findings(frame, chunks[1], state);
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
                ScanStatus::Running => Color::Yellow,
                ScanStatus::Done => Color::Green,
                ScanStatus::Failed => Color::Red,
                _ => Color::DarkGray,
            };
            let label = format!("{} {:<14}", icon, s.scanner_type.label());
            let style = Style::default().fg(color);

            // Build item — two lines for failed scanners with an error message
            let item_text = if s.status == ScanStatus::Failed {
                if let Some(ref err) = s.error {
                    let truncated: String = err.chars().take(20).collect();
                    Text::from(vec![
                        Line::from(vec![Span::styled(label, Style::default().fg(Color::Red))]),
                        Line::from(vec![Span::styled(
                            format!("  └ {}", truncated),
                            Style::default().fg(Color::DarkGray).add_modifier(Modifier::ITALIC),
                        )]),
                    ])
                } else {
                    Text::from(Line::from(vec![Span::styled(label, Style::default().fg(Color::Red))]))
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

    let title = format!("SCANNERS  {}C {}H {}M {}L", total_crit, total_high, total_med, total_low);
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title));
    frame.render_widget(list, area);
}

fn render_findings(frame: &mut Frame, area: Rect, state: &mut UiState) {
    let inner_width = area.width.saturating_sub(2) as usize; // subtract left+right border
    let items: Vec<ListItem> = state
        .findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let sev_color = match f.severity {
                crate::state::Severity::Critical => Color::Red,
                crate::state::Severity::High => Color::LightRed,
                crate::state::Severity::Medium => Color::Yellow,
                crate::state::Severity::Low => Color::Blue,
                crate::state::Severity::Info => Color::DarkGray,
            };
            let sev = format!("{}", f.severity);
            let loc = f.location.as_deref().unwrap_or("").chars().take(20).collect::<String>();
            let fixed = 8 + 8 + loc.len(); // sev col + scanner col + loc col
            let title_width = inner_width.saturating_sub(fixed).max(10);
            let title = f.title.chars().take(title_width).collect::<String>();
            let line = Line::from(vec![
                Span::styled(format!("{:<8}", sev), Style::default().fg(sev_color).add_modifier(Modifier::BOLD)),
                Span::raw(format!("{:<8}", f.scanner.chars().take(6).collect::<String>())),
                Span::raw(format!("{:<width$}", title, width = title_width)),
                Span::styled(loc, Style::default().fg(Color::DarkGray)),
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
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title));
    let mut list_state = ListState::default();
    if !state.findings.is_empty() {
        list_state.select(Some(state.selected_idx));
    }
    frame.render_stateful_widget(list, area, &mut list_state);
}

fn render_activity(frame: &mut Frame, area: Rect, state: &UiState) {
    let content = if state.scan_done {
        let (icon, icon_color, verb) = if state.scan_aborted {
            ("✗", Color::Red, "Aborted".to_string())
        } else {
            let elapsed = state.elapsed_duration();
            let secs = elapsed.as_secs();
            let duration = if secs >= 60 {
                format!("Hacked in {}m {}s", secs / 60, secs % 60)
            } else {
                format!("Hacked in {}s", secs)
            };
            ("✓", Color::Green, duration)
        };
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
                Style::default().fg(Color::DarkGray).add_modifier(Modifier::ITALIC),
            ),
        ])
    } else {
        let animation_speed = 20;
        let word_index = (state.animation_index / animation_speed) % ACTIVITY_VERBS.len();
        let current_verb = ACTIVITY_VERBS[word_index];
        let speed = 1.676767_f64;
        let brightness = (state.animation_index as f64 * speed).sin();
        let pulse = ((brightness * 60.0) + 190.0) as u8;
        let glow_color = Color::Rgb(pulse, pulse, 255);
        Line::from(vec![
            Span::styled(
                format!("{:<2}", LOADING_FRAMES[state.animation_index % LOADING_FRAMES.len()]),
                Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("{: <22}", current_verb),
                Style::default().fg(glow_color).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" {}", state.activity),
                Style::default().fg(Color::DarkGray).add_modifier(Modifier::ITALIC),
            ),
        ])
    };
    frame.render_widget(Paragraph::new(content), area);
}

fn render_detail(frame: &mut Frame, area: Rect, state: &UiState) {
    let content = state.selected_finding().map(|f| {
        let loc = f.location.as_deref().map(|l| format!(" · {}", l)).unwrap_or_default();
        format!("[{}] {}{}\n{}\nFIX: {}", f.severity, f.title, loc, f.description, f.recommendation)
    }).unwrap_or_default();

    let paragraph = Paragraph::new(content)
        .block(Block::default().borders(Borders::ALL).title("DETAIL"))
        .wrap(ratatui::widgets::Wrap { trim: true });
    frame.render_widget(paragraph, area);
}

fn render_keys(frame: &mut Frame, area: Rect, popup_open: bool, scan_done: bool) {
    let text = if popup_open {
        " ↑↓ navigate · Enter select · Esc close"
    } else if scan_done {
        " ↑↓ select finding · p menu · q menu"
    } else {
        " ↑↓ navigate · p menu · q menu"
    };
    let paragraph = Paragraph::new(text).style(Style::default().fg(Color::DarkGray));
    frame.render_widget(paragraph, area);
}

fn render_popup(frame: &mut Frame, area: Rect, popup: &crate::tui::PopupState, scan_done: bool) {
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
                Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow)
            } else {
                Style::default()
            };
            ListItem::new(format!("{}{}", prefix, label)).style(style)
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("  MENU  ").title_style(Style::default().fg(Color::Cyan)));
    frame.render_widget(list, popup_area);
}

fn render_provider_popup(
    frame: &mut Frame,
    area: Rect,
    popup: &crate::tui::PopupState,
    profiles: &[String],
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
                Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow)
            } else {
                Style::default()
            };
            ListItem::new(format!("{}{}", prefix, name)).style(style)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title("  SELECT PROVIDER  ")
            .title_style(Style::default().fg(Color::Cyan)),
    );
    frame.render_widget(list, popup_area);
}

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    Rect::new(x, y, width.min(area.width), height.min(area.height))
}
