use crate::agent::{ScanEvent, ScannerType};
use crate::tui::{ScanOutcome, ScanStatus, UiState};
use anyhow::Result;
use crossterm::event::{Event, EventStream, KeyCode};
use futures::StreamExt;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph},
    Frame,
};
use tokio::sync::mpsc;

pub const POPUP_ITEMS: &[&str] = &[
    "Change Model / Provider",
    "Abort Scan",
    "Exit App",
];

pub async fn run_scan_ui(
    mut rx: mpsc::Receiver<ScanEvent>,
    scanners: Vec<ScannerType>,
    model_info: String,
    context_window: u32,
) -> Result<ScanOutcome> {
    let mut terminal = ratatui::init();
    let result = run_loop(&mut terminal, &mut rx, scanners, model_info, context_window).await;
    ratatui::restore();
    result
}

async fn run_loop(
    terminal: &mut ratatui::DefaultTerminal,
    rx: &mut mpsc::Receiver<ScanEvent>,
    scanners: Vec<ScannerType>,
    model_info: String,
    context_window: u32,
) -> Result<ScanOutcome> {
    let mut state = UiState::new(scanners, model_info, context_window);
    let mut keys = EventStream::new();
    let mut ticker = tokio::time::interval(std::time::Duration::from_millis(80));

    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                state.apply_event(event);
                if state.all_done() && !state.popup_open {
                    terminal.draw(|f| render(f, &mut state))?;
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    return Ok(ScanOutcome::Completed);
                }
            }
            Some(Ok(evt)) = keys.next() => {
                if let Event::Key(key) = evt {
                    if state.popup_open {
                        match key.code {
                            KeyCode::Esc => state.toggle_popup(),
                            KeyCode::Up => state.popup.prev(),
                            KeyCode::Down => state.popup.next(POPUP_ITEMS.len()),
                            KeyCode::Enter => {
                                match state.popup.selected {
                                    0 => return Ok(ScanOutcome::Reconfigure),
                                    1 => return Ok(ScanOutcome::Aborted),
                                    2 => return Ok(ScanOutcome::ExitApp),
                                    _ => {}
                                }
                            }
                            _ => {}
                        }
                    } else {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Esc => return Ok(ScanOutcome::Aborted),
                            KeyCode::Char('p') | KeyCode::Char('?') => state.toggle_popup(),
                            KeyCode::Down => state.select_next(),
                            KeyCode::Up => state.select_prev(),
                            _ => {}
                        }
                    }
                }
            }
            _ = ticker.tick() => {}
        }
        terminal.draw(|f| render(f, &mut state))?;
    }
}

fn render(frame: &mut Frame, state: &mut UiState) {
    let area = frame.area();
    let chunks = Layout::vertical([
        Constraint::Length(4),
        Constraint::Min(6),
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Length(1),
    ])
    .split(area);

    render_header(frame, chunks[0], state);
    render_body(frame, chunks[1], state);
    render_activity(frame, chunks[2], state);
    render_detail(frame, chunks[3], state);
    render_keys(frame, chunks[4], state.popup_open);

    if state.popup_open {
        render_popup(frame, area, &state.popup);
    }
}

fn render_header(frame: &mut Frame, area: Rect, state: &UiState) {
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

    let text = format!(
        "{}\n{} · tokens: {} / {} {}",
        banner,
        state.model_info,
        state.total_tokens,
        state.context_window,
        bar
    );

    let paragraph = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL))
        .style(Style::default().fg(Color::Cyan));
    frame.render_widget(paragraph, area);
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
    let items: Vec<ListItem> = state
        .scanners
        .iter()
        .map(|s| {
            let icon = match s.status {
                ScanStatus::Running => "⟳",
                ScanStatus::Done => "✓",
                ScanStatus::Failed => "✗",
                ScanStatus::Queued | ScanStatus::Waiting => "○",
            };
            let color = match s.status {
                ScanStatus::Running => Color::Yellow,
                ScanStatus::Done => Color::Green,
                ScanStatus::Failed => Color::Red,
                _ => Color::DarkGray,
            };
            let label = format!("{} {:<14}", icon, format!("{:?}", s.scanner_type));
            ListItem::new(label).style(Style::default().fg(color))
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
            let title = f.title.chars().take(30).collect::<String>();
            let line = Line::from(vec![
                Span::styled(format!("{:<8}", sev), Style::default().fg(sev_color).add_modifier(Modifier::BOLD)),
                Span::raw(format!("{:<8}", f.scanner.chars().take(6).collect::<String>())),
                Span::raw(format!("{:<32}", title)),
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
    let text = format!(" ACTIVITY  {}", state.activity);
    let paragraph = Paragraph::new(text).style(Style::default().fg(Color::DarkGray));
    frame.render_widget(paragraph, area);
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

fn render_keys(frame: &mut Frame, area: Rect, popup_open: bool) {
    let text = if popup_open {
        " ↑↓ navigate · Enter select · Esc close"
    } else {
        " ↑↓ navigate · p menu · q quit"
    };
    let paragraph = Paragraph::new(text).style(Style::default().fg(Color::DarkGray));
    frame.render_widget(paragraph, area);
}

fn render_popup(frame: &mut Frame, area: Rect, popup: &crate::tui::PopupState) {
    let popup_width = 40u16;
    let popup_height = (POPUP_ITEMS.len() as u16) + 4;
    let popup_area = centered_rect(popup_width, popup_height, area);

    frame.render_widget(Clear, popup_area);

    let items: Vec<ListItem> = POPUP_ITEMS
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

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    Rect::new(x, y, width.min(area.width), height.min(area.height))
}
