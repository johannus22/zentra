use crate::agent::ScannerType;
use crate::state::{Finding, Severity};
use crate::tui::{ScanStatus, UiState};
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::{
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame,
};
use std::time::Duration;

pub fn parse_findings(raw: &str) -> Vec<Finding> {
    raw.split("\n\n---\n")
        .map(|b| b.trim())
        .filter(|block| block.contains("## ["))
        .filter_map(parse_finding_block)
        .collect()
}

fn parse_finding_block(block: &str) -> Option<Finding> {
    let mut lines = block.lines();
    let header = lines.next()?.trim_start_matches('#').trim();
    let rest = header.strip_prefix('[')?;
    let (sev_str, title) = rest.split_once(']')?;
    let title = title.trim().to_string();
    let severity = parse_severity(sev_str)?;

    let mut scanner = String::new();
    let mut location = None;
    let mut description = String::new();
    let mut recommendation = String::new();

    for line in lines {
        if let Some(v) = line.strip_prefix("**Scanner:** ") {
            scanner = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("**Location:** ") {
            location = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("**Description:** ") {
            description = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("**Recommendation:** ") {
            recommendation = v.trim().to_string();
        }
    }

    if scanner.is_empty() || description.is_empty() {
        return None;
    }

    Some(Finding { scanner, severity, title, description, location, recommendation })
}

fn parse_severity(s: &str) -> Option<Severity> {
    match s {
        "CRITICAL" => Some(Severity::Critical),
        "HIGH" => Some(Severity::High),
        "MEDIUM" => Some(Severity::Medium),
        "LOW" => Some(Severity::Low),
        "INFO" => Some(Severity::Info),
        _ => None,
    }
}

pub async fn run_results() -> Result<()> {
    let raw = match std::fs::read_to_string(".zentra/detailed-findings.md") {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("No findings yet. Run 'zentra scan' first.");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    let findings = parse_findings(&raw);
    if findings.is_empty() {
        println!("No findings in .zentra/detailed-findings.md.");
        return Ok(());
    }

    tokio::task::spawn_blocking(move || run_results_blocking(findings)).await?
}

fn run_results_blocking(findings: Vec<Finding>) -> Result<()> {
    let scanner_types = vec![
        ScannerType::ThreatModel,
        ScannerType::Sast,
        ScannerType::SupplyChain,
        ScannerType::ApiScan,
        ScannerType::IacScan,
        ScannerType::Report,
    ];
    let mut state = UiState::new(scanner_types, "Results — read-only".to_string(), 0, vec![], String::new(), String::new());

    for s in state.scanners.iter_mut() {
        s.status = ScanStatus::Done;
    }
    for f in &findings {
        if let Some(s) = state.scanners.iter_mut().find(|s| s.scanner_type.name() == f.scanner) {
            s.add_finding(&f.severity);
        }
    }
    state.findings = findings;

    let mut terminal = ratatui::init();
    let result = run_results_loop(&mut terminal, &mut state);
    ratatui::restore();
    result
}

fn run_results_loop(terminal: &mut ratatui::DefaultTerminal, state: &mut UiState) -> Result<()> {
    loop {
        terminal.draw(|f| render_results(f, state))?;
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Down => state.select_next(),
                    KeyCode::Up => state.select_prev(),
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

fn render_results(frame: &mut Frame, state: &mut UiState) {
    let area = frame.area();
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(6),
        Constraint::Length(8),   // detail: 6 inner rows
        Constraint::Length(1),
    ])
    .split(area);

    let header = Paragraph::new(format!(
        "ZENTRA · Last Scan Results — {} findings",
        state.total_findings()
    ))
    .block(Block::default().borders(Borders::ALL))
    .style(Style::default().fg(Color::Cyan));
    frame.render_widget(header, chunks[0]);

    let body_chunks = Layout::horizontal([
        Constraint::Length(26),
        Constraint::Min(20),
    ])
    .split(chunks[1]);

    render_scanners_read_only(frame, body_chunks[0], state);
    render_findings_list(frame, body_chunks[1], state);

    let detail_content = state.selected_finding().map(|f| {
        let loc = f.location.as_deref().map(|l| format!(" · {}", l)).unwrap_or_default();
        format!("[{}] {}{}\n{}\nFIX: {}", f.severity, f.title, loc, f.description, f.recommendation)
    }).unwrap_or_default();
    let detail = Paragraph::new(detail_content)
        .block(Block::default().borders(Borders::ALL).title("DETAIL"))
        .wrap(ratatui::widgets::Wrap { trim: true });
    frame.render_widget(detail, chunks[2]);

    let keys = Paragraph::new(" ↑↓ navigate · q quit (read-only)");
    frame.render_widget(keys, chunks[3]);
}

fn render_scanners_read_only(frame: &mut Frame, area: ratatui::layout::Rect, state: &UiState) {
    let items: Vec<ListItem> = state.scanners.iter().map(|s| {
        let total = s.critical_count + s.high_count + s.medium_count + s.low_count + s.info_count;
        ListItem::new(format!("✓ {:<14} {}", format!("{:?}", s.scanner_type), total))
            .style(Style::default().fg(Color::Green))
    }).collect();
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("SCANNERS"));
    frame.render_widget(list, area);
}

fn render_findings_list(frame: &mut Frame, area: ratatui::layout::Rect, state: &mut UiState) {
    let inner_width = area.width.saturating_sub(2) as usize;
    let items: Vec<ListItem> = state.findings.iter().enumerate().map(|(i, f)| {
        let sev_color = match f.severity {
            Severity::Critical => Color::Red,
            Severity::High => Color::LightRed,
            Severity::Medium => Color::Yellow,
            Severity::Low => Color::Blue,
            Severity::Info => Color::DarkGray,
        };
        let loc = f.location.as_deref().unwrap_or("").chars().take(20).collect::<String>();
        let fixed = 8 + 8 + loc.len();
        let title_width = inner_width.saturating_sub(fixed).max(10);
        let title = f.title.chars().take(title_width).collect::<String>();
        let line = Line::from(vec![
            Span::styled(format!("{:<8}", format!("{}", f.severity)), Style::default().fg(sev_color).add_modifier(Modifier::BOLD)),
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
    }).collect();

    let title = format!("FINDINGS — ALL ({})", state.total_findings());
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title));
    let mut list_state = ListState::default();
    if !state.findings.is_empty() {
        list_state.select(Some(state.selected_idx));
    }
    frame.render_stateful_widget(list, area, &mut list_state);
}
