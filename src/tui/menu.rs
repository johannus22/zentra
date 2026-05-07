use crate::agent::ScannerType;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::{
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};
use std::time::Duration;

#[derive(Debug, Clone)]
pub enum MenuAction {
    RunScan(Vec<ScannerType>),
    ViewLastResults,
    Config,
    Exit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MenuScreen {
    Main,
    ScannerSelector,
}

pub struct MenuState {
    pub selected_idx: usize,
    pub screen: MenuScreen,
    pub scanner_idx: usize,
    pub scanner_selected: [bool; 5], // ThreatModel, Sast, SupplyChain, ApiScan, IacScan
    pub provider_configured: bool,
    pub project_configured: bool,
}

impl MenuState {
    pub fn new(provider_configured: bool, project_configured: bool) -> Self {
        Self {
            selected_idx: 0,
            screen: MenuScreen::Main,
            scanner_idx: 0,
            scanner_selected: [true; 5],
            provider_configured,
            project_configured,
        }
    }

    pub fn next(&mut self) {
        let max = match self.screen {
            MenuScreen::Main => 4,
            MenuScreen::ScannerSelector => 5,
        };
        if self.selected_idx < max {
            self.selected_idx += 1;
        }
    }

    pub fn prev(&mut self) {
        if self.selected_idx > 0 {
            self.selected_idx -= 1;
        }
    }

    pub fn is_item_enabled(&self, idx: usize) -> bool {
        match idx {
            0 | 1 => self.provider_configured,
            _ => true,
        }
    }

    pub fn toggle_scanner(&mut self) {
        if self.scanner_idx < 5 {
            let i = self.scanner_idx;
            self.scanner_selected[i] = !self.scanner_selected[i];
        }
    }

    pub fn selected_scanner_types(&self) -> Vec<ScannerType> {
        let scanners = [
            ScannerType::ThreatModel,
            ScannerType::Sast,
            ScannerType::SupplyChain,
            ScannerType::ApiScan,
            ScannerType::IacScan,
        ];
        let mut result: Vec<ScannerType> = scanners
            .iter()
            .enumerate()
            .filter(|(i, _)| self.scanner_selected[*i])
            .map(|(_, &t)| t)
            .collect();
        result.push(ScannerType::Report);
        result
    }
}

pub async fn run_menu(provider_configured: bool, project_configured: bool) -> Result<MenuAction> {
    tokio::task::spawn_blocking(move || run_menu_blocking(provider_configured, project_configured))
        .await?
}

fn run_menu_blocking(provider_configured: bool, project_configured: bool) -> Result<MenuAction> {
    let mut terminal = ratatui::init();
    let mut state = MenuState::new(provider_configured, project_configured);
    let result = run_menu_loop(&mut terminal, &mut state);
    ratatui::restore();
    result
}

fn run_menu_loop(
    terminal: &mut ratatui::DefaultTerminal,
    state: &mut MenuState,
) -> Result<MenuAction> {
    loop {
        terminal.draw(|f| render_menu(f, state))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match state.screen {
                    MenuScreen::Main => match key.code {
                        KeyCode::Up => state.prev(),
                        KeyCode::Down => state.next(),
                        KeyCode::Enter => {
                            if !state.is_item_enabled(state.selected_idx) {
                                continue;
                            }
                            match state.selected_idx {
                                0 => {
                                    return Ok(MenuAction::RunScan(vec![
                                        ScannerType::ThreatModel,
                                        ScannerType::Sast,
                                        ScannerType::SupplyChain,
                                        ScannerType::ApiScan,
                                        ScannerType::IacScan,
                                        ScannerType::Report,
                                    ]));
                                }
                                1 => {
                                    state.screen = MenuScreen::ScannerSelector;
                                    state.selected_idx = 0;
                                }
                                2 => return Ok(MenuAction::ViewLastResults),
                                3 => return Ok(MenuAction::Config),
                                4 => return Ok(MenuAction::Exit),
                                _ => {}
                            }
                        }
                        KeyCode::Char('q') => return Ok(MenuAction::Exit),
                        _ => {}
                    },
                    MenuScreen::ScannerSelector => match key.code {
                        KeyCode::Up => {
                            if state.scanner_idx > 0 { state.scanner_idx -= 1; }
                        }
                        KeyCode::Down => {
                            if state.scanner_idx < 5 { state.scanner_idx += 1; }
                        }
                        KeyCode::Char(' ') => {
                            if state.scanner_idx < 5 { state.toggle_scanner(); }
                        }
                        KeyCode::Enter => {
                            if state.scanner_idx == 5 {
                                let types = state.selected_scanner_types();
                                return Ok(MenuAction::RunScan(types));
                            }
                        }
                        KeyCode::Esc => {
                            state.screen = MenuScreen::Main;
                            state.selected_idx = 1;
                        }
                        _ => {}
                    },
                }
            }
        }
    }
}

const BANNER: &str = " ____        _ \n|_  /___ _ _| |_ _ _ __ _\n / // -_) ' \\  _| '_/ _` |\n/___\\___|_||_\\__|_| \\__,_|";

fn render_menu(frame: &mut Frame, state: &MenuState) {
    let area = frame.area();
    match state.screen {
        MenuScreen::Main => render_main_menu(frame, area, state),
        MenuScreen::ScannerSelector => render_scanner_selector(frame, area, state),
    }
}

fn render_main_menu(frame: &mut Frame, area: ratatui::layout::Rect, state: &MenuState) {
    let chunks = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(6),
        Constraint::Min(7),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .split(area);

    let warning = if !state.provider_configured {
        "\n⚠  No provider configured — select Setup/Config to get started"
    } else {
        ""
    };
    let header_text = format!(
        "{}\nAI-powered Application Security · v{}{}",
        BANNER,
        env!("CARGO_PKG_VERSION"),
        warning
    );
    let header = Paragraph::new(header_text)
        .block(Block::default().borders(Borders::ALL))
        .style(Style::default().fg(Color::Cyan));
    frame.render_widget(header, chunks[1]);

    let menu_items = [
        "Run Full Scan",
        "Select Scanners",
        "View Last Results",
        "Setup / Config",
        "Exit",
    ];

    let items: Vec<ListItem> = menu_items
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let enabled = state.is_item_enabled(i);
            let selected = state.selected_idx == i;
            let prefix = if selected { "▶ " } else { "  " };
            let style = if !enabled {
                Style::default().fg(Color::DarkGray)
            } else if selected {
                Style::default().add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            ListItem::new(format!("{}{}", prefix, label)).style(style)
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL));
    let menu_area = Layout::horizontal([
        Constraint::Percentage(20),
        Constraint::Percentage(60),
        Constraint::Percentage(20),
    ])
    .split(chunks[2])[1];
    frame.render_widget(list, menu_area);

    let keys = Paragraph::new(" ↑↓ navigate · Enter select · q quit")
        .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(keys, chunks[3]);
}

fn render_scanner_selector(frame: &mut Frame, area: ratatui::layout::Rect, state: &MenuState) {
    let chunks = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(6),
        Constraint::Min(10),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .split(area);

    let header = Paragraph::new(BANNER)
        .block(Block::default().borders(Borders::ALL))
        .style(Style::default().fg(Color::Cyan));
    frame.render_widget(header, chunks[1]);

    let scanner_names = [
        ("Threat Model", "STRIDE · attack surface · trust boundaries"),
        ("SAST", "OWASP Top 10 static analysis"),
        ("Supply Chain", "CVEs · deps · npm audit"),
        ("API Scan", "OWASP API Top 10 · OpenAPI"),
        ("IaC Scan", "Docker · Terraform · K8s"),
    ];

    let mut items: Vec<ListItem> = scanner_names
        .iter()
        .enumerate()
        .map(|(i, (name, desc))| {
            let check = if state.scanner_selected[i] { "✓" } else { " " };
            let selected = state.scanner_idx == i;
            let prefix = if selected { "▶" } else { " " };
            let style = if selected {
                Style::default().add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            ListItem::new(
                Line::from(vec![
                    Span::raw(format!("{} [{}] {:<16}", prefix, check, name)),
                    Span::styled(desc.to_string(), Style::default().fg(Color::DarkGray)),
                ])
            ).style(style)
        })
        .collect();

    items.push(ListItem::new("  ─────────────────────────────────────────")
        .style(Style::default().fg(Color::DarkGray)));
    items.push(ListItem::new("  [✓] Report              Always included   [locked]")
        .style(Style::default().fg(Color::DarkGray)));
    let run_label = format!(
        "▶ Run Selected ({} scanners)",
        state.scanner_selected.iter().filter(|&&b| b).count() + 1
    );
    let run_style = if state.scanner_idx == 5 {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    items.push(ListItem::new(run_label).style(run_style));

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("SELECT SCANNERS"));
    let list_area = Layout::horizontal([
        Constraint::Percentage(10),
        Constraint::Percentage(80),
        Constraint::Percentage(10),
    ])
    .split(chunks[2])[1];
    frame.render_widget(list, list_area);

    let keys = Paragraph::new(" Space toggle · Enter run · Esc back")
        .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(keys, chunks[3]);
}
