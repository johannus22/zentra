use crate::agent::ScannerType;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::{
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};
use ratatui::layout::Alignment;
use std::time::Duration;

#[derive(Debug, Clone, Copy)]
enum MenuRow {
    Section(&'static str),
    Item { label: &'static str, action: usize },
}

const ACTION_RUN_FULL_SCAN: usize = 0;
const ACTION_SELECT_SCANNERS: usize = 1;
const ACTION_VIEW_RESULTS: usize = 2;
const ACTION_CHANGE_PROVIDER: usize = 3;
const ACTION_ADD_PROVIDER: usize = 4;
const ACTION_EXIT: usize = 5;

/// Highest selectable action index in the main menu (6 items: 0–5).
const MAX_MENU_ACTION: usize = 5;

const MAIN_MENU_ROWS: &[MenuRow] = &[
    MenuRow::Section("SCAN"),
    MenuRow::Item { label: "Run Full Scan",      action: ACTION_RUN_FULL_SCAN },
    MenuRow::Item { label: "Select Scanners",    action: ACTION_SELECT_SCANNERS },
    MenuRow::Item { label: "View Last Results",  action: ACTION_VIEW_RESULTS },
    MenuRow::Section("PROVIDER"),
    MenuRow::Item { label: "Change Provider",    action: ACTION_CHANGE_PROVIDER },
    MenuRow::Item { label: "Add Provider",       action: ACTION_ADD_PROVIDER },
    MenuRow::Section("APP"),
    MenuRow::Item { label: "Exit",               action: ACTION_EXIT },
];

#[derive(Debug, Clone)]
pub enum MenuAction {
    RunScan(Vec<ScannerType>),
    ViewLastResults,
    ChangeProvider(String),   // profile name — from ProviderSelector
    ProviderAdded(String),    // newly created profile name — from ProviderForm
    Exit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MenuScreen {
    Main,
    ScannerSelector,
    ProviderSelector,
    ProviderForm,
}

pub struct MenuState {
    pub selected_idx: usize,
    pub screen: MenuScreen,
    pub scanner_idx: usize,
    pub scanner_selected: [bool; 5], // ThreatModel, Sast, SupplyChain, ApiScan, IacScan
    pub provider_configured: bool,
    pub project_configured: bool,
    pub active_model: String,
    pub active_profile: String,
    pub profiles: Vec<(String, String)>,  // (profile_name, model)
    pub provider_idx: usize,
}

impl MenuState {
    pub fn new(
        provider_configured: bool,
        project_configured: bool,
        profiles: Vec<(String, String)>,
        active_model: String,
        active_profile: String,
    ) -> Self {
        Self {
            selected_idx: 0,
            screen: MenuScreen::Main,
            scanner_idx: 0,
            scanner_selected: [true; 5],
            provider_configured,
            project_configured,
            active_model,
            active_profile,
            profiles,
            provider_idx: 0,
        }
    }

    pub fn next(&mut self) {
        let max = match self.screen {
            MenuScreen::Main => MAX_MENU_ACTION,
            MenuScreen::ScannerSelector => 5,
            MenuScreen::ProviderSelector | MenuScreen::ProviderForm => 0,
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
            i if i == ACTION_RUN_FULL_SCAN
              || i == ACTION_SELECT_SCANNERS
              || i == ACTION_CHANGE_PROVIDER => self.provider_configured,
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

pub async fn run_menu(
    provider_configured: bool,
    project_configured: bool,
    profiles: Vec<(String, String)>,
    active_model: String,
    active_profile: String,
) -> Result<MenuAction> {
    tokio::task::spawn_blocking(move || {
        run_menu_blocking(provider_configured, project_configured, profiles, active_model, active_profile)
    })
    .await?
}

fn run_menu_blocking(
    provider_configured: bool,
    project_configured: bool,
    profiles: Vec<(String, String)>,
    active_model: String,
    active_profile: String,
) -> Result<MenuAction> {
    debug_assert!(
        MAIN_MENU_ROWS.iter().filter(|r| matches!(r, MenuRow::Item { .. })).count() == MAX_MENU_ACTION + 1,
        "MAX_MENU_ACTION out of sync with MAIN_MENU_ROWS"
    );
    let mut terminal = ratatui::init();
    let mut state = MenuState::new(provider_configured, project_configured, profiles, active_model, active_profile);
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
                                ACTION_RUN_FULL_SCAN => {
                                    return Ok(MenuAction::RunScan(vec![
                                        ScannerType::ThreatModel,
                                        ScannerType::Sast,
                                        ScannerType::SupplyChain,
                                        ScannerType::ApiScan,
                                        ScannerType::IacScan,
                                        ScannerType::SecretsScan,
                                        ScannerType::Report,
                                    ]));
                                }
                                ACTION_SELECT_SCANNERS => {
                                    state.screen = MenuScreen::ScannerSelector;
                                    state.scanner_idx = 0;
                                    state.selected_idx = 0;
                                }
                                ACTION_VIEW_RESULTS => return Ok(MenuAction::ViewLastResults),
                                ACTION_CHANGE_PROVIDER => {
                                    state.screen = MenuScreen::ProviderSelector;
                                    state.provider_idx = 0;
                                }
                                ACTION_ADD_PROVIDER => {
                                    state.screen = MenuScreen::ProviderForm;
                                }
                                ACTION_EXIT => return Ok(MenuAction::Exit),
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
                    MenuScreen::ProviderSelector => match key.code {  // Task 5
                        KeyCode::Esc => {
                            state.screen = MenuScreen::Main;
                            state.selected_idx = ACTION_CHANGE_PROVIDER;
                        }
                        _ => {}
                    },
                    MenuScreen::ProviderForm => match key.code {  // Task 6
                        KeyCode::Esc => {
                            state.screen = MenuScreen::Main;
                            state.selected_idx = ACTION_ADD_PROVIDER;
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
        MenuScreen::ProviderSelector => render_main_menu(frame, area, state), // placeholder
        MenuScreen::ProviderForm => render_main_menu(frame, area, state),     // placeholder
    }
}

fn render_main_menu(frame: &mut Frame, area: ratatui::layout::Rect, state: &MenuState) {
    let chunks = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(6),   // header block
        Constraint::Min(12),     // menu list
        Constraint::Length(1),   // key hints
        Constraint::Fill(1),
    ])
    .split(area);

    // ── Header block: banner left, version/model/profile right ──────────────
    let header_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = header_block.inner(chunks[1]);
    frame.render_widget(header_block, chunks[1]);

    let header_cols = Layout::horizontal([
        Constraint::Min(36),
        Constraint::Length(26),
    ])
    .split(inner);

    let banner_para = Paragraph::new(BANNER).style(Style::default().fg(Color::Cyan));
    frame.render_widget(banner_para, header_cols[0]);

    let warning = if !state.provider_configured {
        "⚠ No provider configured"
    } else {
        ""
    };
    let info = Text::from(vec![
        Line::from(vec![Span::styled(
            format!("v{}", env!("CARGO_PKG_VERSION")),
            Style::default().fg(Color::DarkGray),
        )]),
        Line::from(vec![Span::styled(
            state.active_model.chars().take(22).collect::<String>(),
            Style::default().fg(Color::Green),
        )]),
        Line::from(vec![Span::styled(
            state.active_profile.chars().take(22).collect::<String>(),
            Style::default().fg(Color::DarkGray),
        )]),
        Line::from(vec![Span::styled(
            warning.to_string(),
            Style::default().fg(Color::Yellow),
        )]),
    ]);
    frame.render_widget(
        Paragraph::new(info).alignment(Alignment::Right),
        header_cols[1],
    );

    // ── Menu list with grouped sections ─────────────────────────────────────
    let items: Vec<ListItem> = MAIN_MENU_ROWS.iter().map(|row| {
        match row {
            MenuRow::Section(label) => {
                ListItem::new(format!("  {}", label))
                    .style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::ITALIC))
            }
            MenuRow::Item { label, action } => {
                let enabled = state.is_item_enabled(*action);
                let selected = state.selected_idx == *action;
                let prefix = if selected { "▶ " } else { "  " };
                let style = if !enabled {
                    Style::default().fg(Color::DarkGray)
                } else if selected {
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                ListItem::new(format!("{}{}", prefix, label)).style(style)
            }
        }
    }).collect();

    let list = List::new(items).block(Block::default().borders(Borders::ALL));
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
