use crate::agent::ScannerType;
use crate::wizard::{provider_defaults, KNOWN_PROVIDER_NAMES};
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

pub fn clip_with_ellipsis(s: &str, max_width: usize) -> String {
    let count = s.chars().count();
    if count > max_width && max_width > 0 {
        let take = max_width.saturating_sub(1);
        let clipped: String = s.chars().take(take).collect();
        format!("{}…", clipped)
    } else {
        s.to_string()
    }
}

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

#[derive(Clone)]
pub struct ProviderFormState {
    pub provider_idx: usize,
    pub model: String,
    pub base_url: String,
    pub api_key: String,
    pub profile_name: String,
    pub focused_field: usize,  // 0=provider, 1=model, 2=base_url, 3=api_key, 4=name, 5=save
    pub error: Option<String>,
}

impl Default for ProviderFormState {
    fn default() -> Self {
        let name = KNOWN_PROVIDER_NAMES[0];
        let d = provider_defaults(name);
        Self {
            provider_idx: 0,
            model: d.models.first().cloned().unwrap_or_default(),
            base_url: d.base_url,
            api_key: String::new(),
            profile_name: name.to_string(),
            focused_field: 0,
            error: None,
        }
    }
}

impl std::fmt::Debug for ProviderFormState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderFormState")
            .field("provider_idx", &self.provider_idx)
            .field("model", &self.model)
            .field("base_url", &self.base_url)
            .field("api_key", &"[REDACTED]")
            .field("profile_name", &self.profile_name)
            .field("focused_field", &self.focused_field)
            .field("error", &self.error)
            .finish()
    }
}

impl ProviderFormState {
    pub fn cycle_provider(&mut self, delta: isize) {
        let len = KNOWN_PROVIDER_NAMES.len() as isize;
        let new_idx = ((self.provider_idx as isize + delta).rem_euclid(len)) as usize;
        self.provider_idx = new_idx;
        let name = KNOWN_PROVIDER_NAMES[new_idx];
        let d = provider_defaults(name);
        self.model = d.models.first().cloned().unwrap_or_default();
        self.base_url = d.base_url;
        self.profile_name = name.to_string();
        self.error = None;
    }

    pub fn append_char(&mut self, c: char) {
        match self.focused_field {
            1 => self.model.push(c),
            2 => self.base_url.push(c),
            3 => self.api_key.push(c),
            4 => self.profile_name.push(c),
            _ => {}
        }
    }

    pub fn backspace(&mut self) {
        match self.focused_field {
            1 => { self.model.pop(); }
            2 => { self.base_url.pop(); }
            3 => { self.api_key.pop(); }
            4 => { self.profile_name.pop(); }
            _ => {}
        }
    }

    pub fn masked_key(&self) -> String {
        if self.api_key.len() <= 6 {
            "*".repeat(self.api_key.len())
        } else {
            format!("{}{}", &self.api_key[..6], "*".repeat(self.api_key.len() - 6))
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.profile_name.trim().is_empty() {
            anyhow::bail!("Profile name cannot be empty");
        }
        // Prevent path traversal: only allow alphanumeric, hyphen, underscore
        if !self.profile_name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            anyhow::bail!("Profile name may only contain letters, numbers, hyphens, and underscores");
        }
        if self.model.trim().is_empty() {
            anyhow::bail!("Model cannot be empty");
        }
        let d = provider_defaults(KNOWN_PROVIDER_NAMES[self.provider_idx]);
        if !d.keyless && self.api_key.trim().is_empty() {
            anyhow::bail!("API key cannot be empty for this provider");
        }
        Ok(())
    }

    pub fn save(&self) -> anyhow::Result<String> {
        use crate::config::{keychain, AuthMethod, GlobalConfig, ProviderProfile};
        use crate::wizard::model_context_window;

        self.validate()?;

        let d = provider_defaults(KNOWN_PROVIDER_NAMES[self.provider_idx]);
        let cw = model_context_window(&self.model);

        let profile = ProviderProfile {
            kind: d.kind.clone(),
            base_url: self.base_url.clone(),
            model: self.model.clone(),
            keyless: d.keyless,
            auth_method: AuthMethod::ApiKey,
            context_window: Some(cw),
        };

        let mut global = GlobalConfig::load()?;
        global.profiles.insert(self.profile_name.clone(), profile);
        if global.default_profile.is_none() {
            global.default_profile = Some(self.profile_name.clone());
        }
        global.save()?;

        if !d.keyless && !self.api_key.is_empty() {
            keychain::set_key(&self.profile_name, &self.api_key)?;
        }

        Ok(self.profile_name.clone())
    }
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
    pub form: ProviderFormState,
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
            form: ProviderFormState::default(),
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
                    MenuScreen::ProviderSelector => match key.code {
                        KeyCode::Up => {
                            if state.provider_idx > 0 {
                                state.provider_idx -= 1;
                            }
                        }
                        KeyCode::Down => {
                            if state.provider_idx + 1 < state.profiles.len() {
                                state.provider_idx += 1;
                            }
                        }
                        KeyCode::Enter => {
                            if let Some((name, _)) = state.profiles.get(state.provider_idx) {
                                return Ok(MenuAction::ChangeProvider(name.clone()));
                            }
                        }
                        KeyCode::Esc => {
                            state.screen = MenuScreen::Main;
                            state.selected_idx = ACTION_CHANGE_PROVIDER;
                        }
                        _ => {}
                    },
                    MenuScreen::ProviderForm => match key.code {
                        KeyCode::Left => {
                            if state.form.focused_field == 0 {
                                state.form.cycle_provider(-1);
                            }
                        }
                        KeyCode::Right => {
                            if state.form.focused_field == 0 {
                                state.form.cycle_provider(1);
                            }
                        }
                        KeyCode::Tab | KeyCode::Down => {
                            state.form.focused_field = (state.form.focused_field + 1) % 6;
                        }
                        KeyCode::BackTab | KeyCode::Up => {
                            state.form.focused_field = state.form.focused_field.saturating_sub(1);
                        }
                        KeyCode::Char(c) => {
                            state.form.append_char(c);
                        }
                        KeyCode::Backspace => {
                            state.form.backspace();
                        }
                        KeyCode::Enter => {
                            if state.form.focused_field == 5 {
                                match state.form.save() {
                                    Ok(name) => return Ok(MenuAction::ProviderAdded(name)),
                                    Err(e) => state.form.error = Some(e.to_string()),
                                }
                            } else {
                                state.form.focused_field = (state.form.focused_field + 1) % 6;
                            }
                        }
                        KeyCode::Esc => {
                            state.screen = MenuScreen::Main;
                            state.selected_idx = ACTION_ADD_PROVIDER;
                            state.form = ProviderFormState::default(); // reset
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
        MenuScreen::ProviderSelector => render_provider_selector(frame, area, state),
        MenuScreen::ProviderForm => render_provider_form(frame, area, state),
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
    // Center header at 60% — same as the menu list
    let header_center = Layout::horizontal([
        Constraint::Percentage(30),
        Constraint::Percentage(40),
        Constraint::Percentage(30),
    ]).split(chunks[1])[1];

    let header_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = header_block.inner(header_center);
    frame.render_widget(header_block, header_center);

    let header_cols = Layout::horizontal([
        Constraint::Min(28),    // was Min(36) — banner longest line is 28 chars
        Constraint::Min(10),    // info panel (shrunk, text will clip)
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
        Constraint::Percentage(30),
        Constraint::Percentage(40),
        Constraint::Percentage(30),
    ])
    .split(chunks[2])[1];
    frame.render_widget(list, menu_area);

    let keys = Paragraph::new(" ↑↓ navigate · Enter select · q quit")
        .style(Style::default().fg(Color::DarkGray));
    let hints_center = Layout::horizontal([
        Constraint::Percentage(30),
        Constraint::Percentage(40),
        Constraint::Percentage(30),
    ]).split(chunks[3])[1];
    frame.render_widget(keys, hints_center);
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
        Constraint::Percentage(30),
        Constraint::Percentage(40),
        Constraint::Percentage(30),
    ])
    .split(chunks[2])[1];
    frame.render_widget(list, list_area);

    let keys = Paragraph::new(" Space toggle · Enter run · Esc back")
        .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(keys, chunks[3]);
}

fn render_provider_selector(frame: &mut Frame, area: ratatui::layout::Rect, state: &MenuState) {
    let chunks = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(6),
        Constraint::Min(6),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .split(area);

    let header = Paragraph::new(BANNER)
        .block(Block::default().borders(Borders::ALL))
        .style(Style::default().fg(Color::Cyan));
    frame.render_widget(header, chunks[1]);

    let items: Vec<ListItem> = state.profiles.iter().enumerate().map(|(i, (name, model))| {
        let selected = state.provider_idx == i;
        let is_active = *name == state.active_profile;
        let bullet = if is_active { "●" } else { " " };
        let prefix = if selected { "▶" } else { " " };
        let style = if selected {
            Style::default().add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        let bullet_style = Style::default().fg(if is_active { Color::Green } else { Color::DarkGray });
        ListItem::new(Line::from(vec![
            Span::raw(format!("{} ", prefix)),
            Span::styled(format!("{} ", bullet), bullet_style),
            Span::styled(format!("{:<20}", name.chars().take(20).collect::<String>()), style),
            Span::styled(
                model.chars().take(20).collect::<String>(),
                Style::default().fg(Color::DarkGray),
            ),
        ]))
    }).collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("SELECT PROVIDER"));
    let list_area = Layout::horizontal([
        Constraint::Percentage(30),
        Constraint::Percentage(40),
        Constraint::Percentage(30),
    ])
    .split(chunks[2])[1];
    frame.render_widget(list, list_area);

    let keys = Paragraph::new(" ↑↓ navigate · Enter select · Esc back")
        .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(keys, chunks[3]);
}

fn render_provider_form(frame: &mut Frame, area: ratatui::layout::Rect, state: &MenuState) {
    let form = &state.form;
    let provider_name = KNOWN_PROVIDER_NAMES[form.provider_idx];

    let field_style = |field_idx: usize| -> Style {
        if form.focused_field == field_idx {
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        }
    };

    let form_area = Layout::horizontal([
        Constraint::Percentage(30),
        Constraint::Percentage(40),
        Constraint::Percentage(30),
    ])
    .split(Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(13),
        Constraint::Fill(1),
    ]).split(area)[1])[1];

    let block = Block::default().borders(Borders::ALL).title(" ADD PROVIDER ").title_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(form_area);
    let max_field_width = inner.width.saturating_sub(15) as usize;

    let fields = vec![
        Line::from(vec![
            Span::raw("  Provider   "),
            Span::styled(format!("◀ {:<18} ▶", provider_name), field_style(0)),
        ]),
        Line::from(vec![
            Span::raw("  Model      "),
            Span::styled(format!("{:width$}", clip_with_ellipsis(&form.model, max_field_width), width = max_field_width), field_style(1)),
        ]),
        Line::from(vec![
            Span::raw("  Base URL   "),
            Span::styled(format!("{:width$}", clip_with_ellipsis(&form.base_url, max_field_width), width = max_field_width), field_style(2)),
        ]),
        Line::from(vec![
            Span::raw("  API Key    "),
            Span::styled(format!("{:width$}", clip_with_ellipsis(&form.masked_key(), max_field_width), width = max_field_width), field_style(3)),
        ]),
        Line::from(vec![
            Span::raw("  Name       "),
            Span::styled(format!("{:width$}", clip_with_ellipsis(&form.profile_name, max_field_width), width = max_field_width), field_style(4)),
        ]),
        Line::from(Span::raw("")),
    ];

    let content = Text::from(fields);
    let paragraph = Paragraph::new(content);

    let chunks = Layout::vertical([
        Constraint::Min(1),
        Constraint::Length(2),
    ])
    .split(inner);

    let bottom_rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .split(chunks[1]);

    let button_chunks = Layout::horizontal([
        Constraint::Percentage(50),
        Constraint::Percentage(50),
    ])
    .split(bottom_rows[0]);

    frame.render_widget(block, form_area);
    frame.render_widget(paragraph, chunks[0]);

    let save_label = if form.focused_field == 5 { "  ▶ Save" } else { "    Save" };
    let save = Paragraph::new(Line::from(Span::styled(save_label, field_style(5))));
    frame.render_widget(save, button_chunks[0]);

    let cancel = Paragraph::new(Line::from(Span::styled("Esc Cancel", Style::default().fg(Color::DarkGray))));
    frame.render_widget(cancel, button_chunks[1]);

    if let Some(ref err) = form.error {
        let error = Paragraph::new(Line::from(Span::styled(
            format!("  ✗ {}", err),
            Style::default().fg(Color::Red),
        )));
        frame.render_widget(error, bottom_rows[1]);
    }
}
