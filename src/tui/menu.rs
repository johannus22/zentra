use crate::agent::ScannerType;
use crate::config::AuthMethod;
use crate::wizard::{provider_defaults, KNOWN_PROVIDER_NAMES};
use anyhow::Context;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::Alignment;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
    Frame,
};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
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

const ACTION_RUN_FULL_SCAN: usize = 0;
const ACTION_CLONE_AND_SCAN: usize = 1;
const ACTION_RUN_PENTEST: usize = 2;
const ACTION_SELECT_SCANNERS: usize = 3;
const ACTION_VIEW_RESULTS: usize = 4;
const ACTION_SETTINGS: usize = 5;
const ACTION_EXIT: usize = 6;

/// Highest selectable action index in the main menu (7 items: 0-6).
const MAX_MENU_ACTION: usize = 6;

pub fn main_menu_actions() -> &'static [&'static str] {
    &[
        "Run Full Scan (this directory)",
        "Clone Repo & Scan",
        "Run Pentest",
        "Select Scanners",
        "View Last Results",
        "Settings",
        "Exit",
    ]
}

pub fn centered_middle_column(area: Rect) -> Rect {
    Layout::horizontal([
        Constraint::Percentage(30),
        Constraint::Percentage(40),
        Constraint::Percentage(30),
    ])
    .split(area)[1]
}

fn centered_fixed(width: u16, height: u16, area: Rect) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    Rect {
        x,
        y,
        width: w,
        height: h,
    }
}

pub fn scanner_selector_footer_hint() -> &'static str {
    " Space toggle · Enter run · Esc back"
}

pub fn provider_selector_footer_hint(state: &MenuState) -> &'static str {
    if state.pending_delete_profile.is_some() {
        " d again confirm delete · ↑↓ move cancel · ← back"
    } else {
        " ↑↓ navigate · Enter use · a add · d delete · ← back"
    }
}

#[derive(Debug, Clone)]
pub enum MenuAction {
    RunScan(Vec<ScannerType>),
    RunPentest,
    CloneAndScan(String), // repo URL — from RepoInput screen
    ViewLastResults,
    Exit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MenuScreen {
    Main,
    ScannerSelector,
    RepoInput,
}

/// Top-level Settings categories shown in the left nav of the Settings hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsCategory {
    Providers,
    Theme,
    OutputDir,
    About,
}

impl SettingsCategory {
    pub const ALL: [SettingsCategory; 4] = [
        SettingsCategory::Providers,
        SettingsCategory::Theme,
        SettingsCategory::OutputDir,
        SettingsCategory::About,
    ];

    pub fn label(self) -> &'static str {
        match self {
            SettingsCategory::Providers => "Providers",
            SettingsCategory::Theme => "Theme",
            SettingsCategory::OutputDir => "Output dir",
            SettingsCategory::About => "About",
        }
    }

    /// The detail mode shown when this category is first focused.
    fn default_detail(self) -> DetailMode {
        match self {
            SettingsCategory::Providers => DetailMode::ProviderList,
            SettingsCategory::Theme => DetailMode::ThemeList,
            SettingsCategory::OutputDir => DetailMode::OutputEdit,
            SettingsCategory::About => DetailMode::About,
        }
    }
}

/// Which pane of the Settings hub currently has keyboard focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsFocus {
    Nav,
    Detail,
}

/// What the right detail pane is currently showing/editing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailMode {
    ProviderList,
    ProviderForm,
    ThemeList,
    OutputEdit,
    About,
}

/// State for the Settings screen. Currently a single editable field: the base
/// directory for run artifacts (pentest output). Blank means "use the default".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SettingsFormState {
    /// User-entered output directory (empty = default).
    pub output_dir: String,
    /// Resolved default path, shown as a hint when `output_dir` is empty.
    pub default_dir: String,
    pub focused_field: usize,
    pub error: Option<String>,
    pub saved: bool,
}

impl SettingsFormState {
    const OUTPUT_DIR_FIELD: usize = 0;
    const SAVE_FIELD: usize = 1;
    const FIELD_COUNT: usize = 2;

    pub fn next_field(&mut self) {
        self.focused_field = (self.focused_field + 1) % Self::FIELD_COUNT;
    }

    pub fn prev_field(&mut self) {
        self.focused_field = if self.focused_field == 0 {
            Self::FIELD_COUNT - 1
        } else {
            self.focused_field - 1
        };
    }

    pub fn append_char(&mut self, c: char) {
        if self.focused_field == Self::OUTPUT_DIR_FIELD {
            self.output_dir.push(c);
            self.saved = false;
            self.error = None;
        }
    }

    pub fn backspace(&mut self) {
        if self.focused_field == Self::OUTPUT_DIR_FIELD {
            self.output_dir.pop();
            self.saved = false;
            self.error = None;
        }
    }

    /// Persist the output directory to the global config. Empty input clears the
    /// override (reverts to the default).
    pub fn save(&mut self) -> anyhow::Result<()> {
        self.save_to(&crate::config::GlobalConfig::default_path()?)
    }

    pub fn save_to(&mut self, config_path: &std::path::Path) -> anyhow::Result<()> {
        let mut global = crate::config::GlobalConfig::load_from(config_path)?;
        let trimmed = self.output_dir.trim();
        global.output_dir = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        };
        global.save_to(config_path)?;
        self.saved = true;
        self.error = None;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OAuthModalPhase {
    LaunchingBrowser,
    WaitingForCallback,
    ExchangingCode,
    Success,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthModalState {
    pub phase: OAuthModalPhase,
    pub auth_url: String,
    pub error: Option<String>,
}

#[allow(dead_code)]
enum OAuthModalEvent {
    BrowserLaunchFailed(String),
    Phase(OAuthModalPhase),
    Completed(anyhow::Result<crate::auth::OAuthTokens>),
}

#[derive(Clone)]
pub struct ProviderFormState {
    pub provider_idx: usize,
    pub model: String,
    pub base_url: String,
    pub auth_method: AuthMethod,
    pub api_key: String,
    pub profile_name: String,
    pub reasoning_effort: String,
    pub focused_field: usize,
    pub error: Option<String>,
}

/// Default profile name to pre-fill for a given provider. "custom" is a generic
/// provider with no sensible name, so it starts empty and the user must choose one.
fn default_profile_name(provider: &str) -> String {
    if provider == "custom" {
        String::new()
    } else {
        provider.to_string()
    }
}

impl Default for ProviderFormState {
    fn default() -> Self {
        let name = KNOWN_PROVIDER_NAMES[0];
        let d = provider_defaults(name);
        Self {
            provider_idx: 0,
            model: d.models.first().cloned().unwrap_or_default(),
            base_url: d.base_url,
            auth_method: AuthMethod::ApiKey,
            api_key: String::new(),
            profile_name: default_profile_name(name),
            reasoning_effort: String::new(),
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
            .field("auth_method", &self.auth_method)
            .field("api_key", &"[REDACTED]")
            .field("profile_name", &self.profile_name)
            .field("reasoning_effort", &self.reasoning_effort)
            .field("focused_field", &self.focused_field)
            .field("error", &self.error)
            .finish()
    }
}

impl ProviderFormState {
    #[allow(dead_code)]
    fn auth_field_idx(&self) -> Option<usize> {
        None
    }

    fn reasoning_field_idx(&self) -> usize {
        3
    }

    fn api_key_field_idx(&self) -> usize {
        4
    }

    fn profile_name_field_idx(&self) -> usize {
        5
    }

    fn save_field_idx(&self) -> usize {
        6
    }

    fn field_count(&self) -> usize {
        self.save_field_idx() + 1
    }

    fn requires_api_key(&self) -> bool {
        let d = provider_defaults(KNOWN_PROVIDER_NAMES[self.provider_idx]);
        !d.keyless
    }

    pub fn cycle_provider(&mut self, delta: isize) {
        let len = KNOWN_PROVIDER_NAMES.len() as isize;
        let new_idx = ((self.provider_idx as isize + delta).rem_euclid(len)) as usize;
        self.provider_idx = new_idx;
        let name = KNOWN_PROVIDER_NAMES[new_idx];
        let d = provider_defaults(name);
        self.model = d.models.first().cloned().unwrap_or_default();
        self.base_url = d.base_url;
        self.auth_method = AuthMethod::ApiKey;
        self.profile_name = default_profile_name(name);
        self.reasoning_effort.clear();
        self.focused_field = self.focused_field.min(self.save_field_idx());
        self.error = None;
    }

    pub fn cycle_auth_method(&mut self, delta: isize) {
        if delta == 0 {
            return;
        }
        self.error = None;
    }

    pub fn next_field(&mut self) {
        self.focused_field = (self.focused_field + 1) % self.field_count();
    }

    pub fn prev_field(&mut self) {
        self.focused_field = self.focused_field.saturating_sub(1);
    }

    pub fn append_char(&mut self, c: char) {
        match self.focused_field {
            1 => self.model.push(c),
            2 => self.base_url.push(c),
            field if field == self.reasoning_field_idx() => self.reasoning_effort.push(c),
            field if field == self.api_key_field_idx() => self.api_key.push(c),
            field if field == self.profile_name_field_idx() => self.profile_name.push(c),
            _ => {}
        }
    }

    pub fn backspace(&mut self) {
        match self.focused_field {
            1 => {
                self.model.pop();
            }
            2 => {
                self.base_url.pop();
            }
            field if field == self.reasoning_field_idx() => {
                self.reasoning_effort.pop();
            }
            field if field == self.api_key_field_idx() => {
                self.api_key.pop();
            }
            field if field == self.profile_name_field_idx() => {
                self.profile_name.pop();
            }
            _ => {}
        }
    }

    pub fn masked_key(&self) -> String {
        if self.api_key.len() <= 6 {
            "*".repeat(self.api_key.len())
        } else {
            format!(
                "{}{}",
                &self.api_key[..6],
                "*".repeat(self.api_key.len() - 6)
            )
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.profile_name.trim().is_empty() {
            anyhow::bail!("Profile name cannot be empty");
        }
        // Prevent path traversal: only allow alphanumeric, hyphen, underscore
        if !self
            .profile_name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            anyhow::bail!(
                "Profile name may only contain letters, numbers, hyphens, and underscores"
            );
        }
        if self.model.trim().is_empty() {
            anyhow::bail!("Model cannot be empty");
        }
        let kind = provider_defaults(KNOWN_PROVIDER_NAMES[self.provider_idx]).kind;
        let is_cli_provider = kind == "claude_cli" || kind == "codex_cli";
        if !is_cli_provider {
            crate::config::validation::validate_provider_base_url(&self.base_url)?;
        }
        if self.requires_api_key() && self.api_key.trim().is_empty() {
            anyhow::bail!("API key cannot be empty for this provider");
        }
        Ok(())
    }

    pub fn save(&self) -> anyhow::Result<String> {
        use crate::config::keychain;

        self.save_with_oauth(
            || match tokio::runtime::Handle::try_current() {
                Ok(handle) => handle.block_on(crate::auth::run_oauth_flow()),
                Err(_) => tokio::runtime::Runtime::new()?.block_on(crate::auth::run_oauth_flow()),
            },
            |profile_name, tokens| keychain::set_oauth_tokens(profile_name, tokens),
        )
    }

    pub fn save_with_oauth<RunOAuth, StoreOAuth>(
        &self,
        run_oauth: RunOAuth,
        store_oauth: StoreOAuth,
    ) -> anyhow::Result<String>
    where
        RunOAuth: FnOnce() -> anyhow::Result<crate::auth::OAuthTokens>,
        StoreOAuth: FnOnce(&str, &crate::auth::OAuthTokens) -> anyhow::Result<()>,
    {
        let config_path = crate::config::GlobalConfig::default_path()?;
        self.save_with_oauth_to_path(&config_path, run_oauth, store_oauth)
    }

    pub fn save_with_oauth_to_path<RunOAuth, StoreOAuth>(
        &self,
        config_path: &std::path::Path,
        _run_oauth: RunOAuth,
        store_oauth: StoreOAuth,
    ) -> anyhow::Result<String>
    where
        RunOAuth: FnOnce() -> anyhow::Result<crate::auth::OAuthTokens>,
        StoreOAuth: FnOnce(&str, &crate::auth::OAuthTokens) -> anyhow::Result<()>,
    {
        use crate::config::keychain;

        self.save_with_oauth_to_path_using(
            config_path,
            _run_oauth,
            store_oauth,
            |profile_name| keychain::delete_oauth_tokens(profile_name),
            |profile_name, api_key| keychain::set_key(profile_name, api_key).map(|_| ()),
            |profile_name| keychain::delete_key(profile_name),
        )
    }

    pub fn save_with_oauth_to_path_using<RunOAuth, StoreOAuth, DeleteOAuth, StoreKey, DeleteKey>(
        &self,
        config_path: &std::path::Path,
        _run_oauth: RunOAuth,
        store_oauth: StoreOAuth,
        delete_oauth: DeleteOAuth,
        store_key: StoreKey,
        delete_key: DeleteKey,
    ) -> anyhow::Result<String>
    where
        RunOAuth: FnOnce() -> anyhow::Result<crate::auth::OAuthTokens>,
        StoreOAuth: FnOnce(&str, &crate::auth::OAuthTokens) -> anyhow::Result<()>,
        DeleteOAuth: FnOnce(&str) -> anyhow::Result<()>,
        StoreKey: FnOnce(&str, &str) -> anyhow::Result<()>,
        DeleteKey: FnOnce(&str) -> anyhow::Result<()>,
    {
        use crate::config::{GlobalConfig, ProviderProfile};
        use crate::wizard::model_context_window;

        self.validate()?;

        let d = provider_defaults(KNOWN_PROVIDER_NAMES[self.provider_idx]);
        let cw = model_context_window(&self.model);
        let oauth_tokens = None;

        let profile = ProviderProfile {
            kind: d.kind.clone(),
            base_url: self.base_url.clone(),
            model: self.model.clone(),
            keyless: d.keyless,
            auth_method: AuthMethod::ApiKey,
            context_window: Some(cw),
            reasoning_effort: {
                let t = self.reasoning_effort.trim();
                if t.is_empty() { None } else { Some(t.to_string()) }
            },
        };

        if let Some(ref tokens) = oauth_tokens {
            store_oauth(&self.profile_name, tokens)?;
            if let Err(delete_err) = delete_key(&self.profile_name) {
                if let Err(cleanup_err) = delete_oauth(&self.profile_name) {
                    return Err(anyhow::anyhow!(
                        "{}; additionally failed to rollback OAuth tokens: {}",
                        delete_err,
                        cleanup_err
                    ));
                }
                return Err(delete_err);
            }
        } else if !d.keyless && !self.api_key.is_empty() {
            store_key(&self.profile_name, &self.api_key)?;
        }

        let mut global = GlobalConfig::load_from(config_path)?;
        global.profiles.insert(self.profile_name.clone(), profile);
        if global.default_profile.is_none() {
            global.default_profile = Some(self.profile_name.clone());
        }
        if let Err(save_err) = global.save_to(config_path) {
            if oauth_tokens.is_some() {
                if let Err(cleanup_err) = delete_oauth(&self.profile_name) {
                    return Err(anyhow::anyhow!(
                        "{}; additionally failed to rollback OAuth tokens: {}",
                        save_err,
                        cleanup_err
                    ));
                }
            }
            return Err(save_err);
        }

        Ok(self.profile_name.clone())
    }
}

pub struct MenuState {
    pub selected_idx: usize,
    pub screen: MenuScreen,
    pub scanner_idx: usize,
    pub scanner_selected: [bool; 5],
    pub provider_configured: bool,
    pub project_configured: bool,
    pub active_model: String,
    pub active_profile: String,
    pub default_profile: String,
    pub profiles: Vec<(String, String)>,
    pub provider_idx: usize,
    pub pending_delete_profile: Option<String>,
    pub provider_error: Option<String>,
    pub form: ProviderFormState,
    pub settings: SettingsFormState,
    pub oauth_modal: Option<OAuthModalState>,
    pub project_name: String,
    pub branch_name: String,
    pub repo_url: String,
    pub repo_input_error: Option<String>,
    pub last_error: Option<String>,
    pub error_expanded: bool,
    pub theme: crate::tui::theme::Theme,
    pub settings_open: bool,
    pub settings_category_idx: usize,
    pub settings_focus: SettingsFocus,
    pub settings_detail: DetailMode,
    pub theme_options: Vec<crate::tui::theme::Theme>,
    pub theme_idx: usize,
    /// The theme that was active before the picker opened (restored on Esc).
    theme_before_picker: Option<crate::tui::theme::Theme>,
    oauth_modal_rx: Option<Receiver<OAuthModalEvent>>,
}

impl MenuState {
    pub fn new(
        provider_configured: bool,
        project_configured: bool,
        profiles: Vec<(String, String)>,
        active_model: String,
        active_profile: String,
        project_name: String,
        branch_name: String,
    ) -> Self {
        Self {
            selected_idx: 0,
            screen: MenuScreen::Main,
            scanner_idx: 0,
            scanner_selected: [true; 5],
            provider_configured,
            project_configured,
            active_model,
            default_profile: active_profile.clone(),
            active_profile,
            profiles,
            provider_idx: 0,
            pending_delete_profile: None,
            provider_error: None,
            form: ProviderFormState::default(),
            settings: Self::load_settings(),
            oauth_modal: None,
            project_name,
            branch_name,
            repo_url: String::new(),
            repo_input_error: None,
            last_error: None,
            error_expanded: false,
            theme: crate::tui::theme::resolve(
                crate::config::GlobalConfig::load().ok().and_then(|g| g.theme).as_deref(),
            ),
            settings_open: false,
            settings_category_idx: 0,
            settings_focus: SettingsFocus::Nav,
            settings_detail: DetailMode::ProviderList,
            theme_options: crate::tui::theme::load_all(),
            theme_idx: 0,
            theme_before_picker: None,
            oauth_modal_rx: None,
        }
    }

    pub fn open_theme_picker(&mut self) {
        self.theme_before_picker = Some(self.theme.clone());
        self.theme_idx = self
            .theme_options
            .iter()
            .position(|t| t.id == self.theme.id)
            .unwrap_or(0);
    }

    /// Move the highlight and live-apply the highlighted theme.
    pub fn theme_picker_next(&mut self) {
        if self.theme_idx + 1 < self.theme_options.len() {
            self.theme_idx += 1;
        }
        self.apply_highlighted_theme();
    }

    pub fn theme_picker_prev(&mut self) {
        if self.theme_idx > 0 {
            self.theme_idx -= 1;
        }
        self.apply_highlighted_theme();
    }

    fn apply_highlighted_theme(&mut self) {
        if let Some(t) = self.theme_options.get(self.theme_idx) {
            self.theme = t.clone();
        }
    }

    /// Persist the highlighted theme and close.
    pub fn confirm_theme(&mut self) -> anyhow::Result<()> {
        self.confirm_theme_to(&crate::config::GlobalConfig::default_path()?)
    }

    pub fn confirm_theme_to(&mut self, config_path: &std::path::Path) -> anyhow::Result<()> {
        self.apply_highlighted_theme();
        let mut global = crate::config::GlobalConfig::load_from(config_path)?;
        global.theme = Some(self.theme.id.clone());
        global.save_to(config_path)?;
        self.theme_before_picker = Some(self.theme.clone());
        Ok(())
    }

    /// Close without saving, restoring the pre-picker theme.
    pub fn cancel_theme(&mut self) {
        if let Some(t) = self.theme_before_picker.take() {
            self.theme = t;
        }
    }

    /// Build the Settings form from the current global config (best-effort —
    /// falls back to defaults if the config can't be read).
    fn load_settings() -> SettingsFormState {
        let output_dir = crate::config::GlobalConfig::load()
            .ok()
            .and_then(|g| g.output_dir)
            .unwrap_or_default();
        SettingsFormState {
            output_dir,
            default_dir: crate::config::GlobalConfig::default_output_base_dir()
                .display()
                .to_string(),
            focused_field: 0,
            error: None,
            saved: false,
        }
    }

    pub fn settings_category(&self) -> SettingsCategory {
        SettingsCategory::ALL[self.settings_category_idx.min(SettingsCategory::ALL.len() - 1)]
    }

    /// Open the Settings hub, reloading every sub-state from disk.
    pub fn open_settings(&mut self) {
        self.settings = Self::load_settings();
        self.form = ProviderFormState::default();
        self.provider_idx = 0;
        self.clear_provider_selector_messages();
        self.settings_category_idx = 0;
        self.settings_focus = SettingsFocus::Nav;
        self.settings_detail = SettingsCategory::Providers.default_detail();
        self.settings_open = true;
    }

    pub fn close_settings(&mut self) {
        self.settings_open = false;
        self.settings_focus = SettingsFocus::Nav;
    }

    pub fn settings_nav_up(&mut self) {
        if self.settings_category_idx > 0 {
            self.settings_category_idx -= 1;
            self.settings_detail = self.settings_category().default_detail();
        }
    }

    pub fn settings_nav_down(&mut self) {
        if self.settings_category_idx + 1 < SettingsCategory::ALL.len() {
            self.settings_category_idx += 1;
            self.settings_detail = self.settings_category().default_detail();
        }
    }

    /// Move focus from the nav into the detail pane for the current category.
    pub fn settings_enter_detail(&mut self) {
        self.settings_detail = self.settings_category().default_detail();
        self.settings_focus = SettingsFocus::Detail;
        if self.settings_category() == SettingsCategory::Theme {
            self.open_theme_picker(); // establish restore baseline + highlight
        }
    }

    /// Return focus to the nav, discarding any uncommitted detail edits.
    pub fn settings_leave_detail(&mut self) {
        if self.settings_category() == SettingsCategory::Theme {
            self.cancel_theme(); // restore pre-preview theme
        }
        self.form = ProviderFormState::default();
        self.clear_provider_selector_messages();
        self.settings_detail = self.settings_category().default_detail();
        self.settings_focus = SettingsFocus::Nav;
    }

    /// Open a fresh inline provider form from the provider list.
    pub fn open_provider_form(&mut self) {
        self.form = ProviderFormState::default();
        self.settings_detail = DetailMode::ProviderForm;
    }

    /// Cancel the inline provider form, returning to the provider list.
    pub fn cancel_provider_form(&mut self) {
        self.form = ProviderFormState::default();
        self.settings_detail = DetailMode::ProviderList;
    }

    pub fn open_repo_input(&mut self) {
        self.screen = MenuScreen::RepoInput;
        self.repo_url.clear();
        self.repo_input_error = None;
    }

    pub fn validate_repo_input(&self) -> anyhow::Result<()> {
        crate::commands::clone::validate_repo_url(&self.repo_url)
    }

    pub fn toggle_error_expanded(&mut self) {
        if self.last_error.is_some() {
            self.error_expanded = !self.error_expanded;
        }
    }

    pub fn dismiss_error(&mut self) {
        self.last_error = None;
        self.error_expanded = false;
    }

    pub fn next(&mut self) {
        let max = match self.screen {
            MenuScreen::Main => MAX_MENU_ACTION,
            MenuScreen::ScannerSelector => 5,
            MenuScreen::RepoInput => 0,
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
                || i == ACTION_CLONE_AND_SCAN
                || i == ACTION_SELECT_SCANNERS =>
            {
                self.provider_configured
            }
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

    fn clear_provider_selector_messages(&mut self) {
        self.pending_delete_profile = None;
        self.provider_error = None;
    }

    pub fn provider_selector_move_up(&mut self) {
        self.clear_provider_selector_messages();
        if self.provider_idx > 0 {
            self.provider_idx -= 1;
        }
    }

    pub fn provider_selector_move_down(&mut self) {
        self.clear_provider_selector_messages();
        if self.provider_idx + 1 < self.profiles.len() {
            self.provider_idx += 1;
        }
    }

    /// Set `name` as the default provider, persist it, and refresh the
    /// in-memory view from the saved config — all without leaving the TUI.
    ///
    /// Used by the provider selector, the add-provider form, and the OAuth
    /// modal. Previously these paths returned a `MenuAction` to `main.rs`,
    /// which tore the whole terminal down (`ratatui::restore()`) and rebuilt
    /// it (`ratatui::init()`) just to update the default profile — the source
    /// of the "screen goes blank for a second" flash on every provider change.
    fn apply_provider_change(&mut self, name: &str) -> Result<()> {
        self.apply_provider_change_to(name, &crate::config::GlobalConfig::default_path()?)
    }

    /// Path-injectable core of [`apply_provider_change`] (see that method for
    /// the rationale). Split out so tests can drive it against a temp config.
    pub fn apply_provider_change_to(
        &mut self,
        name: &str,
        config_path: &std::path::Path,
    ) -> Result<()> {
        let mut global = crate::config::GlobalConfig::load_from(config_path).unwrap_or_default();
        if global.profiles.contains_key(name) {
            global.default_profile = Some(name.to_string());
            global.save_to(config_path)?;
        }
        self.profiles = global
            .profiles
            .iter()
            .map(|(n, p)| (n.clone(), p.model.clone()))
            .collect();
        self.profiles.sort_by(|a, b| a.0.cmp(&b.0));
        self.provider_configured = !global.profiles.is_empty();
        self.active_profile = name.to_string();
        self.default_profile = name.to_string();
        self.active_model = global
            .profiles
            .get(name)
            .map(|p| p.model.clone())
            .unwrap_or_default();
        self.clear_provider_selector_messages();
        Ok(())
    }

    pub fn handle_provider_delete_key(&mut self) -> Result<bool> {
        let Some((name, _)) = self.profiles.get(self.provider_idx).cloned() else {
            self.clear_provider_selector_messages();
            return Ok(false);
        };

        self.provider_error = None;

        if name == self.active_profile || name == self.default_profile {
            self.pending_delete_profile = None;
            self.provider_error = Some("Cannot delete active provider".to_string());
            return Ok(false);
        }

        if self.pending_delete_profile.as_deref() != Some(name.as_str()) {
            self.pending_delete_profile = Some(name);
            return Ok(false);
        }

        crate::commands::config::remove_profile(&name)?;
        self.profiles.remove(self.provider_idx);
        if self.provider_idx >= self.profiles.len() && self.provider_idx > 0 {
            self.provider_idx -= 1;
        }
        self.clear_provider_selector_messages();
        Ok(true)
    }

    pub fn open_oauth_modal(&mut self, auth_url: String) {
        self.form.error = None;
        self.oauth_modal = Some(OAuthModalState {
            phase: OAuthModalPhase::LaunchingBrowser,
            auth_url,
            error: None,
        });
    }

    pub fn set_oauth_modal_phase(&mut self, phase: OAuthModalPhase) {
        if let Some(modal) = self.oauth_modal.as_mut() {
            modal.phase = phase;
        }
    }

    pub fn set_oauth_modal_error(&mut self, error: Option<String>) {
        if let Some(modal) = self.oauth_modal.as_mut() {
            modal.error = error;
        }
    }

    pub fn finish_oauth_modal_error(&mut self, error: String) {
        self.oauth_modal = None;
        self.oauth_modal_rx = None;
        self.form.error = Some(error);
        self.settings_detail = DetailMode::ProviderForm;
    }

    #[allow(dead_code)]
    fn start_oauth_modal_save(&mut self) -> Result<()> {
        self.form.validate()?;

        let session = crate::auth::OAuthSession::start();
        self.open_oauth_modal(session.auth_url().to_string());

        let (tx, rx) = mpsc::channel();
        self.oauth_modal_rx = Some(rx);

        thread::spawn(move || {
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(runtime) => runtime,
                Err(err) => {
                    let _ = tx.send(OAuthModalEvent::Completed(Err(err.into())));
                    return;
                }
            };

            if let Err(err) = open::that(session.auth_url()).context("Failed to launch browser") {
                let _ = tx.send(OAuthModalEvent::BrowserLaunchFailed(err.to_string()));
            }

            let _ = tx.send(OAuthModalEvent::Phase(OAuthModalPhase::WaitingForCallback));

            let code = match runtime.block_on(session.wait_for_code(Duration::from_secs(300))) {
                Ok(code) => code,
                Err(err) => {
                    let _ = tx.send(OAuthModalEvent::Completed(Err(err)));
                    return;
                }
            };

            let _ = tx.send(OAuthModalEvent::Phase(OAuthModalPhase::ExchangingCode));

            match runtime.block_on(session.exchange_code(&code)) {
                Ok(tokens) => {
                    let _ = tx.send(OAuthModalEvent::Phase(OAuthModalPhase::Success));
                    let _ = tx.send(OAuthModalEvent::Completed(Ok(tokens)));
                }
                Err(err) => {
                    let _ = tx.send(OAuthModalEvent::Completed(Err(err)));
                }
            }
        });

        Ok(())
    }

    fn poll_oauth_modal(&mut self) -> Result<Option<String>> {
        let event = match self.oauth_modal_rx.as_ref() {
            Some(rx) => match rx.try_recv() {
                Ok(event) => Some(event),
                Err(TryRecvError::Empty) => None,
                Err(TryRecvError::Disconnected) => Some(OAuthModalEvent::Completed(Err(
                    anyhow::anyhow!("OAuth login was interrupted"),
                ))),
            },
            None => None,
        };

        let Some(event) = event else {
            return Ok(None);
        };

        match event {
            OAuthModalEvent::BrowserLaunchFailed(error) => {
                self.set_oauth_modal_error(Some(error));
            }
            OAuthModalEvent::Phase(phase) => {
                self.set_oauth_modal_phase(phase);
            }
            OAuthModalEvent::Completed(result) => match result {
                Ok(tokens) => {
                    use crate::config::keychain;

                    let profile_name = match self.form.save_with_oauth(
                        || Ok(tokens),
                        |profile_name, tokens| keychain::set_oauth_tokens(profile_name, tokens),
                    ) {
                        Ok(profile_name) => profile_name,
                        Err(err) => {
                            self.finish_oauth_modal_error(err.to_string());
                            return Ok(None);
                        }
                    };
                    self.oauth_modal = None;
                    self.oauth_modal_rx = None;
                    return Ok(Some(profile_name));
                }
                Err(err) => self.finish_oauth_modal_error(err.to_string()),
            },
        }

        Ok(None)
    }
}

pub async fn run_menu(
    provider_configured: bool,
    project_configured: bool,
    profiles: Vec<(String, String)>,
    active_model: String,
    active_profile: String,
    project_name: String,
    branch_name: String,
    last_error: Option<String>,
) -> Result<MenuAction> {
    tokio::task::spawn_blocking(move || {
        run_menu_blocking(
            provider_configured,
            project_configured,
            profiles,
            active_model,
            active_profile,
            project_name,
            branch_name,
            last_error,
        )
    })
    .await?
}

fn run_menu_blocking(
    provider_configured: bool,
    project_configured: bool,
    profiles: Vec<(String, String)>,
    active_model: String,
    active_profile: String,
    project_name: String,
    branch_name: String,
    last_error: Option<String>,
) -> Result<MenuAction> {
    debug_assert!(
        main_menu_actions().len() == MAX_MENU_ACTION + 1,
        "MAX_MENU_ACTION out of sync with main_menu_actions()"
    );
    let mut terminal = ratatui::init();
    let mut state = MenuState::new(
        provider_configured,
        project_configured,
        profiles,
        active_model,
        active_profile,
        project_name,
        branch_name,
    );
    state.last_error = last_error;
    let result = run_menu_loop(&mut terminal, &mut state);
    ratatui::restore();
    result
}

fn run_menu_loop(
    terminal: &mut ratatui::DefaultTerminal,
    state: &mut MenuState,
) -> Result<MenuAction> {
    // Only redraw when something actually changed (a key press, a resize, or
    // an OAuth modal update). The old loop redrew every 100ms unconditionally,
    // burning CPU at idle and reading as flicker on some Windows terminals.
    let mut dirty = true;
    loop {
        if let Some(name) = state.poll_oauth_modal()? {
            // OAuth login finished — the profile is already persisted. Apply it
            // as the default in place instead of returning to main.rs, which
            // would tear the terminal down and rebuild it.
            state.apply_provider_change(&name)?;
            dirty = true;
        }
        if state.oauth_modal.is_some() {
            // The modal shows live phase updates; keep it fresh while active.
            dirty = true;
        }

        if dirty {
            terminal.draw(|f| render_menu(f, state))?;
            dirty = false;
        }

        if event::poll(Duration::from_millis(100))? {
            let ev = event::read()?;
            if matches!(ev, Event::Resize(_, _)) {
                dirty = true;
            }
            if let Event::Key(key) = ev {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                dirty = true;
                match state.screen {
                    MenuScreen::Main => {
                        if state.settings_open {
                            match state.settings_focus {
                                SettingsFocus::Nav => match key.code {
                                    KeyCode::Up => state.settings_nav_up(),
                                    KeyCode::Down => state.settings_nav_down(),
                                    KeyCode::Right | KeyCode::Enter => state.settings_enter_detail(),
                                    KeyCode::Esc => state.close_settings(),
                                    _ => {}
                                },
                                SettingsFocus::Detail => match state.settings_detail {
                                    DetailMode::ProviderList => match key.code {
                                        KeyCode::Up => state.provider_selector_move_up(),
                                        KeyCode::Down => state.provider_selector_move_down(),
                                        KeyCode::Char('a') => state.open_provider_form(),
                                        KeyCode::Char('d') => {
                                            state.handle_provider_delete_key()?;
                                        }
                                        KeyCode::Enter => {
                                            if let Some((name, _)) =
                                                state.profiles.get(state.provider_idx)
                                            {
                                                let name = name.clone();
                                                state.apply_provider_change(&name)?;
                                            }
                                        }
                                        KeyCode::Left | KeyCode::Esc => state.settings_leave_detail(),
                                        _ => {}
                                    },
                                    DetailMode::ProviderForm => {
                                        if state.oauth_modal.is_none() {
                                            match key.code {
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
                                                KeyCode::Tab | KeyCode::Down => state.form.next_field(),
                                                KeyCode::BackTab | KeyCode::Up => state.form.prev_field(),
                                                KeyCode::Char(c) => state.form.append_char(c),
                                                KeyCode::Backspace => state.form.backspace(),
                                                KeyCode::Enter => {
                                                    if state.form.focused_field
                                                        == state.form.save_field_idx()
                                                    {
                                                        match state.form.save() {
                                                            Ok(name) => {
                                                                state.apply_provider_change(&name)?;
                                                                state.form =
                                                                    ProviderFormState::default();
                                                                state.settings_detail =
                                                                    DetailMode::ProviderList;
                                                            }
                                                            Err(e) => {
                                                                state.form.error = Some(e.to_string())
                                                            }
                                                        }
                                                    } else {
                                                        state.form.next_field();
                                                    }
                                                }
                                                KeyCode::Esc => state.cancel_provider_form(),
                                                _ => {}
                                            }
                                        }
                                    }
                                    DetailMode::ThemeList => match key.code {
                                        KeyCode::Up => state.theme_picker_prev(),
                                        KeyCode::Down => state.theme_picker_next(),
                                        KeyCode::Enter => {
                                            if let Err(e) = state.confirm_theme() {
                                                state.last_error =
                                                    Some(format!("Failed to save theme: {e}"));
                                            }
                                        }
                                        KeyCode::Left | KeyCode::Esc => state.settings_leave_detail(),
                                        _ => {}
                                    },
                                    DetailMode::OutputEdit => match key.code {
                                        KeyCode::Tab | KeyCode::Down => state.settings.next_field(),
                                        KeyCode::BackTab | KeyCode::Up => state.settings.prev_field(),
                                        KeyCode::Char(c) => state.settings.append_char(c),
                                        KeyCode::Backspace => state.settings.backspace(),
                                        KeyCode::Enter => {
                                            if state.settings.focused_field
                                                == SettingsFormState::SAVE_FIELD
                                            {
                                                if let Err(e) = state.settings.save() {
                                                    state.settings.error = Some(e.to_string());
                                                }
                                            } else {
                                                state.settings.next_field();
                                            }
                                        }
                                        KeyCode::Esc => state.settings_leave_detail(),
                                        _ => {}
                                    },
                                    DetailMode::About => match key.code {
                                        KeyCode::Left | KeyCode::Esc => state.settings_leave_detail(),
                                        _ => {}
                                    },
                                },
                            }
                            continue;
                        }
                        match key.code {
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
                                        ScannerType::Report,
                                    ]));
                                }
                                ACTION_CLONE_AND_SCAN => {
                                    state.last_error = None;
                                    state.error_expanded = false;
                                    state.open_repo_input();
                                }
                                ACTION_RUN_PENTEST => return Ok(MenuAction::RunPentest),
                                ACTION_SELECT_SCANNERS => {
                                    state.screen = MenuScreen::ScannerSelector;
                                    state.scanner_idx = 0;
                                    state.selected_idx = 0;
                                }
                                ACTION_VIEW_RESULTS => return Ok(MenuAction::ViewLastResults),
                                ACTION_SETTINGS => state.open_settings(),
                                ACTION_EXIT => return Ok(MenuAction::Exit),
                                _ => {}
                            }
                        }
                        KeyCode::Char('q') => return Ok(MenuAction::Exit),
                        KeyCode::Char('e') => state.toggle_error_expanded(),
                        KeyCode::Char('x') => state.dismiss_error(),
                        KeyCode::Esc => state.dismiss_error(),
                        _ => {}
                        }
                    }
                    MenuScreen::ScannerSelector => match key.code {
                        KeyCode::Up => {
                            if state.scanner_idx > 0 {
                                state.scanner_idx -= 1;
                            }
                        }
                        KeyCode::Down => {
                            if state.scanner_idx < 5 {
                                state.scanner_idx += 1;
                            }
                        }
                        KeyCode::Char(' ') => {
                            if state.scanner_idx < 5 {
                                state.toggle_scanner();
                            }
                        }
                        KeyCode::Enter => {
                            if state.scanner_idx == 5 {
                                let types = state.selected_scanner_types();
                                return Ok(MenuAction::RunScan(types));
                            }
                        }
                        KeyCode::Esc => {
                            state.screen = MenuScreen::Main;
                            state.selected_idx = ACTION_SELECT_SCANNERS;
                        }
                        _ => {}
                    },
                    MenuScreen::RepoInput => match key.code {
                        KeyCode::Char(c) => {
                            state.repo_input_error = None;
                            state.repo_url.push(c);
                        }
                        KeyCode::Backspace => {
                            state.repo_input_error = None;
                            state.repo_url.pop();
                        }
                        KeyCode::Enter => match state.validate_repo_input() {
                            Ok(()) => {
                                let url = state.repo_url.trim().to_string();
                                return Ok(MenuAction::CloneAndScan(url));
                            }
                            Err(e) => state.repo_input_error = Some(e.to_string()),
                        },
                        KeyCode::Esc => {
                            state.screen = MenuScreen::Main;
                            state.selected_idx = ACTION_CLONE_AND_SCAN;
                        }
                        _ => {}
                    },
                }
            }
        }
    }
}

const BANNER: &str = " ____        _ \n|_  /___ _ _| |_ _ _ __ _\n / // -_) ' \\  _| '_/ _` |\n/___\\___|_||_\\__|_| \\__,_|";
pub(crate) const HEADER_HEIGHT: u16 = 7;

fn render_menu(frame: &mut Frame, state: &MenuState) {
    // Paint the whole frame with the theme background first.
    frame.render_widget(
        ratatui::widgets::Block::default().style(ratatui::style::Style::default().bg(state.theme.bg)),
        frame.area(),
    );

    let area = frame.area();
    match state.screen {
        MenuScreen::Main => render_main_menu(frame, area, state),
        MenuScreen::ScannerSelector => render_scanner_selector(frame, area, state),
        MenuScreen::RepoInput => render_repo_input(frame, area, state),
    }
}

fn render_banner_header(frame: &mut Frame, area: ratatui::layout::Rect, state: &MenuState) {
    let header_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(state.theme.border))
        .style(Style::default().bg(state.theme.bg));
    let inner = header_block.inner(area);
    frame.render_widget(header_block, area);

    let header_cols = Layout::horizontal([Constraint::Min(28), Constraint::Min(10)]).split(inner);

    let banner_para = Paragraph::new(BANNER).style(Style::default().fg(state.theme.accent));
    frame.render_widget(banner_para, header_cols[0]);

    let warning = if !state.provider_configured {
        "⚠ No provider configured"
    } else {
        ""
    };
    let project_display = state.project_name.chars().take(22).collect::<String>();
    let branch_display = state.branch_name.chars().take(22).collect::<String>();
    let provider_model = if state.provider_configured {
        format!(
            "{} · {}",
            state.active_profile.chars().take(10).collect::<String>(),
            state.active_model.chars().take(10).collect::<String>()
        )
    } else {
        String::new()
    };
    let info = Text::from(vec![
        Line::from(vec![Span::styled(
            project_display,
            Style::default()
                .fg(state.theme.success)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![Span::styled(
            format!("⎇ {}", branch_display),
            Style::default().fg(state.theme.text_dim),
        )]),
        Line::from(vec![Span::styled(
            provider_model,
            Style::default().fg(state.theme.success),
        )]),
        Line::from(vec![Span::styled(
            format!("v{}", env!("CARGO_PKG_VERSION")),
            Style::default().fg(state.theme.text_dim),
        )]),
        Line::from(vec![Span::styled(
            warning.to_string(),
            Style::default().fg(state.theme.warning),
        )]),
    ]);
    frame.render_widget(
        Paragraph::new(info).alignment(Alignment::Right),
        header_cols[1],
    );
}

fn render_main_menu(frame: &mut Frame, area: ratatui::layout::Rect, state: &MenuState) {
    let chunks = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(HEADER_HEIGHT),
        Constraint::Min(12),   // menu list
        Constraint::Length(1), // error summary (blank when no error)
        Constraint::Length(1), // key hints
        Constraint::Fill(1),   // expanded error details
    ])
    .split(area);

    let header_center = Layout::horizontal([
        Constraint::Percentage(30),
        Constraint::Percentage(40),
        Constraint::Percentage(30),
    ])
    .split(chunks[1])[1];

    render_banner_header(frame, header_center, state);

    let items: Vec<ListItem> = main_menu_actions()
        .iter()
        .enumerate()
        .map(|(action, label)| {
            let enabled = state.is_item_enabled(action);
            let selected = state.selected_idx == action;
            let prefix = if selected { "▶ " } else { "  " };
            let style = if !enabled {
                Style::default().fg(state.theme.text_muted)
            } else if selected {
                Style::default()
                    .fg(state.theme.selection_fg)
                    .bg(state.theme.selection_bg)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(state.theme.text)
            };
            ListItem::new(format!("{}{}", prefix, label)).style(style)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(state.theme.border))
            .style(Style::default().bg(state.theme.bg)),
    );
    let menu_area = centered_middle_column(chunks[2]);
    frame.render_widget(list, menu_area);

    // Collapsible error summary line.
    if let Some(err) = &state.last_error {
        let first_line = err.lines().next().unwrap_or("");
        let toggle = if state.error_expanded { "collapse" } else { "expand" };
        let summary_area = centered_middle_column(chunks[3]);
        // Reserve room for the "✗ {} · e {toggle} · x dismiss" chrome (20 fixed
        // chars + the toggle word) so the dismiss hint isn't truncated on
        // narrow terminals; derive the message budget from the actual row width.
        let chrome = 20 + toggle.chars().count();
        let budget = (summary_area.width as usize).saturating_sub(chrome).max(1);
        let summary = format!(
            "✗ {}  · e {} · x dismiss",
            clip_with_ellipsis(first_line, budget),
            toggle
        );
        frame.render_widget(
            Paragraph::new(summary).style(Style::default().fg(state.theme.error)),
            summary_area,
        );
    }

    let keys = Paragraph::new(" ↑↓ navigate · Enter select · q quit")
        .style(Style::default().fg(state.theme.text_dim));
    frame.render_widget(keys, centered_middle_column(chunks[4]));

    // Expanded details box.
    if state.error_expanded {
        if let Some(err) = &state.last_error {
            let details = Paragraph::new(err.clone())
                .style(Style::default().fg(state.theme.error))
                .wrap(Wrap { trim: false })
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Error details ")
                        .border_style(Style::default().fg(state.theme.border))
                        .style(Style::default().bg(state.theme.bg)),
                );
            frame.render_widget(details, centered_middle_column(chunks[5]));
        }
    }

    if state.settings_open {
        render_settings_hub(frame, area, state);
    }
}

fn render_settings_hub(frame: &mut Frame, area: Rect, state: &MenuState) {
    // Wide popup so long model IDs (e.g. "deepseek-v4-pro:cloud") fit.
    let w = (area.width.saturating_mul(8) / 10).clamp(60.min(area.width).max(1), area.width.max(1));
    let h = (area.height.saturating_mul(8) / 10).clamp(16.min(area.height).max(1), area.height.max(1));
    let popup = centered_fixed(w, h, area);
    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" SETTINGS ")
        .title_style(Style::default().fg(state.theme.accent))
        .border_style(Style::default().fg(state.theme.border))
        .style(Style::default().bg(state.theme.surface));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let cols = Layout::horizontal([Constraint::Length(16), Constraint::Min(20)]).split(inner);

    // ── Left nav ──────────────────────────────────────────────────────────
    let nav_items: Vec<ListItem> = SettingsCategory::ALL
        .iter()
        .enumerate()
        .map(|(i, cat)| {
            let selected = i == state.settings_category_idx;
            let nav_active = state.settings_focus == SettingsFocus::Nav;
            let marker = if selected { "▶ " } else { "  " };
            let style = if selected && nav_active {
                // Left nav has focus → strong solid highlight bar.
                Style::default()
                    .fg(state.theme.selection_fg)
                    .bg(state.theme.selection_bg)
                    .add_modifier(Modifier::BOLD)
            } else if selected {
                // A category is active but focus is in the detail pane → distinct
                // accent color (no bar) so it's clear the nav isn't focused.
                Style::default()
                    .fg(state.theme.accent)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(state.theme.text)
            };
            ListItem::new(format!("{}{}", marker, cat.label())).style(style)
        })
        .collect();
    frame.render_widget(List::new(nav_items), cols[0]);

    let detail = Block::default()
        .borders(Borders::LEFT)
        .border_style(Style::default().fg(state.theme.border));
    let detail_inner = detail.inner(cols[1]);
    frame.render_widget(detail, cols[1]);

    // ── Right detail ──────────────────────────────────────────────────────
    match state.settings_detail {
        DetailMode::ProviderList => render_settings_provider_list(frame, detail_inner, state),
        DetailMode::ProviderForm => render_settings_provider_form(frame, detail_inner, state),
        DetailMode::ThemeList => render_settings_theme_list(frame, detail_inner, state),
        DetailMode::OutputEdit => render_settings_output(frame, detail_inner, state),
        DetailMode::About => render_settings_about(frame, detail_inner, state),
    }

    if let Some(modal) = &state.oauth_modal {
        render_oauth_modal(frame, area, modal, &state.theme);
    }
}

fn render_settings_provider_list(frame: &mut Frame, area: Rect, state: &MenuState) {
    let chunks = Layout::vertical([
        Constraint::Length(1), // "Active: …"
        Constraint::Min(3),    // list
        Constraint::Length(1), // hint / error
    ])
    .split(area);

    let active = if state.active_profile.is_empty() {
        "Active: none".to_string()
    } else {
        format!("Active: {}", state.active_profile)
    };
    frame.render_widget(
        Paragraph::new(active).style(Style::default().fg(state.theme.accent)),
        chunks[0],
    );

    let max_w = chunks[1].width.saturating_sub(4) as usize;
    let mut items: Vec<ListItem> = state
        .profiles
        .iter()
        .enumerate()
        .map(|(i, (name, model))| {
            let selected = state.provider_idx == i && !state.profiles.is_empty();
            let is_active = *name == state.active_profile;
            let bullet = if is_active { "●" } else { " " };
            let name_style = if selected {
                Style::default()
                    .fg(state.theme.selection_fg)
                    .bg(state.theme.selection_bg)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(state.theme.text)
            };
            ListItem::new(vec![
                Line::from(vec![
                    Span::styled(
                        format!("{} ", bullet),
                        Style::default().fg(if is_active {
                            state.theme.success
                        } else {
                            state.theme.text_muted
                        }),
                    ),
                    Span::styled(clip_with_ellipsis(name, max_w), name_style),
                ]),
                Line::from(Span::styled(
                    format!("    {}", clip_with_ellipsis(model, max_w.saturating_sub(4))),
                    Style::default().fg(state.theme.text_dim),
                )),
            ])
        })
        .collect();
    items.push(ListItem::new(Line::from(Span::styled(
        "  + Add provider",
        Style::default().fg(state.theme.accent),
    ))));
    frame.render_widget(List::new(items), chunks[1]);

    let hint = if let Some(err) = &state.provider_error {
        Paragraph::new(format!("✗ {}", err)).style(Style::default().fg(state.theme.error))
    } else {
        Paragraph::new(provider_selector_footer_hint(state))
            .style(Style::default().fg(state.theme.text_dim))
    };
    frame.render_widget(hint, chunks[2]);
}

fn render_settings_provider_form(frame: &mut Frame, area: Rect, state: &MenuState) {
    let form = &state.form;
    let provider_name = KNOWN_PROVIDER_NAMES[form.provider_idx];
    let max_field_width = area.width.saturating_sub(15) as usize;

    let field_style = |idx: usize| -> Style {
        if form.focused_field == idx {
            Style::default()
                .fg(state.theme.warning)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(state.theme.text_dim)
        }
    };
    let cursor = |idx: usize| if form.focused_field == idx { "▶ " } else { "  " };
    let pad = |s: String| format!("{:width$}", s, width = max_field_width);

    let mut lines = vec![
        Line::from(Span::styled(
            "Add provider",
            Style::default().fg(state.theme.accent),
        )),
        Line::from(vec![
            Span::raw("  Provider   "),
            Span::styled(format!("◀ {} ▶", provider_name), field_style(0)),
        ]),
        Line::from(vec![
            Span::raw(cursor(1)),
            Span::styled("Model      ", field_style(1)),
            Span::styled(pad(clip_with_ellipsis(&form.model, max_field_width)), field_style(1)),
        ]),
        Line::from(vec![
            Span::raw(cursor(2)),
            Span::styled("Base URL   ", field_style(2)),
            Span::styled(pad(clip_with_ellipsis(&form.base_url, max_field_width)), field_style(2)),
        ]),
        Line::from(vec![
            Span::raw(cursor(form.reasoning_field_idx())),
            Span::styled("Reasoning  ", field_style(form.reasoning_field_idx())),
            Span::styled(
                pad(clip_with_ellipsis(
                    if form.reasoning_effort.is_empty() {
                        "(blank = default)"
                    } else {
                        &form.reasoning_effort
                    },
                    max_field_width,
                )),
                field_style(form.reasoning_field_idx()),
            ),
        ]),
        Line::from(vec![
            Span::raw(cursor(form.api_key_field_idx())),
            Span::styled("API Key    ", field_style(form.api_key_field_idx())),
            Span::styled(
                pad(clip_with_ellipsis(&form.masked_key(), max_field_width)),
                field_style(form.api_key_field_idx()),
            ),
        ]),
        Line::from(vec![
            Span::raw(cursor(form.profile_name_field_idx())),
            Span::styled("Name       ", field_style(form.profile_name_field_idx())),
            Span::styled(
                pad(clip_with_ellipsis(&form.profile_name, max_field_width)),
                field_style(form.profile_name_field_idx()),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            if form.focused_field == form.save_field_idx() {
                "  ▶ Save        Esc cancel"
            } else {
                "    Save        Esc cancel"
            },
            field_style(form.save_field_idx()),
        )),
    ];
    if let Some(err) = &form.error {
        lines.push(Line::from(Span::styled(
            format!("  ✗ {}", err),
            Style::default().fg(state.theme.error),
        )));
    }
    frame.render_widget(Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false }), area);
}

fn render_settings_theme_list(frame: &mut Frame, area: Rect, state: &MenuState) {
    let rows: Vec<ListItem> = state
        .theme_options
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let chips = Line::from(vec![
                Span::styled("  ", Style::default().bg(t.accent)),
                Span::styled("  ", Style::default().bg(t.error)),
                Span::styled("  ", Style::default().bg(t.success)),
                Span::raw(format!("  {}", t.name)),
            ]);
            let style = if i == state.theme_idx {
                Style::default()
                    .bg(state.theme.selection_bg)
                    .fg(state.theme.selection_fg)
            } else {
                Style::default().fg(state.theme.text)
            };
            ListItem::new(chips).style(style)
        })
        .collect();
    let chunks = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).split(area);
    frame.render_widget(List::new(rows), chunks[0]);
    frame.render_widget(
        Paragraph::new("↑↓ preview · Enter save · ← cancel")
            .style(Style::default().fg(state.theme.text_dim)),
        chunks[1],
    );
}

fn render_settings_output(frame: &mut Frame, area: Rect, state: &MenuState) {
    let s = &state.settings;
    let max_w = area.width.saturating_sub(8) as usize;
    let shown = if s.output_dir.is_empty() {
        format!("(default: {})", s.default_dir)
    } else {
        s.output_dir.clone()
    };
    let fs = |idx: usize| {
        if s.focused_field == idx {
            Style::default().fg(state.theme.warning).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(state.theme.text_dim)
        }
    };
    let mut lines = vec![
        Line::from(Span::styled(
            "Artifact output directory",
            Style::default().fg(state.theme.accent),
        )),
        Line::from(Span::styled(
            "Pentest reports & evidence go here. Blank = default.",
            Style::default().fg(state.theme.text_dim),
        )),
        Line::from(""),
        Line::from(vec![
            Span::raw(if s.focused_field == SettingsFormState::OUTPUT_DIR_FIELD { "▶ " } else { "  " }),
            Span::styled("Dir  ", fs(SettingsFormState::OUTPUT_DIR_FIELD)),
            Span::styled(clip_with_ellipsis(&shown, max_w), fs(SettingsFormState::OUTPUT_DIR_FIELD)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            if s.focused_field == SettingsFormState::SAVE_FIELD { "  ▶ Save" } else { "    Save" },
            fs(SettingsFormState::SAVE_FIELD),
        )),
    ];
    if let Some(err) = &s.error {
        lines.push(Line::from(Span::styled(
            format!("  ✗ {}", err),
            Style::default().fg(state.theme.error),
        )));
    } else if s.saved {
        lines.push(Line::from(Span::styled(
            "  ✓ Saved",
            Style::default().fg(state.theme.success),
        )));
    }

    // Anchor the key hint at the bottom of the pane, like the other detail panes.
    let chunks = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).split(area);
    frame.render_widget(
        Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false }),
        chunks[0],
    );
    frame.render_widget(
        Paragraph::new("Tab/↑↓ move · type to edit · Enter save · ← back")
            .style(Style::default().fg(state.theme.text_dim)),
        chunks[1],
    );
}

fn render_settings_about(frame: &mut Frame, area: Rect, state: &MenuState) {
    let config_path = crate::config::GlobalConfig::default_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "~/.zentra/config.toml".to_string());
    let lines = vec![
        Line::from(Span::styled(
            format!("Zentra CLI v{}", env!("CARGO_PKG_VERSION")),
            Style::default().fg(state.theme.accent).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "LLM-powered security scanner & pentest orchestrator.",
            Style::default().fg(state.theme.text_dim),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("Config:  ", Style::default().fg(state.theme.text)),
            Span::styled(config_path, Style::default().fg(state.theme.text_dim)),
        ]),
        Line::from(vec![
            Span::styled("Themes:  ", Style::default().fg(state.theme.text)),
            Span::styled("~/.zentra/themes/*.toml", Style::default().fg(state.theme.text_dim)),
        ]),
        Line::from(vec![
            Span::styled("Repo:    ", Style::default().fg(state.theme.text)),
            Span::styled(
                "https://github.com/johannus22/zentra-cli",
                Style::default().fg(state.theme.text_dim),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "← back",
            Style::default().fg(state.theme.text_dim),
        )),
    ];
    frame.render_widget(Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false }), area);
}

fn render_scanner_selector(frame: &mut Frame, area: ratatui::layout::Rect, state: &MenuState) {
    let chunks = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(HEADER_HEIGHT),
        Constraint::Min(10),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .split(area);

    let header_center = Layout::horizontal([
        Constraint::Percentage(30),
        Constraint::Percentage(40),
        Constraint::Percentage(30),
    ])
    .split(chunks[1])[1];
    render_banner_header(frame, header_center, state);

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
            let check = if state.scanner_selected[i] {
                "✓"
            } else {
                " "
            };
            let selected = state.scanner_idx == i;
            let prefix = if selected { "▶" } else { " " };
            let style = if selected {
                Style::default()
                    .fg(state.theme.selection_fg)
                    .bg(state.theme.selection_bg)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(state.theme.text)
            };
            ListItem::new(Line::from(vec![
                Span::raw(format!("{} [{}] {:<16}", prefix, check, name)),
                Span::styled(desc.to_string(), Style::default().fg(state.theme.text_dim)),
            ]))
            .style(style)
        })
        .collect();

    items.push(
        ListItem::new("  ─────────────────────────────────────────")
            .style(Style::default().fg(state.theme.text_muted)),
    );
    items.push(
        ListItem::new("  [✓] Report              Always included   [locked]")
            .style(Style::default().fg(state.theme.text_muted)),
    );
    let run_label = format!(
        "▶ Run Selected ({} scanners)",
        state.scanner_selected.iter().filter(|&&b| b).count() + 1
    );
    let run_style = if state.scanner_idx == 5 {
        Style::default()
            .fg(state.theme.selection_fg)
            .bg(state.theme.selection_bg)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(state.theme.text)
    };
    items.push(ListItem::new(run_label).style(run_style));

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title("SELECT SCANNERS")
            .border_style(Style::default().fg(state.theme.border))
            .style(Style::default().bg(state.theme.bg)),
    );
    let list_area = centered_middle_column(chunks[2]);
    frame.render_widget(list, list_area);

    let keys =
        Paragraph::new(scanner_selector_footer_hint()).style(Style::default().fg(state.theme.text_dim));
    frame.render_widget(keys, centered_middle_column(chunks[3]));
}

fn render_repo_input(frame: &mut Frame, area: ratatui::layout::Rect, state: &MenuState) {
    let outer = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(HEADER_HEIGHT),
        Constraint::Length(9),
        Constraint::Fill(1),
    ])
    .split(area);

    let header_center = Layout::horizontal([
        Constraint::Percentage(30),
        Constraint::Percentage(40),
        Constraint::Percentage(30),
    ])
    .split(outer[1])[1];
    render_banner_header(frame, header_center, state);

    let form_area = Layout::horizontal([
        Constraint::Percentage(20),
        Constraint::Percentage(60),
        Constraint::Percentage(20),
    ])
    .split(outer[2])[1];

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" CLONE & SCAN ")
        .title_style(Style::default().fg(state.theme.accent))
        .border_style(Style::default().fg(state.theme.border))
        .style(Style::default().bg(state.theme.bg));
    let inner = block.inner(form_area);
    frame.render_widget(block, form_area);

    let max_w = inner.width.saturating_sub(11) as usize;
    let mut lines = vec![
        Line::from(Span::styled(
            "  Public Git URL — cloned to a temp dir, then scanned.",
            Style::default().fg(state.theme.text_dim),
        )),
        Line::from(""),
        Line::from(vec![
            Span::raw("  Repo URL  "),
            Span::styled(
                clip_with_ellipsis(&state.repo_url, max_w),
                Style::default()
                    .fg(state.theme.warning)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            " Enter clone & scan · Esc cancel",
            Style::default().fg(state.theme.text_dim),
        )),
    ];
    if let Some(err) = &state.repo_input_error {
        lines.push(Line::from(Span::styled(
            format!(" ✗ {}", err),
            Style::default().fg(state.theme.error),
        )));
    }
    frame.render_widget(Paragraph::new(Text::from(lines)), inner);
}

fn render_oauth_modal(
    frame: &mut Frame,
    area: Rect,
    modal: &OAuthModalState,
    theme: &crate::tui::theme::Theme,
) {
    let modal_area = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(11),
        Constraint::Fill(1),
    ])
    .split(area)[1];
    let modal_area = Layout::horizontal([
        Constraint::Percentage(20),
        Constraint::Percentage(60),
        Constraint::Percentage(20),
    ])
    .split(modal_area)[1];

    let status = match modal.phase {
        OAuthModalPhase::LaunchingBrowser => "Launching browser...",
        OAuthModalPhase::WaitingForCallback => "Waiting for browser login callback...",
        OAuthModalPhase::ExchangingCode => "Exchanging authorization code...",
        OAuthModalPhase::Success => "Authentication complete. Saving provider...",
    };

    let mut lines = vec![
        Line::from(Span::styled(
            status,
            Style::default()
                .fg(theme.warning)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Open this URL if the browser does not open:",
            Style::default().fg(theme.text_dim),
        )),
        Line::from(modal.auth_url.clone()),
    ];

    if let Some(error) = &modal.error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("Browser launch failed: {error}"),
            Style::default().fg(theme.error),
        )));
    }

    frame.render_widget(Clear, modal_area);
    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" OPENAI LOGIN ")
                    .title_style(Style::default().fg(theme.accent))
                    .border_style(Style::default().fg(theme.border))
                    .style(Style::default().bg(theme.surface)),
            )
            .wrap(Wrap { trim: false }),
        modal_area,
    );
}
