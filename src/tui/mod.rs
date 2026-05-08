pub mod menu;
pub mod results;
pub mod scan_ui;

use crate::agent::{ScanEvent, ScannerType};
use crate::state::{Finding, Severity};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanOutcome {
    Completed,
    Aborted,
    Reconfigure,
    ChangeProvider(String),
    BackToMenu,
}

pub struct PopupState {
    pub selected: usize,
}

impl Default for PopupState {
    fn default() -> Self {
        Self::new()
    }
}

impl PopupState {
    pub fn new() -> Self {
        Self { selected: 0 }
    }

    pub fn next(&mut self, item_count: usize) {
        if self.selected + 1 < item_count {
            self.selected += 1;
        }
    }

    pub fn prev(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanStatus {
    Queued,
    Waiting,  // Report scanner: waits for all others
    Running,
    Done,
    Failed,
}

#[derive(Debug, Clone)]
pub struct UiScanner {
    pub scanner_type: ScannerType,
    pub status: ScanStatus,
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
    pub info_count: u32,
    pub error: Option<String>,
}

impl UiScanner {
    fn new(scanner_type: ScannerType, is_report: bool) -> Self {
        Self {
            scanner_type,
            status: if is_report { ScanStatus::Waiting } else { ScanStatus::Queued },
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            info_count: 0,
            error: None,
        }
    }

    pub fn add_finding(&mut self, severity: &Severity) {
        match severity {
            Severity::Critical => self.critical_count += 1,
            Severity::High => self.high_count += 1,
            Severity::Medium => self.medium_count += 1,
            Severity::Low => self.low_count += 1,
            Severity::Info => self.info_count += 1,
        }
    }
}

pub struct UiState {
    pub scanners: Vec<UiScanner>,
    pub findings: Vec<Finding>,
    pub activity: String,
    pub selected_idx: usize,
    pub peak_input_tokens: u32,
    pub total_tokens: u32,
    pub context_window: u32,
    pub model_info: String,
    pub branch: String,
    pub popup_open: bool,
    pub popup: PopupState,
    pub scan_done: bool,
    pub scan_aborted: bool,
    pub animation_index: usize,
    pub scan_start: std::time::Instant,
    pub scan_end: Option<std::time::Instant>,
    pub project_name: String,
    pub profiles: Vec<String>,
    pub provider_popup_open: bool,
    pub provider_popup: PopupState,
}

impl UiState {
    pub fn new(
        scanner_types: Vec<ScannerType>,
        model_info: String,
        context_window: u32,
        profiles: Vec<String>,
        branch: String,
        project_name: String,
    ) -> Self {
        let scanners = scanner_types
            .iter()
            .map(|&t| UiScanner::new(t, t == ScannerType::Report))
            .collect();
        Self {
            scanners,
            findings: Vec::new(),
            activity: String::new(),
            selected_idx: 0,
            peak_input_tokens: 0,
            total_tokens: 0,
            context_window,
            model_info,
            branch,
            popup_open: false,
            popup: PopupState::new(),
            scan_done: false,
            scan_aborted: false,
            animation_index: 0,
            scan_start: std::time::Instant::now(),
            scan_end: None,
            project_name,
            profiles,
            provider_popup_open: false,
            provider_popup: PopupState::new(),
        }
    }

    pub fn apply_event(&mut self, event: ScanEvent) {
        match event {
            ScanEvent::ScannerStarted(t) => {
                if let Some(s) = self.scanners.iter_mut().find(|s| s.scanner_type == t) {
                    s.status = ScanStatus::Running;
                }
            }
            ScanEvent::ScannerCompleted(t) => {
                if let Some(s) = self.scanners.iter_mut().find(|s| s.scanner_type == t) {
                    if s.status != ScanStatus::Failed {
                        s.status = ScanStatus::Done;
                    }
                }
            }
            ScanEvent::FindingAdded(f) => {
                if let Some(s) = self.scanners.iter_mut().find(|s| s.scanner_type.name() == f.scanner) {
                    s.add_finding(&f.severity);
                }
                self.findings.push(f);
                self.findings.sort_by_key(|f| f.severity.order());
                self.selected_idx = self.selected_idx.min(self.findings.len().saturating_sub(1));
            }
            ScanEvent::ToolCall { tool, arg, .. } => {
                self.activity = if arg.is_empty() {
                    format!("→ {}", tool)
                } else {
                    format!("→ {}({})", tool, arg)
                };
            }
            ScanEvent::Error { scanner, message } => {
                if let Some(s) = self.scanners.iter_mut().find(|s| s.scanner_type == scanner) {
                    s.status = ScanStatus::Failed;
                    s.error = Some(message);
                }
            }
            ScanEvent::TokensUsed { input, output } => {
                self.total_tokens += input + output;
                if input > self.peak_input_tokens {
                    self.peak_input_tokens = input;
                }
            }
        }
    }

    pub fn all_done(&self) -> bool {
        self.scanners.iter().all(|s| {
            matches!(s.status, ScanStatus::Done | ScanStatus::Failed)
        })
    }

    pub fn select_next(&mut self) {
        if !self.findings.is_empty() && self.selected_idx < self.findings.len() - 1 {
            self.selected_idx += 1;
        }
    }

    pub fn select_prev(&mut self) {
        if self.selected_idx > 0 {
            self.selected_idx -= 1;
        }
    }

    pub fn selected_finding(&self) -> Option<&Finding> {
        self.findings.get(self.selected_idx)
    }

    pub fn total_findings(&self) -> usize {
        self.findings.iter().filter(|f| f.scanner != "framework").count()
    }

    pub fn token_pct(&self) -> u16 {
        if self.context_window == 0 {
            return 0;
        }
        ((self.peak_input_tokens as f64 / self.context_window as f64) * 100.0).min(100.0) as u16
    }

    pub fn toggle_popup(&mut self) {
        self.popup_open = !self.popup_open;
        if self.popup_open {
            self.popup = PopupState::new();
        }
    }

    pub fn toggle_provider_popup(&mut self) {
        self.provider_popup_open = !self.provider_popup_open;
        if self.provider_popup_open {
            self.provider_popup = PopupState::new();
        }
    }

    pub fn mark_complete(&mut self) {
        if self.scan_end.is_some() {
            return;
        }
        self.scan_done = true;
        self.scan_end = Some(std::time::Instant::now());
    }

    pub fn abort_scan(&mut self) {
        if self.scan_done {
            return;
        }
        for s in &mut self.scanners {
            if s.status == ScanStatus::Running {
                s.status = ScanStatus::Failed;
            }
        }
        self.scan_aborted = true;
        self.scan_done = true;
        self.scan_end = Some(std::time::Instant::now());
    }

    pub fn elapsed_duration(&self) -> std::time::Duration {
        self.scan_end
            .map(|end| end.checked_duration_since(self.scan_start).unwrap_or(std::time::Duration::ZERO))
            .unwrap_or_else(|| self.scan_start.elapsed())
    }
}
