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
    ExitApp,
}

pub struct PopupState {
    pub selected: usize,
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
    pub total_tokens: u32,
    pub context_window: u32,
    pub model_info: String,
    pub popup_open: bool,
    pub popup: PopupState,
    pub scan_done: bool,
}

impl UiState {
    pub fn new(scanner_types: Vec<ScannerType>, model_info: String, context_window: u32) -> Self {
        let scanners = scanner_types
            .iter()
            .map(|&t| UiScanner::new(t, t == ScannerType::Report))
            .collect();
        Self {
            scanners,
            findings: Vec::new(),
            activity: String::new(),
            selected_idx: 0,
            total_tokens: 0,
            context_window,
            model_info,
            popup_open: false,
            popup: PopupState::new(),
            scan_done: false,
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
            }
            ScanEvent::ToolCall { tool, arg, .. } => {
                self.activity = if arg.is_empty() {
                    format!("→ {}", tool)
                } else {
                    format!("→ {}({})", tool, arg)
                };
            }
            ScanEvent::Error { scanner, .. } => {
                if let Some(s) = self.scanners.iter_mut().find(|s| s.scanner_type == scanner) {
                    s.status = ScanStatus::Failed;
                }
            }
            ScanEvent::TokensUsed { input, output } => {
                self.total_tokens += input + output;
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
        self.findings.len()
    }

    pub fn token_pct(&self) -> u16 {
        if self.context_window == 0 {
            return 0;
        }
        ((self.total_tokens as f64 / self.context_window as f64) * 100.0).min(100.0) as u16
    }

    pub fn toggle_popup(&mut self) {
        self.popup_open = !self.popup_open;
        if self.popup_open {
            self.popup = PopupState::new();
        }
    }
}
