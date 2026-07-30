pub mod context_budget;
pub mod correlation;
pub mod coverage;
pub mod orchestrator;
pub mod pack;
pub mod scanner;
pub mod screening;

use crate::state::Finding;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScannerType {
    FrameworkAnalysis,
    ThreatModel,
    Sast,
    SupplyChain,
    ApiScan,
    IacScan,
    Report,
}

impl ScannerType {
    pub fn name(&self) -> &'static str {
        match self {
            ScannerType::FrameworkAnalysis => "framework",
            ScannerType::ThreatModel => "threat_model",
            ScannerType::Sast => "sast",
            ScannerType::SupplyChain => "supply_chain",
            ScannerType::ApiScan => "api_scan",
            ScannerType::IacScan => "iac_scan",
            ScannerType::Report => "report",
        }
    }

    /// Short label for TUI display (≤14 chars).
    pub fn label(&self) -> &'static str {
        match self {
            ScannerType::FrameworkAnalysis => "Framework",
            ScannerType::ThreatModel => "ThreatModel",
            ScannerType::Sast => "SAST",
            ScannerType::SupplyChain => "SupplyChain",
            ScannerType::ApiScan => "ApiScan",
            ScannerType::IacScan => "IacScan",
            ScannerType::Report => "Report",
        }
    }
}

#[derive(Debug)]
pub enum ScanEvent {
    ScannerStarted(ScannerType),
    ScannerCompleted(ScannerType),
    FindingAdded(Finding),
    ToolCall {
        scanner: ScannerType,
        tool: String,
        arg: String,
    },
    Error {
        scanner: ScannerType,
        message: String,
    },
    /// One file read attempt and its outcome. The TUI counts these, so the live
    /// panel and `.zentra/coverage.md` are driven by the same signal and cannot
    /// disagree.
    FileRead {
        scanner: ScannerType,
        path: String,
        outcome: crate::tools::fs_tools::ReadOutcome,
    },
    TokensUsed {
        input: u32,
        output: u32,
    },
    /// Emitted by CliProvider (codex_cli) to report MCP channel lifecycle.
    /// Wired to the scan event channel in Task 8 (final integration).
    McpChannelStatus(McpStatus),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpStatus {
    Active,
    Done,
    Disconnected,
}
