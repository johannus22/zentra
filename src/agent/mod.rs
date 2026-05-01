pub mod orchestrator;
pub mod scanner;

use crate::state::Finding;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScannerType {
    ThreatModel,
    Sast,
    SupplyChain,
    ApiScan,
    IacScan,
    SecretsScan,
    Report,
}

impl ScannerType {
    pub fn name(&self) -> &'static str {
        match self {
            ScannerType::ThreatModel => "threat_model",
            ScannerType::Sast => "sast",
            ScannerType::SupplyChain => "supply_chain",
            ScannerType::ApiScan => "api_scan",
            ScannerType::IacScan => "iac_scan",
            ScannerType::SecretsScan => "secrets",
            ScannerType::Report => "report",
        }
    }
}

#[derive(Debug)]
pub enum ScanEvent {
    ScannerStarted(ScannerType),
    ScannerCompleted(ScannerType),
    FindingAdded(Finding),
    ToolCall { scanner: ScannerType, tool: String, arg: String },
    Error { scanner: ScannerType, message: String },
    TokensUsed { input: u32, output: u32 },
}
