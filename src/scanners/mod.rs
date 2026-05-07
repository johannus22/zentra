pub mod api_scan;
pub mod framework_analysis;
pub mod iac_scan;
pub mod report;
pub mod sast;
pub mod secrets;
pub mod supply_chain;
pub mod threat_model;

use crate::agent::ScannerType;

pub fn system_prompt(scanner: ScannerType) -> &'static str {
    match scanner {
        ScannerType::FrameworkAnalysis => framework_analysis::system_prompt(),
        ScannerType::ThreatModel => threat_model::system_prompt(),
        ScannerType::Sast => sast::system_prompt(),
        ScannerType::SupplyChain => supply_chain::system_prompt(),
        ScannerType::ApiScan => api_scan::system_prompt(),
        ScannerType::IacScan => iac_scan::system_prompt(),
        ScannerType::Report => report::system_prompt(),
        ScannerType::SecretsScan => panic!("SecretsScan is non-LLM; orchestrator dispatches it directly"),
    }
}

pub fn allowed_tools(scanner: ScannerType) -> &'static [&'static str] {
    match scanner {
        ScannerType::FrameworkAnalysis => framework_analysis::allowed_tools(),
        ScannerType::ThreatModel => threat_model::allowed_tools(),
        ScannerType::Sast => sast::allowed_tools(),
        ScannerType::SupplyChain => supply_chain::allowed_tools(),
        ScannerType::ApiScan => api_scan::allowed_tools(),
        ScannerType::IacScan => iac_scan::allowed_tools(),
        ScannerType::Report => report::allowed_tools(),
        ScannerType::SecretsScan => panic!("SecretsScan is non-LLM; orchestrator dispatches it directly"),
    }
}
