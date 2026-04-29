pub struct ScannerAgent;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScannerType {
    ThreatModel,
    Sast,
    SupplyChain,
    ApiScan,
    IacScan,
    Report,
}
