use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

impl Severity {
    pub fn order(&self) -> u8 {
        match self {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
            Severity::Info => 4,
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "critical" => Some(Severity::Critical),
            "high" => Some(Severity::High),
            "medium" => Some(Severity::Medium),
            "low" => Some(Severity::Low),
            "info" => Some(Severity::Info),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub scanner: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub location: Option<String>,
    pub recommendation: String,
    /// Other scanners that independently reported the same underlying issue.
    /// Empty for singleton findings. Populated by the correlation pass as a
    /// confidence signal (independent corroboration ⇒ likely true positive).
    #[serde(default)]
    pub corroborated_by: Vec<String>,
    /// Primary CWE id, e.g. "CWE-89". Model-supplied (best-effort).
    #[serde(default)]
    pub cwe: Option<String>,
    /// Additional related CWE ids, e.g. ["CWE-20", "CWE-74"].
    #[serde(default)]
    pub secondary_cwe: Vec<String>,
    /// CVSS v3.1 base vector string (model-supplied). Present only when valid.
    #[serde(default)]
    pub cvss_vector: Option<String>,
    /// CVSS v3.1 base score, computed by us from `cvss_vector` — never model-supplied.
    #[serde(default)]
    pub cvss_score: Option<f32>,
    /// OWASP Top 10 category, e.g. "A03:2021-Injection". Model-supplied (best-effort).
    #[serde(default)]
    pub owasp: Option<String>,
    /// Legacy screening confidence, 0-100. Independent verification clears this;
    /// model confidence is not an evidence credential.
    #[serde(default)]
    pub confidence: Option<u8>,
    /// Verification disposition, or a legacy screening annotation.
    #[serde(default)]
    pub screening: Option<Screening>,
    /// Compatibility summary of the verdict or incomplete reason. Full independent
    /// review records and citations live in verification.json.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
}

impl Finding {
    /// Legacy screening and discovery severity never satisfy the verification gate.
    pub fn is_source_verified(&self) -> bool {
        self.screening == Some(Screening::SourceVerified)
    }
}

/// The audit pass verdict on one finding.
///
/// The pass annotates and never drops, matching the correlation pass: a
/// `Disputed` Critical that turns out to be real must still reach the human.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Screening {
    /// Two independent source reviews; no runtime reproduction is implied.
    #[serde(rename = "source_verified")]
    SourceVerified,
    #[serde(rename = "needs_validation")]
    NeedsValidation,
    Rejected,
    Incomplete,
    /// Reachable from untrusted input with no mitigation in the way.
    Confirmed,
    /// The pass could not show reachability, or found a mitigation.
    Disputed,
    /// Not enough context in the batch to decide either way.
    Unclear,
}

impl fmt::Display for Screening {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Screening::SourceVerified => write!(f, "source_verified"),
            Screening::NeedsValidation => write!(f, "needs_validation"),
            Screening::Rejected => write!(f, "rejected"),
            Screening::Incomplete => write!(f, "incomplete"),
            Screening::Confirmed => write!(f, "confirmed"),
            Screening::Disputed => write!(f, "disputed"),
            Screening::Unclear => write!(f, "unclear"),
        }
    }
}

impl Screening {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "source_verified" => Some(Screening::SourceVerified),
            "needs_validation" => Some(Screening::NeedsValidation),
            "rejected" => Some(Screening::Rejected),
            "incomplete" => Some(Screening::Incomplete),
            "confirmed" => Some(Screening::Confirmed),
            "disputed" => Some(Screening::Disputed),
            "unclear" => Some(Screening::Unclear),
            _ => None,
        }
    }
}
