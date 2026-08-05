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
    /// Screening confidence, 0-100. Set by the audit pass (`agent::screening`),
    /// never by the scanner that reported the finding — a scanner grading its own
    /// work is not evidence. `None` means the finding was never screened.
    #[serde(default)]
    pub confidence: Option<u8>,
    /// What the audit pass concluded. `None` means it never ran on this finding.
    #[serde(default)]
    pub screening: Option<Screening>,
}

/// The audit pass verdict on one finding.
///
/// The pass annotates and never drops, matching the correlation pass: a
/// `Disputed` Critical that turns out to be real must still reach the human.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Screening {
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
            Screening::Confirmed => write!(f, "confirmed"),
            Screening::Disputed => write!(f, "disputed"),
            Screening::Unclear => write!(f, "unclear"),
        }
    }
}

impl Screening {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "confirmed" => Some(Screening::Confirmed),
            "disputed" => Some(Screening::Disputed),
            "unclear" => Some(Screening::Unclear),
            _ => None,
        }
    }
}
