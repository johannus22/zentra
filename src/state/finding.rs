use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub scanner: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub location: Option<String>,
    pub recommendation: String,
}
