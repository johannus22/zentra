pub mod allowlist;
pub mod engine;
pub mod entropy;
pub mod git_history;
pub mod patterns;
pub mod report;
pub mod validator;

pub use engine::SecretScanner;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsMatch {
    pub file: String,
    pub line: u32,
    pub commit: Option<String>,
    pub detector: String,
    pub entropy: Option<f64>,
    pub redacted: String,
    pub suppressed: bool,
    pub suppression_reason: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub enum HistoryDepth {
    #[default]
    Last50,
    Last(usize),
    All,
}

impl HistoryDepth {
    pub fn from_str(s: &str) -> Self {
        if s.eq_ignore_ascii_case("all") {
            HistoryDepth::All
        } else if let Ok(n) = s.parse::<usize>() {
            HistoryDepth::Last(n)
        } else {
            HistoryDepth::Last(50)
        }
    }

    pub fn max_count_arg(&self) -> Option<String> {
        match self {
            HistoryDepth::Last50 => Some("--max-count=50".to_string()),
            HistoryDepth::Last(n) => Some(format!("--max-count={}", n)),
            HistoryDepth::All => None,
        }
    }
}
