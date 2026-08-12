use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

/// One observation posted by a scanner for later scanners to read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    /// The scanner that posted this observation (e.g. "threat_model", "sast").
    pub scanner: String,
    /// A category tag (e.g. "trust_boundary", "input_source", "auth_pattern").
    pub category: String,
    /// The observation text, kept short. Use one or two sentences.
    pub text: String,
}

/// A shared, thread-safe observation board. Scanners read observations from
/// earlier phases and post their own for later phases. It sits behind
/// `Arc<Mutex>` because Phase 2 scanners run on parallel threads. The lock is
/// never held across an await: callers clone the data out under the lock.
#[derive(Debug, Clone, Default)]
pub struct ObservationBoard {
    observations: Arc<Mutex<Vec<Observation>>>,
}

impl ObservationBoard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Read all observations posted so far. This returns a clone, so the caller
    /// can hold the value without keeping the lock alive.
    pub fn observations(&self) -> Vec<Observation> {
        self.observations
            .lock()
            .map(|o| o.clone())
            .unwrap_or_default()
    }

    /// Read observations posted by scanners other than `self_scanner`. Use
    /// this to inject cross-scanner context into a scanner's system prompt.
    pub fn from_others(&self, self_scanner: &str) -> Vec<Observation> {
        self.observations
            .lock()
            .map(|o| {
                o.iter()
                    .filter(|obs| obs.scanner != self_scanner)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Post an observation to the board.
    pub fn post(&self, observation: Observation) {
        if let Ok(mut o) = self.observations.lock() {
            o.push(observation);
        }
    }

    /// Render observations as a system-prompt section. This returns an empty
    /// string when there are no observations from other scanners.
    pub fn render_for_prompt(&self, self_scanner: &str) -> String {
        let obs = self.from_others(self_scanner);
        if obs.is_empty() {
            return String::new();
        }
        let mut out = String::from(
            "## Cross-Scanner Observations\n\n\
             Earlier scanners posted these observations. Use them to calibrate \
             your analysis and avoid false positives.\n\n",
        );
        for o in &obs {
            out.push_str(&format!(
                "- **[{} | {}]** {}\n",
                o.scanner, o.category, o.text
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(scanner: &str, category: &str, text: &str) -> Observation {
        Observation {
            scanner: scanner.to_string(),
            category: category.to_string(),
            text: text.to_string(),
        }
    }

    #[test]
    fn new_creates_empty_board() {
        let board = ObservationBoard::new();
        assert!(board.observations().is_empty());
    }

    #[test]
    fn post_adds_observation_and_observations_returns_it() {
        let board = ObservationBoard::new();
        board.post(obs("threat_model", "trust_boundary", "External boundary at API gateway."));
        let all = board.observations();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].scanner, "threat_model");
        assert_eq!(all[0].category, "trust_boundary");
        assert_eq!(all[0].text, "External boundary at API gateway.");
    }

    #[test]
    fn from_others_excludes_caller_observations() {
        let board = ObservationBoard::new();
        board.post(obs("threat_model", "trust_boundary", "Boundary one."));
        board.post(obs("sast", "input_source", "User input flows here."));
        let others = board.from_others("threat_model");
        assert_eq!(others.len(), 1);
        assert_eq!(others[0].scanner, "sast");
    }

    #[test]
    fn render_for_prompt_returns_empty_when_no_observations() {
        let board = ObservationBoard::new();
        assert_eq!(board.render_for_prompt("sast"), "");
    }

    #[test]
    fn render_for_prompt_returns_empty_when_only_self_observations() {
        let board = ObservationBoard::new();
        board.post(obs("sast", "input_source", "Self-only note."));
        assert_eq!(board.render_for_prompt("sast"), "");
    }

    #[test]
    fn render_for_prompt_includes_others_with_format() {
        let board = ObservationBoard::new();
        board.post(obs("threat_model", "trust_boundary", "External boundary at API gateway."));
        board.post(obs("sast", "input_source", "Self-only note."));
        let rendered = board.render_for_prompt("sast");
        assert!(rendered.contains("## Cross-Scanner Observations"));
        assert!(rendered.contains("[threat_model | trust_boundary]"));
        assert!(rendered.contains("External boundary at API gateway."));
        assert!(!rendered.contains("Self-only note."));
    }

    #[test]
    fn cloning_shares_underlying_data() {
        let board = ObservationBoard::new();
        let copy = board.clone();
        board.post(obs("threat_model", "trust_boundary", "Shared note."));
        assert_eq!(copy.observations().len(), 1);
        assert_eq!(copy.observations()[0].scanner, "threat_model");
    }
}
