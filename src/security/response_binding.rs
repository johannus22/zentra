use anyhow::{bail, Result};
use rand::RngCore;
use std::collections::{HashMap, HashSet};
use std::time::Instant;

struct NonceBinding {
    nonce: String,
    issued_at: Instant,
    max_age_secs: u64,
}

pub struct ResponseBindingVerifier {
    pending: HashMap<u64, NonceBinding>,
    used: HashSet<String>,
    max_age_secs: u64,
    enabled: bool,
}

impl ResponseBindingVerifier {
    pub fn new(max_age_secs: u64, enabled: bool) -> Self {
        Self {
            pending: HashMap::new(),
            used: HashSet::new(),
            max_age_secs,
            enabled,
        }
    }

    /// Generate a nonce, store it keyed by request_id, and return it.
    pub fn issue_nonce(&mut self, request_id: u64) -> String {
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        let nonce: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        self.pending.insert(
            request_id,
            NonceBinding {
                nonce: nonce.clone(),
                issued_at: Instant::now(),
                max_age_secs: self.max_age_secs,
            },
        );
        nonce
    }

    /// Check that the response contains the expected nonce and hasn't expired or been replayed.
    pub fn verify(&mut self, request_id: u64, response_content: &str) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let binding = self
            .pending
            .remove(&request_id)
            .ok_or_else(|| anyhow::anyhow!("Unknown request_id: {}", request_id))?;

        if binding.issued_at.elapsed().as_secs() > binding.max_age_secs {
            bail!(
                "Response arrived after {}s max-age window",
                binding.max_age_secs
            );
        }
        if self.used.contains(&binding.nonce) {
            bail!("Nonce already consumed (replay detected)");
        }
        if !response_content.contains(&binding.nonce) {
            bail!("Response missing expected ZENTRA-NONCE echo");
        }
        self.used.insert(binding.nonce);
        Ok(())
    }
}

/// Append the nonce sentinel to the system prompt so the LLM echoes it.
pub fn inject_into_system(nonce: &str, system: &str) -> String {
    format!(
        "{}\n\nZENTRA-NONCE: {} \
        (include this exact token verbatim somewhere in your response)",
        system, nonce
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echoed_nonce_verifies() {
        let mut v = ResponseBindingVerifier::new(120, true);
        let nonce = v.issue_nonce(1);
        let response = format!("Here is my analysis. {} done.", nonce);
        assert!(v.verify(1, &response).is_ok());
    }

    #[test]
    fn missing_nonce_is_rejected() {
        let mut v = ResponseBindingVerifier::new(120, true);
        let _ = v.issue_nonce(1);
        assert!(v.verify(1, "a tampered response with no nonce").is_err());
    }

    #[test]
    fn replayed_nonce_is_rejected() {
        let mut v = ResponseBindingVerifier::new(120, true);
        let nonce = v.issue_nonce(1);
        let response = format!("ok {}", nonce);
        assert!(v.verify(1, &response).is_ok());
        // Re-issue and try to reuse the same captured nonce on a new request.
        let _ = v.issue_nonce(2);
        let replay = format!("ok {}", nonce);
        assert!(v.verify(2, &replay).is_err());
    }

    #[test]
    fn expired_response_is_rejected() {
        let mut v = ResponseBindingVerifier::new(0, true);
        let nonce = v.issue_nonce(1);
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let response = format!("ok {}", nonce);
        assert!(v.verify(1, &response).is_err());
    }

    #[test]
    fn disabled_verifier_passes_through() {
        let mut v = ResponseBindingVerifier::new(120, false);
        let _ = v.issue_nonce(1);
        assert!(v.verify(1, "no nonce here").is_ok());
    }
}
