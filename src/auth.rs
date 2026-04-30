use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: i64, // unix seconds
}

impl OAuthTokens {
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        now >= self.expires_at - 60 // 60s buffer
    }
}

const OPENAI_CLIENT_ID: &str = "app_IjGvj0Vr0Wr2LGy3BLoCX8G";
const OPENAI_AUTH_URL: &str = "https://auth.openai.com/authorize";
pub(crate) const OPENAI_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
pub(crate) const REDIRECT_PORT: u16 = 8484;

pub fn generate_pkce() -> (String, String) {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let verifier = URL_SAFE_NO_PAD.encode(bytes);
    let hash = Sha256::digest(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(hash.as_slice());
    (verifier, challenge)
}

pub fn build_auth_url(challenge: &str, state: &str) -> String {
    let redirect_uri = format!("http://localhost:{}/callback", REDIRECT_PORT);
    format!(
        "{}?client_id={}&response_type=code&code_challenge={}\
         &code_challenge_method=S256&redirect_uri={}&scope=openid%20profile%20email%20offline_access&state={}",
        OPENAI_AUTH_URL,
        OPENAI_CLIENT_ID,
        challenge,
        percent_encode(&redirect_uri),
        state,
    )
}

fn percent_encode(s: &str) -> String {
    s.chars().map(|c| match c {
        ':' => "%3A".to_string(),
        '/' => "%2F".to_string(),
        c => c.to_string(),
    }).collect()
}
