use anyhow::Context;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;

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
const OAUTH_CALLBACK_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthProgress {
    OpeningBrowser,
    WaitingForCallback,
    ExchangingCode,
}

#[derive(Debug, Clone)]
pub struct OAuthSession {
    verifier: String,
    state: String,
    auth_url: String,
}

impl OAuthSession {
    pub fn start() -> Self {
        let (verifier, challenge) = generate_pkce();
        let mut state_bytes = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut state_bytes);
        let state = URL_SAFE_NO_PAD.encode(state_bytes);
        let auth_url = build_auth_url(&challenge, &state);

        Self {
            verifier,
            state,
            auth_url,
        }
    }

    pub fn auth_url(&self) -> &str {
        &self.auth_url
    }

    pub async fn wait_for_code(&self, timeout: Duration) -> anyhow::Result<String> {
        wait_for_callback_with_state_and_timeout(&self.state, timeout).await
    }

    pub async fn exchange_code(&self, code: &str) -> anyhow::Result<OAuthTokens> {
        exchange_code(code, &self.verifier).await
    }
}

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
    s.chars()
        .map(|c| match c {
            ':' => "%3A".to_string(),
            '/' => "%2F".to_string(),
            c => c.to_string(),
        })
        .collect()
}

pub fn token_endpoint_url(raw: &str) -> String {
    let trimmed = raw.trim_end_matches('/');
    if trimmed.ends_with("/oauth/token") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/oauth/token")
    }
}

fn decode_query_value(value: &str) -> anyhow::Result<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3])
                    .context("OAuth callback contained invalid percent-encoding")?;
                let byte = u8::from_str_radix(hex, 16)
                    .context("OAuth callback contained invalid percent-encoding")?;
                out.push(byte);
                i += 3;
            }
            b'%' => {
                return Err(anyhow::anyhow!(
                    "OAuth callback contained invalid percent-encoding"
                ));
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }

    String::from_utf8(out).context("OAuth callback contained invalid UTF-8")
}

pub fn parse_callback_path(path: &str, expected_state: &str) -> anyhow::Result<String> {
    let query = path
        .split_once('?')
        .map(|(_, query)| query)
        .ok_or_else(|| anyhow::anyhow!("OAuth callback missing query parameters"))?;

    let mut code = None;
    let mut state = None;
    let mut error = None;
    let mut error_description = None;

    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = decode_query_value(value)?;
        match key {
            "code" => code = Some(value),
            "state" => state = Some(value),
            "error" => error = Some(value),
            "error_description" => error_description = Some(value),
            _ => {}
        }
    }

    if let Some(error) = error {
        if let Some(description) = error_description.filter(|description| !description.is_empty()) {
            return Err(anyhow::anyhow!(
                "OAuth callback returned error '{}': {}",
                error,
                description
            ));
        }
        return Err(anyhow::anyhow!("OAuth callback returned error '{}'", error));
    }

    let actual_state =
        state.ok_or_else(|| anyhow::anyhow!("OAuth callback missing 'state' parameter"))?;
    if actual_state != expected_state {
        return Err(anyhow::anyhow!("OAuth callback state mismatch"));
    }

    code.ok_or_else(|| anyhow::anyhow!("OAuth callback missing 'code' parameter"))
}

pub fn parse_token_response(json: &serde_json::Value) -> anyhow::Result<OAuthTokens> {
    let access_token = json["access_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing access_token in token response"))?
        .to_string();
    let refresh_token = json["refresh_token"].as_str().unwrap_or("").to_string();
    let expires_in = json["expires_in"].as_i64().unwrap_or(3600);
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
        + expires_in;
    Ok(OAuthTokens {
        access_token,
        refresh_token,
        expires_at,
    })
}

pub async fn exchange_code_with_url(
    code: &str,
    verifier: &str,
    token_url: &str,
) -> anyhow::Result<OAuthTokens> {
    let redirect_uri = format!("http://localhost:{}/callback", REDIRECT_PORT);
    let url = token_endpoint_url(token_url);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let resp = client
        .post(&url)
        .form(&[
            ("client_id", OPENAI_CLIENT_ID),
            ("grant_type", "authorization_code"),
            ("code", code),
            ("code_verifier", verifier),
            ("redirect_uri", &redirect_uri as &str),
        ])
        .send()
        .await
        .context("Token exchange request failed")?;

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Token exchange failed: {}", text));
    }
    parse_token_response(&resp.json::<serde_json::Value>().await?)
}

pub async fn exchange_code(code: &str, verifier: &str) -> anyhow::Result<OAuthTokens> {
    exchange_code_with_url(code, verifier, OPENAI_TOKEN_URL).await
}

pub async fn refresh_access_token_with_url(
    refresh_token: &str,
    token_url: &str,
) -> anyhow::Result<OAuthTokens> {
    let url = token_endpoint_url(token_url);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let resp = client
        .post(&url)
        .form(&[
            ("client_id", OPENAI_CLIENT_ID),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ])
        .send()
        .await
        .context("Token refresh request failed")?;

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Token refresh failed: {}", text));
    }
    parse_token_response(&resp.json::<serde_json::Value>().await?)
}

pub async fn refresh_access_token(refresh_token: &str) -> anyhow::Result<OAuthTokens> {
    refresh_access_token_with_url(refresh_token, OPENAI_TOKEN_URL).await
}

pub async fn run_oauth_flow() -> anyhow::Result<OAuthTokens> {
    let session = OAuthSession::start();
    println!("\nOpening browser for OpenAI login...");
    println!(
        "If the browser doesn't open automatically, visit:\n  {}\n",
        session.auth_url()
    );

    open::that(session.auth_url()).context("Failed to launch browser")?;
    println!("Waiting for authentication (complete login in your browser)...");

    let code = session.wait_for_code(OAUTH_CALLBACK_TIMEOUT).await?;
    println!("✓ Received authorization code, exchanging for tokens...");

    let tokens = session.exchange_code(&code).await?;
    println!("✓ Authentication successful");
    Ok(tokens)
}

pub async fn ensure_fresh_token(profile_name: &str) -> anyhow::Result<String> {
    use crate::config::keychain;

    let tokens = keychain::get_oauth_tokens(profile_name)?.ok_or_else(|| {
        anyhow::anyhow!(
            "No OAuth tokens found for profile '{}'. Run 'zentra config setup' to re-authenticate.",
            profile_name
        )
    })?;

    if tokens.is_expired() {
        if tokens.refresh_token.is_empty() {
            return Err(anyhow::anyhow!(
                "OAuth session expired and no refresh token available. \
                 Run 'zentra config setup' to re-authenticate."
            ));
        }
        let new_tokens = refresh_access_token(&tokens.refresh_token).await?;
        keychain::set_oauth_tokens(profile_name, &new_tokens)?;
        return Ok(new_tokens.access_token);
    }

    Ok(tokens.access_token)
}

pub async fn wait_for_callback(expected_state: &str) -> anyhow::Result<String> {
    wait_for_callback_with_state_and_timeout(expected_state, OAUTH_CALLBACK_TIMEOUT).await
}

pub async fn wait_for_callback_with_state_and_timeout(
    expected_state: &str,
    timeout: Duration,
) -> anyhow::Result<String> {
    match tokio::time::timeout(timeout, wait_for_callback_once(expected_state)).await {
        Ok(result) => result,
        Err(_) => Err(anyhow::anyhow!(
            "OAuth callback timed out after {} seconds",
            timeout.as_secs_f64()
        )),
    }
}

async fn wait_for_callback_once(expected_state: &str) -> anyhow::Result<String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind(format!("127.0.0.1:{}", REDIRECT_PORT))
        .await
        .context("Failed to bind callback port — is port 8484 already in use?")?;

    let (stream, _) = listener
        .accept()
        .await
        .context("Failed to accept OAuth callback connection")?;

    let (reader_half, mut writer_half) = stream.into_split();
    let mut reader = BufReader::new(reader_half);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;

    let path = request_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("OAuth callback missing request path"))?;
    let code = parse_callback_path(path, expected_state)?;

    let body =
        "<html><body><h2>&#10003; Authenticated. Return to your terminal.</h2></body></html>";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    writer_half.write_all(response.as_bytes()).await?;

    Ok(code)
}
