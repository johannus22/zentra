use anyhow::{bail, Result};
use reqwest::Url;

pub fn validate_provider_base_url(raw: &str) -> Result<()> {
    if raw.trim().is_empty() {
        bail!("provider base URL cannot be empty");
    }

    let url = Url::parse(raw)?;

    match url.scheme() {
        "https" => Ok(()),
        "http" => match url.host_str() {
            Some(host) if is_http_loopback_host(host) => Ok(()),
            Some(_) => bail!("provider base URL must use https for remote hosts"),
            None => bail!("provider base URL must include a host"),
        },
        _ => bail!("provider base URL must use http or https"),
    }
}

fn is_http_loopback_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1"
}

/// Validate the endpoint of a profile at the point it is used to build a provider.
///
/// `validate_provider_base_url` previously ran only at config-write time (wizard /
/// TUI). Nothing re-checked it when a profile was loaded from `~/.zentra/config.toml`
/// or synthesized from `ZENTRA_PROVIDER_*` env vars in CI, so a hand-edited,
/// migrated, or attacker-set `base_url` could send the API key to an arbitrary
/// host or over cleartext http. Call this on the load/use path. CLI providers
/// (`claude_cli` / `codex_cli`) keep a binary name/path in `base_url`, not a URL,
/// so they are exempt.
pub fn validate_profile_endpoint(kind: &str, base_url: &str) -> Result<()> {
    if matches!(kind, "claude_cli" | "codex_cli") {
        return Ok(());
    }
    validate_provider_base_url(base_url)
}
