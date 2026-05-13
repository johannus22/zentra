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
