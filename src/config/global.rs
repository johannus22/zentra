use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// JSON Schema (draft-07) for `~/.zentra/config.toml`, embedded at build time and
/// written next to the config on save so editors (Even Better TOML / Taplo) can
/// validate hand-edits via the `#:schema config.schema.json` directive.
const CONFIG_SCHEMA: &str = include_str!("../../schemas/config.schema.json");

#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    #[default]
    ApiKey,
    OAuth,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct GlobalConfig {
    #[serde(default)]
    pub profiles: HashMap<String, ProviderProfile>,
    pub default_profile: Option<String>,
    /// Base directory for run artifacts (pentest reports/evidence). When unset,
    /// defaults to `<Documents>/Zentra`. Configurable via the TUI Settings screen —
    /// lets WSL users point output at a Windows path
    /// (e.g. `/mnt/c/Users/<you>/Documents/Zentra`).
    #[serde(default)]
    pub output_dir: Option<String>,
    /// Selected UI theme id (e.g. "muted_slate", "dawn", "matrix", or a custom
    /// theme file stem). `None` means the default (Muted Slate).
    #[serde(default)]
    pub theme: Option<String>,
    /// URL template for resolving CWE ids in findings. `{id}` is replaced by the
    /// numeric id (the part after "CWE-"). `None` uses [`DEFAULT_CWE_URL_TEMPLATE`].
    /// Set to an internal mirror/wiki to point CWE links there.
    #[serde(default)]
    pub cwe_url_template: Option<String>,
}

/// Resolve the global zentra directory (`~/.zentra`). Centralizes the inline
/// `home_dir().join(".zentra")` pattern used across config/keychain modules.
pub fn global_zentra_dir() -> Result<PathBuf> {
    let home =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
    Ok(home.join(".zentra"))
}

/// Default CWE reference: links to the canonical MITRE definition page.
pub const DEFAULT_CWE_URL_TEMPLATE: &str = "https://cwe.mitre.org/data/definitions/{id}.html";

/// Sampling temperature applied when a profile does not set one. A low value
/// keeps scan output stable between runs. Providers always send a value, so a
/// profile that omits the key still gets near-deterministic sampling instead of
/// the provider default (1.0 on Anthropic).
pub const DEFAULT_TEMPERATURE: f64 = 0.2;

/// Resolve a CWE id (e.g. "CWE-89" or "89") to a reference URL using `template`.
/// `{id}` in the template is replaced by the numeric id; if the template has no
/// `{id}` placeholder, the numeric id is appended.
pub fn cwe_link(cwe_id: &str, template: &str) -> String {
    let numeric = cwe_id
        .trim()
        .trim_start_matches("CWE-")
        .trim_start_matches("cwe-");
    if template.contains("{id}") {
        template.replace("{id}", numeric)
    } else {
        format!("{template}{numeric}")
    }
}

/// Expand a leading `~` / `~/` / `~\` to the user's home directory.
fn expand_tilde(path: &str) -> PathBuf {
    if path == "~" {
        if let Some(home) = dirs::home_dir() {
            return home;
        }
    }
    if let Some(rest) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(path)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProviderProfile {
    pub kind: String,
    pub base_url: String,
    pub model: String,
    #[serde(default)]
    pub keyless: bool,
    #[serde(default)]
    pub auth_method: AuthMethod,
    #[serde(default)]
    pub context_window: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<String>,
    /// Sampling temperature forwarded to the provider. `None` resolves to
    /// [`DEFAULT_TEMPERATURE`]. Read it through [`ProviderProfile::resolved_temperature`],
    /// which applies the default and clamps the range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
}

impl ProviderProfile {
    /// The temperature to send, with the default applied and the range clamped.
    /// A hand-edited config must never abort a scan, so this clamps instead of
    /// returning an error.
    pub fn resolved_temperature(&self) -> f64 {
        self.temperature
            .unwrap_or(DEFAULT_TEMPERATURE)
            .clamp(0.0, 2.0)
    }
}

impl GlobalConfig {
    pub fn load() -> Result<Self> {
        Self::load_from(&Self::default_path()?)
    }

    pub fn load_from(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&content)?)
    }

    pub fn save(&self) -> Result<()> {
        self.save_to(&Self::default_path()?)
    }

    pub fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            // Best-effort: drop the JSON Schema next to the config so a
            // `#:schema config.schema.json` directive resolves for editors
            // (Even Better TOML / Taplo) during hand-editing.
            let _ = std::fs::write(parent.join("config.schema.json"), CONFIG_SCHEMA);
        }
        let body = toml::to_string_pretty(self)?;
        crate::config::write_atomic(path, format!("#:schema config.schema.json\n\n{body}").as_bytes())?;
        Ok(())
    }

    pub fn default_path() -> Result<PathBuf> {
        let home =
            dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
        Ok(home.join(".zentra").join("config.toml"))
    }

    pub fn is_configured() -> bool {
        Self::default_path().map(|p| p.exists()).unwrap_or(false)
    }

    /// Resolve the base directory for run artifacts, falling back to the default
    /// when `output_dir` is unset or blank.
    pub fn output_base_dir(&self) -> PathBuf {
        match self
            .output_dir
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(dir) => expand_tilde(dir),
            None => Self::default_output_base_dir(),
        }
    }

    /// Default artifact base directory: `<Documents>/Zentra`, with a home-relative
    /// fallback for platforms where the document dir can't be resolved (some WSL setups).
    pub fn default_output_base_dir() -> PathBuf {
        if let Some(docs) = dirs::document_dir() {
            return docs.join("Zentra");
        }
        if let Some(home) = dirs::home_dir() {
            return home.join("Documents").join("Zentra");
        }
        PathBuf::from("Zentra")
    }
}

#[cfg(test)]
mod cwe_tests {
    use super::*;

    #[test]
    fn default_template_links_to_mitre() {
        assert_eq!(
            cwe_link("CWE-89", DEFAULT_CWE_URL_TEMPLATE),
            "https://cwe.mitre.org/data/definitions/89.html"
        );
    }

    #[test]
    fn custom_template_substitutes_id() {
        assert_eq!(
            cwe_link("CWE-89", "https://wiki.acme.com/cwe/{id}"),
            "https://wiki.acme.com/cwe/89"
        );
    }

    #[test]
    fn template_without_placeholder_appends_id() {
        assert_eq!(cwe_link("CWE-89", "https://x.test/"), "https://x.test/89");
    }

    #[test]
    fn bare_or_malformed_id_handled() {
        assert_eq!(
            cwe_link("89", DEFAULT_CWE_URL_TEMPLATE),
            "https://cwe.mitre.org/data/definitions/89.html"
        );
    }

    #[test]
    fn config_roundtrips_cwe_template() {
        let cfg = GlobalConfig {
            cwe_url_template: Some("https://wiki.acme.com/cwe/{id}".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: GlobalConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.cwe_url_template.as_deref(),
            Some("https://wiki.acme.com/cwe/{id}")
        );
    }
}
