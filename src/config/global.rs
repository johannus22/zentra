use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

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
}

/// Resolve the global zentra directory (`~/.zentra`). Centralizes the inline
/// `home_dir().join(".zentra")` pattern used across config/keychain modules.
pub fn global_zentra_dir() -> Result<PathBuf> {
    let home =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
    Ok(home.join(".zentra"))
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
        }
        std::fs::write(path, toml::to_string_pretty(self)?)?;
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
