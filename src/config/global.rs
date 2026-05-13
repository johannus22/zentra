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
}
