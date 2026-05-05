use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize, Clone)]
pub struct CustomProvider {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub default_model: String,
    #[serde(default = "default_kind")]
    pub kind: String,
    #[serde(default)]
    pub keyless: bool,
}

fn default_kind() -> String {
    "openai_compat".to_string()
}

impl CustomProvider {
    pub fn effective_display_name(&self) -> &str {
        self.display_name
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(&self.name)
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct CustomProvidersFile {
    #[serde(default)]
    pub providers: Vec<CustomProvider>,
}

impl CustomProvidersFile {
    pub fn global_path() -> Option<PathBuf> {
        dirs::home_dir().map(|h| h.join(".zentra").join("providers.toml"))
    }

    /// Production entry point — loads from ~/.zentra/providers.toml.
    pub fn load() -> Self {
        match Self::global_path() {
            Some(p) => Self::load_from(&p),
            None => Self::default(),
        }
    }

    /// Testable entry point — loads from an arbitrary path.
    pub fn load_from(path: &Path) -> Self {
        if !path.exists() {
            return Self::default();
        }
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("⚠ {}: read error — skipping custom providers ({})", path.display(), e);
                return Self::default();
            }
        };
        let mut file: Self = match toml::from_str(&content) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("⚠ {}: parse error — skipping custom providers ({})", path.display(), e);
                return Self::default();
            }
        };
        file.providers.retain(|p| {
            let ok = !p.name.is_empty() && !p.base_url.is_empty() && !p.default_model.is_empty() && !p.kind.is_empty();
            if !ok {
                eprintln!(
                    "⚠ {}: provider '{}' missing required field — skipped",
                    path.display(), p.name
                );
            }
            ok
        });
        for p in file.providers.iter_mut() {
            if p.kind != "openai_compat" && p.kind != "anthropic" {
                eprintln!(
                    "⚠ {}: provider '{}' has unrecognized kind '{}', treating as openai_compat",
                    path.display(), p.name, p.kind
                );
                p.kind = "openai_compat".to_string();
            }
        }
        file
    }
}
