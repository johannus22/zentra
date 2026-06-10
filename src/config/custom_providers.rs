use serde::Deserialize;
use std::path::{Path, PathBuf};

use crate::config::validation::validate_provider_base_url;

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
                eprintln!(
                    "⚠ {}: read error — skipping custom providers ({})",
                    path.display(),
                    e
                );
                return Self::default();
            }
        };
        let mut file: Self = match toml::from_str(&content) {
            Ok(f) => f,
            Err(e) => {
                eprintln!(
                    "⚠ {}: parse error — skipping custom providers ({})",
                    path.display(),
                    e
                );
                return Self::default();
            }
        };
        file.providers.retain(|p| {
            let ok = !p.name.is_empty()
                && !p.base_url.is_empty()
                && !p.default_model.is_empty()
                && !p.kind.is_empty();
            if !ok {
                eprintln!(
                    "⚠ {}: provider '{}' missing required field — skipped",
                    path.display(),
                    p.name
                );
            }
            ok
        });
        for p in file.providers.iter_mut() {
            if p.kind != "openai_compat" && p.kind != "anthropic" {
                eprintln!(
                    "⚠ {}: provider '{}' has unrecognized kind '{}', treating as openai_compat",
                    path.display(),
                    p.name,
                    p.kind
                );
                p.kind = "openai_compat".to_string();
            }
        }
        // Every retained provider is openai_compat/anthropic (the loop above
        // normalizes any other kind), so all must have a valid base URL
        // (HTTPS, or http only on loopback — see validate_provider_base_url).
        file.providers
            .retain(|p| match validate_provider_base_url(&p.base_url) {
                Ok(()) => true,
                Err(e) => {
                    eprintln!(
                        "⚠ {}: provider '{}' base_url rejected ({}) — skipped",
                        path.display(),
                        p.name,
                        e
                    );
                    false
                }
            });
        file
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_from_skips_http_remote_provider() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("providers.toml");
        std::fs::write(
            &path,
            "[[providers]]\nname=\"bad\"\nbase_url=\"http://evil.example\"\ndefault_model=\"m\"\nkind=\"openai_compat\"\n",
        )
        .unwrap();
        let file = CustomProvidersFile::load_from(&path);
        assert!(file.providers.is_empty(), "http remote should be skipped");
    }

    #[test]
    fn load_from_normalizes_unknown_kind_then_validates_url() {
        // A non-openai_compat/anthropic kind is normalized to openai_compat by the
        // loop above; a valid https URL then keeps it. This pins the
        // normalize-then-validate invariant the URL-retain relies on.
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("providers.toml");
        std::fs::write(
            &path,
            "[[providers]]\nname=\"local\"\nbase_url=\"https://example.test\"\ndefault_model=\"m\"\nkind=\"claude_cli\"\n",
        )
        .unwrap();
        let file = CustomProvidersFile::load_from(&path);
        assert_eq!(file.providers.len(), 1);
        assert_eq!(file.providers[0].kind, "openai_compat");
    }
}
