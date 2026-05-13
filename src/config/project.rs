use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const CODEBASE_SIGNALS: &[&str] = &[
    "Cargo.toml",
    "package.json",
    "go.mod",
    "requirements.txt",
    "pom.xml",
    "pyproject.toml",
    "build.gradle",
];
const SOURCE_DIRS: &[&str] = &["src", "lib", "app"];

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProjectConfig {
    pub target_path: String,
    pub stack: String,
    pub exclusions: Vec<String>,
}

impl ProjectConfig {
    pub fn new(stack: &str, exclusions: Vec<String>) -> Self {
        Self {
            target_path: ".".to_string(),
            stack: stack.to_string(),
            exclusions,
        }
    }

    pub fn load_from(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&content)?)
    }

    pub fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn default_path() -> PathBuf {
        PathBuf::from(".zentra").join("config.json")
    }

    pub fn exists() -> bool {
        Self::default_path().exists()
    }

    pub fn detect_stack(root: &Path) -> String {
        if root.join("Cargo.toml").exists() {
            return "rust".to_string();
        }
        if root.join("package.json").exists() {
            return "node".to_string();
        }
        if root.join("go.mod").exists() {
            return "go".to_string();
        }
        if root.join("requirements.txt").exists() || root.join("pyproject.toml").exists() {
            return "python".to_string();
        }
        if root.join("pom.xml").exists() || root.join("build.gradle").exists() {
            return "java".to_string();
        }
        "unknown".to_string()
    }

    pub fn looks_like_codebase(root: &Path) -> bool {
        CODEBASE_SIGNALS.iter().any(|s| root.join(s).exists())
            || SOURCE_DIRS.iter().any(|d| root.join(d).is_dir())
            || root.join(".git").exists()
    }
}
