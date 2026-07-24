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
        // Atomic write so an interrupted save can't corrupt the config (F15) —
        // a corrupt project config is now a hard error (see load_or_init_for_run).
        crate::config::write_atomic(path, serde_json::to_string_pretty(self)?.as_bytes())?;
        Ok(())
    }

    /// Load the project config for a scan/CI run, or create a default when none
    /// exists yet. Returns `(config, created)` where `created` is true only when
    /// a fresh default was written (the caller then updates .gitignore / prints).
    ///
    /// A file that EXISTS but fails to parse is a hard error and is left
    /// untouched — we must never silently replace the user's `target_path` and
    /// `exclusions` with defaults. Dropped exclusions would also pull
    /// deliberately-excluded (possibly secret) files into the scan.
    pub fn load_or_init_for_run(path: &Path, detect_root: &Path) -> Result<(Self, bool)> {
        if path.exists() {
            let cfg = Self::load_from(path).map_err(|e| {
                anyhow::anyhow!(
                    "{} exists but could not be parsed ({e}). \
                     Fix the JSON or delete the file to regenerate it.",
                    path.display()
                )
            })?;
            Ok((cfg, false))
        } else {
            let stack = Self::detect_stack(detect_root);
            let cfg = Self::new(&stack, vec![]);
            cfg.save_to(path)?;
            Ok((cfg, true))
        }
    }

    /// Resolve `target_path` against `repo_root`, rejecting anything that escapes
    /// the repo. In CI the `.zentra/config.json` is supplied by an untrusted PR
    /// and `target_path` selects both the scan root and the `.zentra/` output
    /// directory; an absolute path or a `..` component would let the PR redirect
    /// where `zentra ci` writes findings and the audit log. Only plain relative
    /// subpaths (optionally `.`-prefixed) are allowed.
    pub fn resolve_target_within(&self, repo_root: &Path) -> Result<PathBuf> {
        use std::path::Component;
        let rel = Path::new(&self.target_path);
        // Note: on Windows a unix-style "/etc" reports is_absolute()==false, so we
        // reject via the component scan below rather than relying on is_absolute.
        for comp in rel.components() {
            match comp {
                Component::ParentDir => anyhow::bail!(
                    "target_path must not contain '..' (would escape the repo): {}",
                    self.target_path
                ),
                Component::RootDir | Component::Prefix(_) => anyhow::bail!(
                    "target_path must be relative to the repo, got: {}",
                    self.target_path
                ),
                Component::CurDir | Component::Normal(_) => {}
            }
        }
        Ok(repo_root.join(rel))
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
