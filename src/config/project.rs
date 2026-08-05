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
    /// Minimum severity that fails `zentra ci` (blocks the PR/MR): one of
    /// critical/high/medium/low/info, case-insensitive. `None` — including
    /// every config written before this field existed — means the default,
    /// High (blocks High and Critical findings). `ZENTRA_CI_FAIL_THRESHOLD`
    /// overrides this at CI runtime; see `ci::resolve_fail_threshold`.
    #[serde(default)]
    pub fail_threshold: Option<String>,
}

impl ProjectConfig {
    pub fn new(stack: &str, exclusions: Vec<String>) -> Self {
        Self {
            target_path: ".".to_string(),
            stack: stack.to_string(),
            exclusions,
            fail_threshold: None,
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

        // The config is untrusted PR content; an attacker doesn't know or care
        // which OS the CI runner uses, so both escape syntaxes must be rejected
        // regardless of host platform. `Path::components()` only recognizes the
        // *native* separator/prefix syntax — e.g. a Windows drive prefix like
        // "C:" is just an ordinary character on Unix's parser, and "\" isn't a
        // separator there either — so scan the raw string for the other
        // platform's escape syntax first.
        let raw = self.target_path.as_str();
        if raw.starts_with('/') || raw.starts_with('\\') {
            anyhow::bail!("target_path must be relative to the repo, got: {raw}");
        }
        let bytes = raw.as_bytes();
        if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
            anyhow::bail!("target_path must be relative to the repo, got: {raw}");
        }
        if raw.split(['/', '\\']).any(|segment| segment == "..") {
            anyhow::bail!("target_path must not contain '..' (would escape the repo): {raw}");
        }

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
