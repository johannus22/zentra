use crate::{ci::CiPlatformKind, config::ProjectConfig};
use anyhow::Result;
use std::path::Path;

/// Result of initializing a project, so callers can report what happened.
pub enum InitOutcome {
    Created { stack: String },
    Preserved,
}

pub async fn run(ci: Option<CiPlatformKind>) -> Result<()> {
    let cwd = std::env::current_dir()?;

    if !ProjectConfig::looks_like_codebase(&cwd) {
        eprint!(
            "⚠ This directory doesn't look like a project codebase. Initialize anyway? [y/N]: "
        );
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    match init_project_at(&cwd, ci)? {
        InitOutcome::Created { stack } => {
            println!("✓ Initialized .zentra/config.json (stack: {})", stack);
            println!("✓ Added .zentra/ to .gitignore");
            if let Some(platform) = ci {
                println!("✓ Added {} CI workflow", platform.as_str());
            }
            println!("  Run zentra scan to start.");
        }
        InitOutcome::Preserved => {
            println!(
                "• .zentra/config.json already exists — left unchanged \
                 (edit it, or delete it and re-run `zentra init` to reset)."
            );
            if let Some(platform) = ci {
                println!("✓ Added {} CI workflow", platform.as_str());
            }
        }
    }
    Ok(())
}

/// Initialize `.zentra/` under `root` without clobbering an existing config.
/// An existing `config.json` is preserved (F4: re-running init must never
/// silently overwrite the user's target_path/exclusions). `.gitignore` and the
/// optional CI workflow are (idempotently) written regardless.
pub fn init_project_at(root: &Path, ci: Option<CiPlatformKind>) -> Result<InitOutcome> {
    let config_path = root.join(".zentra").join("config.json");

    let outcome = if config_path.exists() {
        InitOutcome::Preserved
    } else {
        let stack = ProjectConfig::detect_stack(root);
        ProjectConfig::new(&stack, vec![]).save_to(&config_path)?;
        InitOutcome::Created { stack }
    };

    update_gitignore_at(root)?;
    if let Some(platform) = ci {
        crate::ci::generate_ci_workflow_at(root, platform)?;
    }
    Ok(outcome)
}

pub fn update_gitignore_at(root: &Path) -> Result<()> {
    let path = root.join(".gitignore");
    let entry = ".zentra/\n";
    if path.exists() {
        let content = std::fs::read_to_string(&path)?;
        if content.contains(".zentra/") {
            return Ok(());
        }
        std::fs::write(&path, format!("{}\n{}", content.trim_end(), entry))?;
    } else {
        std::fs::write(&path, entry)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // F4: re-running `init` must not clobber an existing config.json — that
    // silently discards the user's target_path and exclusions.
    #[test]
    fn init_preserves_an_existing_config() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[package]\n").unwrap();
        let cfg_path = dir.path().join(".zentra").join("config.json");
        let custom =
            r#"{"target_path":"./custom-src","stack":"rust","exclusions":["vendor/","secrets/"]}"#;
        std::fs::create_dir_all(cfg_path.parent().unwrap()).unwrap();
        std::fs::write(&cfg_path, custom).unwrap();

        let outcome = init_project_at(dir.path(), None).unwrap();
        assert!(matches!(outcome, InitOutcome::Preserved));
        assert_eq!(
            std::fs::read_to_string(&cfg_path).unwrap(),
            custom,
            "existing config must be left untouched"
        );
    }

    #[test]
    fn init_creates_config_when_absent() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[package]\n").unwrap();
        let outcome = init_project_at(dir.path(), None).unwrap();
        assert!(matches!(outcome, InitOutcome::Created { .. }));
        assert!(dir.path().join(".zentra").join("config.json").exists());
    }
}
