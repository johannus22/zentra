use crate::config::ProjectConfig;
use anyhow::Result;
use std::path::Path;

pub async fn run() -> Result<()> {
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

    let stack = ProjectConfig::detect_stack(&cwd);
    let config = ProjectConfig::new(&stack, vec![]);
    config.save_to(&ProjectConfig::default_path())?;
    update_gitignore_at(&cwd)?;

    println!("✓ Initialized .zentra/config.json (stack: {})", stack);
    println!("✓ Added .zentra/ to .gitignore");
    println!("  Run zentra scan to start.");
    Ok(())
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
