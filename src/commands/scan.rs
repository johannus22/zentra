use anyhow::{Context, Result};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::agent::{orchestrator::OrchestratorAgent, ScanEvent, ScannerType};
use crate::config::{keychain, GlobalConfig, ProjectConfig};
use crate::provider::{anthropic::AnthropicProvider, openai_compat::OpenAICompatProvider, LLMProvider};
use crate::state::StateWriter;
use crate::tools::ToolRegistry;

pub async fn run(provider_override: Option<String>, only: Option<String>) -> Result<()> {
    let global = GlobalConfig::load()?;
    let profile_name = provider_override
        .or_else(|| global.default_profile.clone())
        .ok_or_else(|| anyhow::anyhow!(
            "No provider configured. Run 'zentra config setup' first."
        ))?;

    let profile = global.profiles.get(&profile_name)
        .ok_or_else(|| anyhow::anyhow!("Profile '{}' not found", profile_name))?
        .clone();

    let api_key = keychain::get_key(&profile_name)?.unwrap_or_default();

    let provider: Arc<dyn LLMProvider> = match profile.kind.as_str() {
        "anthropic" => Arc::new(AnthropicProvider::new(
            profile.base_url, profile.model, api_key,
        )),
        _ => Arc::new(OpenAICompatProvider::new(
            profile.base_url, profile.model, api_key,
        )),
    };

    let project_config = ProjectConfig::load_from(&ProjectConfig::default_path())
        .context("No project config found. Run 'zentra init' first.")?;

    let state_writer = Arc::new(
        StateWriter::new(Path::new(&project_config.target_path))
            .context("Failed to initialize .zentra/ directory")?
    );
    let tool_registry = Arc::new(ToolRegistry::new());

    let scanners = resolve_scanners(only.as_deref());

    let (tx, mut rx) = mpsc::channel(128);

    // Print events to console (TUI replaces this in Plan 3)
    let print_task = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event {
                ScanEvent::ScannerStarted(s) => println!("  \u{27F3} {:?} starting...", s),
                ScanEvent::ScannerCompleted(s) => println!("  \u{2713} {:?} complete", s),
                ScanEvent::FindingAdded(f) => {
                    println!("  [{:?}] {} \u{2014} {}", f.severity, f.title,
                        f.location.as_deref().unwrap_or(""));
                }
                ScanEvent::ToolCall { tool, arg, .. } => {
                    if !arg.is_empty() {
                        println!("    \u{2192} {}({})", tool, arg);
                    } else {
                        println!("    \u{2192} {}", tool);
                    }
                }
                ScanEvent::Error { scanner, message } => {
                    eprintln!("  \u{2717} {:?}: {}", scanner, message);
                }
            }
        }
    });

    let orchestrator = OrchestratorAgent::new(provider, tool_registry, state_writer, tx);
    orchestrator.run(&scanners).await?;

    print_task.await.ok();
    println!("\n\u{2713} Scan complete. Findings in .zentra/");
    Ok(())
}

fn resolve_scanners(only: Option<&str>) -> Vec<ScannerType> {
    match only {
        Some("threat-model") => vec![ScannerType::ThreatModel, ScannerType::Report],
        Some("sast") => vec![ScannerType::Sast, ScannerType::Report],
        Some("supply-chain") => vec![ScannerType::SupplyChain, ScannerType::Report],
        Some("api") => vec![ScannerType::ApiScan, ScannerType::Report],
        Some("iac") => vec![ScannerType::IacScan, ScannerType::Report],
        Some("report") => vec![ScannerType::Report],
        _ => vec![
            ScannerType::ThreatModel,
            ScannerType::Sast,
            ScannerType::SupplyChain,
            ScannerType::ApiScan,
            ScannerType::IacScan,
            ScannerType::Report,
        ],
    }
}
