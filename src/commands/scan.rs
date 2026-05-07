use anyhow::{Context, Result};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::agent::{orchestrator::OrchestratorAgent, ScannerType};
use crate::config::{keychain, GlobalConfig, ProjectConfig};
use crate::provider::{anthropic::AnthropicProvider, openai_compat::OpenAICompatProvider, LLMProvider};
use crate::scanners::secrets::HistoryDepth;
use crate::state::StateWriter;
use crate::tools::ToolRegistry;
use crate::tui::{scan_ui::run_scan_ui, ScanOutcome};
use crate::wizard;

pub async fn run(
    provider_override: Option<String>,
    only: Option<String>,
    depth_str: String,
) -> Result<()> {
    let depth = HistoryDepth::from_str(&depth_str);
    let scanners = resolve_scanners(only.as_deref());
    let mut provider_override = provider_override;
    loop {
        match run_once(provider_override.clone(), scanners.clone(), depth.clone()).await? {
            ScanOutcome::Completed | ScanOutcome::Aborted => break,
            ScanOutcome::Reconfigure => {
                wizard::run_setup(None).await?;
            }
            ScanOutcome::ChangeProvider(name) => {
                provider_override = Some(name);
            }
            ScanOutcome::ExitApp => std::process::exit(0),
        }
    }
    Ok(())
}

pub async fn run_with_scanners(scanners: Vec<ScannerType>) -> Result<()> {
    let depth = HistoryDepth::default();
    let mut provider_override: Option<String> = None;
    loop {
        match run_once(provider_override.clone(), scanners.clone(), depth.clone()).await? {
            ScanOutcome::Completed | ScanOutcome::Aborted => break,
            ScanOutcome::Reconfigure => {
                wizard::run_setup(None).await?;
            }
            ScanOutcome::ChangeProvider(name) => {
                provider_override = Some(name);
            }
            ScanOutcome::ExitApp => std::process::exit(0),
        }
    }
    Ok(())
}

async fn run_once(
    provider_override: Option<String>,
    scanners: Vec<ScannerType>,
    depth: HistoryDepth,
) -> Result<ScanOutcome> {
    let global = GlobalConfig::load()?;
    let profile_name = provider_override
        .or_else(|| global.default_profile.clone())
        .ok_or_else(|| anyhow::anyhow!(
            "No provider configured. Run 'zentra config setup' first."
        ))?;

    let profile = global.profiles.get(&profile_name)
        .ok_or_else(|| anyhow::anyhow!("Profile '{}' not found", profile_name))?
        .clone();

    let api_key = match profile.auth_method {
        crate::config::AuthMethod::OAuth => {
            crate::auth::ensure_fresh_token(&profile_name).await?
        }
        crate::config::AuthMethod::ApiKey => {
            if profile.keyless {
                keychain::get_key(&profile_name)?.unwrap_or_default()
            } else {
                keychain::get_key(&profile_name)?.ok_or_else(|| anyhow::anyhow!(
                    "No API key found for profile '{}'. Run 'zentra config setup' to configure it.",
                    profile_name
                ))?
            }
        }
    };

    let provider: Arc<dyn LLMProvider> = match profile.kind.as_str() {
        "anthropic" => Arc::new(AnthropicProvider::new(
            profile.base_url.clone(), profile.model.clone(), api_key,
        )),
        _ => Arc::new(OpenAICompatProvider::new(
            profile.base_url.clone(), profile.model.clone(), api_key,
        )),
    };

    let project_config = ProjectConfig::load_from(&ProjectConfig::default_path())
        .context("No project config found. Run 'zentra init' first.")?;

    let state_writer = Arc::new(
        StateWriter::new(Path::new(&project_config.target_path))
            .context("Failed to initialize .zentra/ directory")?
    );
    let tool_registry = Arc::new(ToolRegistry::new());

    let context_window = profile.context_window.unwrap_or(256_000);
    let model_info = format!("{} · {}", profile.model, profile_name);
    let branch = current_branch();
    let profiles: Vec<String> = global.profiles.keys().cloned().collect();

    // FrameworkAnalysis runs only when .zentra/architecture.md doesn't exist yet.
    // On subsequent scans the cached file is read and injected by the orchestrator.
    let mut scanners_with_framework = scanners.clone();
    if !scanners_with_framework.contains(&ScannerType::FrameworkAnalysis)
        && !state_writer.architecture_exists()
    {
        scanners_with_framework.insert(0, ScannerType::FrameworkAnalysis);
    }

    let (tx, rx) = mpsc::channel(128);
    let scanners_for_agent = scanners_with_framework.clone();

    let scan_task = tokio::spawn(async move {
        OrchestratorAgent::new(provider, tool_registry, state_writer, tx, depth)
            .run(&scanners_for_agent)
            .await
    });

    let abort_handle = scan_task.abort_handle();
    let outcome = run_scan_ui(
        rx, scanners_with_framework, model_info, context_window, abort_handle, profiles, branch, String::new(),
    ).await?;

    match outcome {
        ScanOutcome::Completed => {
            scan_task.await??;
            println!("\n✓ Scan complete. Findings in .zentra/");
        }
        _ => {
            scan_task.abort();
        }
    }

    Ok(outcome)
}

fn resolve_scanners(only: Option<&str>) -> Vec<ScannerType> {
    match only {
        Some("threat-model") => vec![ScannerType::ThreatModel, ScannerType::Report],
        Some("sast") => vec![ScannerType::Sast, ScannerType::Report],
        Some("supply-chain") => vec![ScannerType::SupplyChain, ScannerType::Report],
        Some("api") => vec![ScannerType::ApiScan, ScannerType::Report],
        Some("iac") => vec![ScannerType::IacScan, ScannerType::Report],
        Some("secrets") => vec![ScannerType::SecretsScan],
        Some("report") => vec![ScannerType::Report],
        _ => vec![
            ScannerType::ThreatModel,
            ScannerType::Sast,
            ScannerType::SupplyChain,
            ScannerType::ApiScan,
            ScannerType::IacScan,
            ScannerType::SecretsScan,
            ScannerType::Report,
        ],
    }
}

fn current_branch() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "detached".to_string())
}
