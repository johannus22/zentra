use anyhow::{Context, Result};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::agent::{orchestrator::OrchestratorAgent, ScannerType};
use crate::config::{keychain, GlobalConfig, ProjectConfig};
use crate::provider::{
    anthropic::AnthropicProvider,
    cli::{CliKind, CliProvider},
    openai_compat::OpenAICompatProvider,
    LLMProvider,
};
use crate::security::{self, AuditEvent, AuditLog, SecurityConfig, SecurityContext};
use crate::state::StateWriter;
use crate::tools::ToolRegistry;
use crate::tui::{scan_ui::run_scan_ui, ScanOutcome};
use crate::wizard;
use tokio_util::sync::CancellationToken;

pub async fn run(provider_override: Option<String>, only: Option<String>) -> Result<()> {
    let scanners = resolve_scanners(only.as_deref());
    let mut provider_override = provider_override;
    loop {
        match run_once(provider_override.clone(), scanners.clone()).await? {
            ScanOutcome::Completed | ScanOutcome::Aborted | ScanOutcome::BackToMenu => break,
            ScanOutcome::Reconfigure => {
                wizard::run_setup(None).await?;
            }
            ScanOutcome::ChangeProvider(name) => {
                provider_override = Some(name);
            }
        }
    }
    Ok(())
}

pub async fn run_with_scanners(scanners: Vec<ScannerType>) -> Result<()> {
    let mut provider_override: Option<String> = None;
    loop {
        match run_once(provider_override.clone(), scanners.clone()).await? {
            ScanOutcome::Completed | ScanOutcome::Aborted | ScanOutcome::BackToMenu => break,
            ScanOutcome::Reconfigure => {
                wizard::run_setup(None).await?;
            }
            ScanOutcome::ChangeProvider(name) => {
                provider_override = Some(name);
            }
        }
    }
    Ok(())
}

async fn run_once(
    provider_override: Option<String>,
    scanners: Vec<ScannerType>,
) -> Result<ScanOutcome> {
    let global = GlobalConfig::load()?;
    let profile_name = provider_override
        .or_else(|| global.default_profile.clone())
        .ok_or_else(|| {
            anyhow::anyhow!("No provider configured. Run 'zentra config setup' first.")
        })?;

    let profile = global
        .profiles
        .get(&profile_name)
        .ok_or_else(|| anyhow::anyhow!("Profile '{}' not found", profile_name))?
        .clone();

    ensure_supported_scan_auth(&profile_name, &profile)?;

    let api_key = match profile.auth_method {
        crate::config::AuthMethod::OAuth => crate::auth::ensure_fresh_token(&profile_name).await?,
        crate::config::AuthMethod::ApiKey => {
            if profile.keyless {
                keychain::get_key(&profile_name)?.unwrap_or_default()
            } else {
                keychain::get_key(&profile_name)?.ok_or_else(|| {
                    anyhow::anyhow!(
                    "No API key found for profile '{}'. Run 'zentra config setup' to configure it.",
                    profile_name
                )
                })?
            }
        }
    };

    // For CLI providers, verify the binary is reachable before starting the TUI
    if profile.kind == "claude_cli" || profile.kind == "codex_cli" {
        let binary = resolve_cli_binary(&profile.kind, &profile.base_url);
        validate_cli_binary(&binary)?;
        if which::which(&binary).is_err() {
            anyhow::bail!(
                "CLI provider '{}' requires '{}' on PATH.\n\
                 Install it and try again, or run 'zentra config use <other-profile>'.",
                profile_name,
                binary
            );
        }
    }

    let (tx, rx) = mpsc::channel(128);

    let provider: Arc<dyn LLMProvider> = match profile.kind.as_str() {
        "anthropic" => Arc::new(AnthropicProvider::new(
            profile.base_url.clone(),
            profile.model.clone(),
            api_key,
        )),
        "claude_cli" => Arc::new(CliProvider::new(
            CliKind::Claude,
            resolve_cli_binary(&profile.kind, &profile.base_url),
            profile.model.clone(),
        )),
        "codex_cli" => Arc::new(
            CliProvider::new(
                CliKind::Codex,
                resolve_cli_binary(&profile.kind, &profile.base_url),
                profile.model.clone(),
            )
            .with_event_channel(tx.clone()),
        ),
        _ => Arc::new(
            OpenAICompatProvider::new(
                profile.base_url.clone(),
                profile.model.clone(),
                api_key,
            )
            .with_reasoning(profile.reasoning_effort.clone())
            .with_context_window(profile.context_window),
        ),
    };

    let project_config = if ProjectConfig::exists() {
        match ProjectConfig::load_from(&ProjectConfig::default_path()) {
            Ok(cfg) => cfg,
            Err(_) => {
                let cwd = std::env::current_dir()?;
                let stack = ProjectConfig::detect_stack(&cwd);
                let cfg = ProjectConfig::new(&stack, vec![]);
                cfg.save_to(&ProjectConfig::default_path())?;
                println!("⚠ Recreated .zentra/config.json (previous file was unreadable)");
                cfg
            }
        }
    } else {
        let cwd = std::env::current_dir()?;
        let stack = ProjectConfig::detect_stack(&cwd);
        let config = ProjectConfig::new(&stack, vec![]);
        config.save_to(&ProjectConfig::default_path())?;
        crate::commands::init::update_gitignore_at(&cwd)?;
        println!("✓ Auto-initialized .zentra/ (stack: {})", stack);
        config
    };

    let state_writer = Arc::new(
        StateWriter::new(Path::new(&project_config.target_path))
            .context("Failed to initialize .zentra/ directory")?,
    );
    let tool_registry = Arc::new(ToolRegistry::new());

    // Security envelope: tamper-evident audit log, response binding, tool gate,
    // and prompt-injection guard. Defaults are balanced; override with
    // ZENTRA_SECURITY=off (disable) or ZENTRA_SECURITY=hardened (strictest).
    let security_config = SecurityConfig::load();
    let session_id = security::new_session_id();
    let zentra_dir = Path::new(&project_config.target_path).join(".zentra");
    let mut audit = AuditLog::new(&zentra_dir, &session_id, security_config.audit_log)
        .context("Failed to open security audit log")?;
    audit
        .record(AuditEvent::SessionStart {
            provider_kind: profile.kind.clone(),
            model: profile.model.clone(),
            scanner: "orchestrator".to_string(),
        })
        .ok();
    let security_ctx = SecurityContext::new(security_config, audit);
    let provider = security::GuardedProvider::wrap(provider, &security_ctx);

    let context_window = profile.context_window.unwrap_or(256_000);
    let model_info = format!("{} · {}", profile.model, profile_name);
    let provider_kind = profile.kind.clone();
    let branch = current_branch();
    let project_name = current_project_name();
    let profiles: Vec<String> = global.profiles.keys().cloned().collect();

    // FrameworkAnalysis runs only when .zentra/architecture.md doesn't exist yet.
    // On subsequent scans the cached file is read and injected by the orchestrator.
    let mut scanners_with_framework = scanners.clone();
    if !scanners_with_framework.contains(&ScannerType::FrameworkAnalysis)
        && !state_writer.architecture_exists()
    {
        scanners_with_framework.insert(0, ScannerType::FrameworkAnalysis);
    }

    let scanners_for_agent = scanners_with_framework.clone();

    let cancel_token = CancellationToken::new();
    let token_for_ui = cancel_token.clone();
    let token_for_orchestrator = cancel_token.clone();

    let scan_task = tokio::spawn(async move {
        OrchestratorAgent::new(
            provider,
            tool_registry,
            state_writer,
            tx,
            token_for_orchestrator,
        )
        .with_security(security_ctx)
        .run(&scanners_for_agent)
        .await
    });

    let outcome = run_scan_ui(
        rx,
        scanners_with_framework,
        model_info,
        context_window,
        token_for_ui,
        profiles,
        branch,
        project_name,
        provider_kind,
    )
    .await?;

    match outcome {
        ScanOutcome::Completed => {
            let failed = scan_task.await??;
            if !failed.is_empty() {
                let names: Vec<&str> = failed.iter().map(|s| s.name()).collect();
                println!(
                    "\n✓ Scan complete. Findings in .zentra/\n\
                     Warning: the following scanners failed: {}",
                    names.join(", ")
                );
            } else {
                println!("\n✓ Scan complete. Findings in .zentra/");
            }
        }
        _ => {
            cancel_token.cancel();
            scan_task.abort();
            let _ = scan_task.await;
        }
    }

    Ok(outcome)
}

/// Resolve the executable name/path for a CLI provider: an explicit `base_url`
/// overrides the default, otherwise the kind selects the conventional binary.
fn resolve_cli_binary(kind: &str, base_url: &str) -> String {
    if !base_url.is_empty() {
        return base_url.to_string();
    }
    match kind {
        "claude_cli" => "claude",
        "codex_cli" => "codex",
        _ => kind,
    }
    .to_string()
}

/// Reject a CLI provider binary that is a relative path with separators (a
/// repo-supplied `base_url` could otherwise point at an in-tree executable).
/// Bare names (resolved via PATH) and absolute paths are allowed.
fn validate_cli_binary(binary: &str) -> Result<()> {
    let p = Path::new(binary);
    if p.is_absolute() {
        return Ok(());
    }
    // On Windows "C:evil" is drive-relative — not absolute per std::path and it
    // contains no separator, so it would otherwise slip past as a "bare name".
    #[cfg(windows)]
    if binary.len() >= 2 && binary.as_bytes()[1] == b':' {
        anyhow::bail!(
            "CLI provider binary '{}' must be a bare name or an absolute path, not a relative path",
            binary
        );
    }
    if binary.contains('/') || binary.contains('\\') {
        anyhow::bail!(
            "CLI provider binary '{}' must be a bare name or an absolute path, not a relative path",
            binary
        );
    }
    Ok(())
}

fn ensure_supported_scan_auth(
    profile_name: &str,
    profile: &crate::config::ProviderProfile,
) -> Result<()> {
    if matches!(profile.auth_method, crate::config::AuthMethod::OAuth) {
        anyhow::bail!(
            "Profile '{}' uses legacy OpenAI browser login. OpenAI profiles now require an API key. Run 'zentra config setup' and reconfigure this profile with an API key.",
            profile_name
        );
    }

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

fn current_project_name() -> String {
    std::env::current_dir()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "project".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthMethod, ProviderProfile};

    #[test]
    fn rejects_saved_oauth_profiles_at_scan_startup() {
        let profile = ProviderProfile {
            kind: "openai_compat".to_string(),
            base_url: "https://api.openai.com/v1".to_string(),
            model: "gpt-4o".to_string(),
            keyless: false,
            auth_method: AuthMethod::OAuth,
            context_window: None,
            reasoning_effort: None,
        };

        let err = ensure_supported_scan_auth("openai", &profile).unwrap_err();
        let msg = err.to_string();

        assert!(msg.contains("legacy OpenAI browser login"), "got: {msg}");
        assert!(msg.contains("now require an API key"), "got: {msg}");
        assert!(msg.contains("zentra config setup"), "got: {msg}");
        assert!(msg.contains("API key"), "got: {msg}");
    }

    #[test]
    fn validate_cli_binary_rejects_relative_path() {
        assert!(validate_cli_binary("./evil").is_err());
        assert!(validate_cli_binary("sub/dir/evil").is_err());
        assert!(validate_cli_binary("claude").is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn validate_cli_binary_rejects_windows_drive_relative() {
        assert!(validate_cli_binary("C:evil").is_err());
    }
}
