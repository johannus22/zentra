use anyhow::{Context, Result};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::agent::{orchestrator::OrchestratorAgent, ScannerType};
use crate::config::{keychain, GlobalConfig, ProjectConfig};
use crate::incremental::{
    build_focus_context, compute_change_set, decide_mode, ModeInputs, ScanManifest, ScanMode,
};
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

/// Max files in the incremental impact set. When the impact set hits this cap,
/// findings in files beyond it are carried forward unverified — we surface a
/// notice so the truncation is never silent.
const INCREMENTAL_IMPACT_CAP: usize = 200;

pub async fn run(
    provider_override: Option<String>,
    only: Option<String>,
    full: bool,
) -> Result<()> {
    let scanners = resolve_scanners(only.as_deref());
    let mut provider_override = provider_override;
    loop {
        match run_once(provider_override.clone(), scanners.clone(), full).await? {
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
        match run_once(provider_override.clone(), scanners.clone(), false).await? {
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
    full: bool,
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
            OpenAICompatProvider::new(profile.base_url.clone(), profile.model.clone(), api_key)
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

    let target_root = Path::new(&project_config.target_path).to_path_buf();
    let zentra_dir = target_root.join(".zentra");

    // Decide full vs incremental from the prior manifest + current env.
    let prior_manifest = ScanManifest::load(&zentra_dir);
    let head_commit = git_head_commit(&target_root);
    let is_git = head_commit.is_some() || git_is_repo(&target_root);
    let engine_version = env!("CARGO_PKG_VERSION");
    let model_id = format!("{} · {}", profile.model, profile_name);
    let decision = decide_mode(ModeInputs {
        forced_full: full,
        is_git_repo: is_git,
        current_engine_version: engine_version,
        current_model_id: &model_id,
        prior: prior_manifest.as_ref(),
    });
    println!("ℹ {}", decision.reason);

    // For incremental: capture prior findings BEFORE StateWriter truncates the file,
    // then compute the change set and build focus context.
    let (incremental, focus_context) = if decision.mode == ScanMode::Incremental {
        let prior_raw =
            std::fs::read_to_string(zentra_dir.join("detailed-findings.md")).unwrap_or_default();
        let prior = crate::state::parse_findings(&prior_raw);
        match compute_change_set(&target_root, &decision.baseline, INCREMENTAL_IMPACT_CAP) {
            Ok(cs) => {
                if cs.impact.len() >= INCREMENTAL_IMPACT_CAP {
                    println!(
                        "⚠ Impact set capped at {INCREMENTAL_IMPACT_CAP} files; findings in files beyond the cap are carried forward unverified. Run with --full for a complete rescan."
                    );
                }
                let focus = build_focus_context(&cs);
                (Some((prior, cs)), Some(focus))
            }
            Err(e) => {
                println!("ℹ change detection failed ({e}); running full scan");
                (None, None)
            }
        }
    } else {
        (None, None)
    };
    let is_incremental = incremental.is_some();

    // Capture banner counts before incremental is moved into the spawned task.
    let banner_info: Option<(usize, usize, usize, String)> =
        incremental.as_ref().map(|(prior, cs)| {
            let baseline_str = head_commit.as_deref().unwrap_or("working-tree").to_string();
            (cs.changed.len(), cs.impact.len(), prior.len(), baseline_str)
        });

    let state_writer = Arc::new(
        StateWriter::open(&target_root, false)
            .context("Failed to initialize .zentra/ directory")?,
    );
    let tool_registry = Arc::new(ToolRegistry::new());

    // Security envelope: tamper-evident audit log, response binding, tool gate,
    // and prompt-injection guard. Defaults are balanced; override with
    // ZENTRA_SECURITY=off (disable) or ZENTRA_SECURITY=hardened (strictest).
    let security_config = SecurityConfig::load();
    let session_id = security::new_session_id();
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
        let mut orch = OrchestratorAgent::new(
            provider,
            tool_registry,
            state_writer,
            tx,
            token_for_orchestrator,
        )
        .with_security(security_ctx)
        .with_focus_context(focus_context);
        if let Some((prior, cs)) = incremental {
            orch = orch.with_incremental(prior, cs);
        }
        orch.run(&scanners_for_agent).await
    });

    // Print incremental banner before launching TUI
    if let Some((changed, impacted, carried, baseline)) = banner_info {
        println!(
            "{}",
            crate::tui::scan_ui::incremental_banner(changed, impacted, carried, &baseline)
        );
    }

    let outcome = run_scan_ui(
        rx,
        scanners_with_framework.clone(),
        model_id.clone(),
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
            let summary = scan_task.await??;
            let failed = summary.failed;

            // Persist the new baseline for the next scan.
            let manifest = ScanManifest {
                last_scan_commit: head_commit.clone(),
                was_dirty: git_is_dirty(&target_root),
                scanned_at: chrono::Utc::now().to_rfc3339(),
                scanner_set: scanners_with_framework
                    .iter()
                    .map(|s| s.name().to_string())
                    .collect(),
                engine_version: engine_version.to_string(),
                model_id: model_id.clone(),
                mode: if is_incremental {
                    "incremental"
                } else {
                    "full"
                }
                .to_string(),
                file_hashes: if is_git {
                    None
                } else {
                    crate::incremental::detect::hash_tree(&target_root).ok()
                },
            };
            let _ = manifest.save(&zentra_dir);

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

            if let Some(delta) = summary.delta {
                println!(
                    "  Δ since last scan: {} new, {} resolved, {} carried",
                    delta.new, delta.resolved, delta.carried
                );
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

fn git_head_commit(root: &Path) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn git_is_repo(root: &Path) -> bool {
    std::process::Command::new("git")
        .args(["rev-parse", "--is-inside-work-tree"])
        .current_dir(root)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn git_is_dirty(root: &Path) -> bool {
    std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(root)
        .output()
        .map(|o| !String::from_utf8_lossy(&o.stdout).trim().is_empty())
        .unwrap_or(false)
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
