use anyhow::{bail, Context, Result};
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

/// Output tokens the pack estimate reserves. Must match the `max_tokens` the
/// ReAct loop passes to the provider (`agent::scanner`), or the budget check
/// here would disagree with the one the scanner applies at send time.
const PACK_MAX_OUTPUT: u32 = 4096;

/// The longest system prompt among `scanners`, so the pack budget check assumes
/// the worst case rather than an average one.
fn scanners_widest_system_prompt(scanners: &[ScannerType]) -> String {
    scanners
        .iter()
        .map(|s| crate::scanners::system_prompt(*s))
        .max_by_key(|prompt| prompt.len())
        .unwrap_or_default()
        .to_string()
}

pub async fn run(
    provider_override: Option<String>,
    only: Option<String>,
    full: bool,
    pack: bool,
    dry_run: bool,
) -> Result<()> {
    let scanners = resolve_scanners(only.as_deref())?;
    let mut provider_override = provider_override;
    loop {
        match run_once(
            provider_override.clone(),
            scanners.clone(),
            full,
            PackOptions { pack, dry_run },
        )
        .await?
        {
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
        match run_once(
            provider_override.clone(),
            scanners.clone(),
            false,
            PackOptions::default(),
        )
        .await?
        {
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

/// Pack-mode switches for one scan. Default is off, which is the historical
/// agentic-exploration behavior.
#[derive(Debug, Clone, Copy, Default)]
pub struct PackOptions {
    pub pack: bool,
    pub dry_run: bool,
}

async fn run_once(
    provider_override: Option<String>,
    scanners: Vec<ScannerType>,
    full: bool,
    pack_options: PackOptions,
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
        validate_cli_binary(&profile.kind, &binary)?;
        if which::which(&binary).is_err() {
            anyhow::bail!(
                "CLI provider '{}' requires '{}' on PATH.\n\
                 Install it and try again, or run 'zentra config use <other-profile>'.",
                profile_name,
                binary
            );
        }
    }

    // Re-validate the endpoint on the use path (config may predate the write-time
    // gate or have been hand-edited); CLI providers keep a binary path here, not a
    // URL, so validate_profile_endpoint exempts them.
    crate::config::validation::validate_profile_endpoint(&profile.kind, &profile.base_url)?;

    let (tx, rx) = mpsc::channel(128);

    let provider: Arc<dyn LLMProvider> = match profile.kind.as_str() {
        "anthropic" => Arc::new(
            AnthropicProvider::new(profile.base_url.clone(), profile.model.clone(), api_key)
                .with_temperature(profile.temperature),
        ),
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
                .with_context_window(profile.context_window)
                .with_temperature(profile.temperature),
        ),
    };

    let cwd = std::env::current_dir()?;
    let (project_config, created) =
        ProjectConfig::load_or_init_for_run(&ProjectConfig::default_path(), &cwd)?;
    if created {
        crate::commands::init::update_gitignore_at(&cwd)?;
        println!(
            "✓ Auto-initialized .zentra/ (stack: {})",
            project_config.stack
        );
    }

    let target_root = Path::new(&project_config.target_path).to_path_buf();
    let zentra_dir = target_root.join(".zentra");

    // Decide full vs incremental from the prior manifest + current env.
    let prior_manifest = ScanManifest::load(&zentra_dir);
    let head_commit = git_head_commit(&target_root);
    let is_git = head_commit.is_some() || git_is_repo(&target_root);
    let engine_version = env!("CARGO_PKG_VERSION");
    let model_id = format!("{} · {}", profile.model, profile_name);
    let decision = decide_mode(ModeInputs {
        // Pack mode sends the whole repository, so an incremental baseline has
        // nothing to narrow. The two modes are mutually exclusive by definition.
        forced_full: full || pack_options.pack,
        is_git_repo: is_git,
        current_engine_version: engine_version,
        current_model_id: &model_id,
        prior: prior_manifest.as_ref(),
    });
    // Pack mode forces a full scan through `forced_full`, but reporting the
    // `--full` reason would name a flag the operator did not pass.
    if pack_options.pack {
        println!("ℹ pack mode — sending the whole repository (implies a full scan)");
    } else {
        println!("ℹ {}", decision.reason);
    }

    // Pack mode: build the pack, check it against the input budget, and refuse
    // rather than truncate. --dry-run stops here, before any provider call.
    let pack: Option<Arc<String>> = if pack_options.pack {
        let built = crate::agent::pack::build_pack(&target_root);
        let system = scanners_widest_system_prompt(&scanners);
        let tools = ToolRegistry::new().definitions();
        let estimate = built.estimate_tokens(&system, &tools);
        let context_window = profile
            .context_window
            .unwrap_or_else(|| provider.context_window());

        println!(
            "{}",
            crate::agent::pack::render_summary(&built, estimate, context_window, PACK_MAX_OUTPUT)
        );

        if pack_options.dry_run {
            println!("\nDry run — no provider call made.");
            return Ok(ScanOutcome::Completed);
        }
        if !crate::agent::pack::fits_budget(estimate, context_window, PACK_MAX_OUTPUT) {
            bail!(crate::agent::pack::refusal_message(
                estimate,
                context_window,
                PACK_MAX_OUTPUT
            ));
        }
        Some(Arc::new(built.render()))
    } else {
        if pack_options.dry_run {
            bail!("--dry-run only applies to --pack. Re-run with: zentra scan --pack --dry-run");
        }
        None
    };

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
        .with_focus_context(focus_context)
        .with_pack(pack);
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

            // Write a deterministic SARIF report from the findings the scan
            // produced. This is a post-step, not an LLM scanner task.
            let findings_raw = std::fs::read_to_string(zentra_dir.join("detailed-findings.md"))
                .unwrap_or_default();
            let findings = crate::state::parse_findings(&findings_raw);
            if let Ok(path) = write_sarif_to_dir(&zentra_dir, &findings) {
                println!("  SARIF: {}", path.display());
            }

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

            let coverage = &summary.coverage;
            println!(
                "  Coverage: {} of {} source files read ({}%) — see .zentra/coverage.md",
                coverage.distinct_read,
                coverage.candidate_count,
                coverage.percent()
            );
        }
        _ => {
            cancel_token.cancel();
            scan_task.abort();
            let _ = tokio::time::timeout(std::time::Duration::from_millis(750), scan_task).await;
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

/// Validate the executable for a CLI provider. `base_url` is run as a program,
/// so on top of rejecting relative paths with separators (an in-tree executable)
/// we require the binary's file stem to match the expected CLI — `claude` for
/// claude_cli, `codex` for codex_cli. A custom install path is fine
/// (`/opt/claude/bin/claude`), but a hand-edited config can't point `zentra scan`
/// at an arbitrary program like `powershell` or `calc.exe` (F14).
fn validate_cli_binary(kind: &str, binary: &str) -> Result<()> {
    let expected = match kind {
        "claude_cli" => "claude",
        "codex_cli" => "codex",
        // Not a CLI provider — nothing is executed from base_url.
        _ => return Ok(()),
    };

    // On Windows "C:evil" is drive-relative — not absolute per std::path and it
    // contains no separator, so it would otherwise slip past as a "bare name".
    #[cfg(windows)]
    if binary.len() >= 2 && binary.as_bytes()[1] == b':' && !Path::new(binary).is_absolute() {
        anyhow::bail!(
            "CLI provider binary '{}' must be a bare name or an absolute path, not a relative path",
            binary
        );
    }
    if !Path::new(binary).is_absolute() && (binary.contains('/') || binary.contains('\\')) {
        anyhow::bail!(
            "CLI provider binary '{}' must be a bare name or an absolute path, not a relative path",
            binary
        );
    }

    let stem = Path::new(binary)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if stem != expected {
        anyhow::bail!(
            "CLI provider '{kind}' must run the '{expected}' binary, but base_url resolves to '{binary}'. \
             Point it at a '{expected}' executable (a custom path is fine)."
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

fn resolve_scanners(only: Option<&str>) -> Result<Vec<ScannerType>> {
    Ok(match only {
        Some("threat-model") => vec![ScannerType::ThreatModel, ScannerType::Report],
        Some("sast") => vec![ScannerType::Sast, ScannerType::Report],
        Some("supply-chain") => vec![ScannerType::SupplyChain, ScannerType::Report],
        Some("api") => vec![ScannerType::ApiScan, ScannerType::Report],
        Some("iac") => vec![ScannerType::IacScan, ScannerType::Report],
        Some("report") => vec![ScannerType::Report],
        Some(unknown) => {
            // Reject typos instead of silently running a full scan (F9).
            anyhow::bail!(
                "unknown scanner '{unknown}' for --only. \
                 Valid values: threat-model, sast, supply-chain, api, iac, report"
            );
        }
        None => vec![
            ScannerType::ThreatModel,
            ScannerType::Sast,
            ScannerType::SupplyChain,
            ScannerType::ApiScan,
            ScannerType::IacScan,
            ScannerType::Report,
        ],
    })
}

/// Write a SARIF 2.1.0 report to `<zentra_dir>/reports/findings.sarif`. The
/// `reports` subdirectory is created if it is absent. Return the written path.
fn write_sarif_to_dir(
    zentra_dir: &Path,
    findings: &[crate::state::Finding],
) -> Result<std::path::PathBuf> {
    use std::fs;
    let reports_dir = zentra_dir.join("reports");
    fs::create_dir_all(&reports_dir)?;
    let path = reports_dir.join("findings.sarif");
    fs::write(&path, crate::state::sarif::render_sarif(findings))?;
    Ok(path)
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

    // F9: an unknown --only value silently ran a FULL scan (the `_` arm),
    // so a typo like `--only sats` burned quota on every scanner. It must be
    // rejected instead.
    #[test]
    fn resolve_scanners_rejects_unknown_only_value() {
        assert!(
            resolve_scanners(Some("sats")).is_err(),
            "a typo'd scanner name must be an error, not a full scan"
        );
        assert!(resolve_scanners(Some("sast")).is_ok());
        assert!(resolve_scanners(None).is_ok(), "no --only means full scan");
    }

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
            temperature: None,
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
        assert!(validate_cli_binary("claude_cli", "./evil").is_err());
        assert!(validate_cli_binary("claude_cli", "sub/dir/evil").is_err());
        assert!(validate_cli_binary("claude_cli", "claude").is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn validate_cli_binary_rejects_windows_drive_relative() {
        assert!(validate_cli_binary("claude_cli", "C:evil").is_err());
    }

    // F14: base_url is executed as a binary. Only allow an executable whose file
    // stem matches the expected CLI (claude/codex) — a custom PATH is fine, but a
    // hand-edited config can't point scan at an arbitrary program.
    #[test]
    fn validate_cli_binary_allowlists_expected_binary_stem() {
        assert!(validate_cli_binary("claude_cli", "claude").is_ok());
        assert!(validate_cli_binary("codex_cli", "codex").is_ok());
        // A custom absolute install path to the right binary is allowed.
        #[cfg(windows)]
        assert!(validate_cli_binary("claude_cli", "C:\\tools\\claude.exe").is_ok());
        #[cfg(unix)]
        assert!(validate_cli_binary("claude_cli", "/opt/claude/bin/claude").is_ok());
        // wrong / arbitrary programs are rejected
        assert!(validate_cli_binary("claude_cli", "powershell").is_err());
        assert!(validate_cli_binary("claude_cli", "codex").is_err());
        #[cfg(windows)]
        assert!(validate_cli_binary("codex_cli", "C:\\Windows\\System32\\calc.exe").is_err());
        #[cfg(unix)]
        assert!(validate_cli_binary("codex_cli", "/usr/bin/sh").is_err());
    }
}
