use anyhow::{bail, Context, Result};
use std::path::Path;
use std::sync::{atomic::AtomicBool, Arc, Mutex};
use tokio::sync::mpsc;

use crate::agent::{
    chat::{ChatScannerState, ChatScannerStatus, ChatSnapshot, NormalizedRepoPath, PhaseBoundary},
    chat_agent::ChatAgent,
    chat_coordinator::{self, ChatCoordinator},
    checkpoint::Checkpoint,
    orchestrator::{OrchestratorAgent, OrchestratorChatRuntime, RunSummary},
    ScannerType,
};
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
use crate::tui::{
    scan_ui::{run_scan_ui_with_chat, ChatUiChannels},
    ScanOutcome,
};
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
}

pub async fn run(
    provider_override: Option<String>,
    only: Option<String>,
    full: bool,
    pack: bool,
    dry_run: bool,
    resume: bool,
) -> Result<()> {
    let scanners = resolve_scanners(only.as_deref())?;
    let mut provider_override = provider_override;
    loop {
        match run_once(
            provider_override.clone(),
            scanners.clone(),
            full,
            PackOptions { pack, dry_run },
            resume,
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
            false,
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
    resume: bool,
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

    // Resume: load the checkpoint when --resume is set, so the orchestrator can
    // skip scanners that completed successfully in a prior (crashed) run.
    // A fresh (non-resume) scan treats a stale regular checkpoint as abandoned.
    // It is not replaced until the durable fresh runtime is prepared below: pack
    // dry-runs and preflight failures must leave the one-shot full-scan trigger.
    let abandoned_checkpoint_present = if resume {
        false
    } else {
        detect_abandoned_checkpoint(&zentra_dir)
            .context("Cannot start scan: failed to inspect stale checkpoint")?
    };
    let resume_checkpoint = if resume {
        Some(
            Checkpoint::load_strict(&zentra_dir)
                .context("Cannot resume: checkpoint.json is missing or corrupt")?,
        )
    } else {
        None
    };

    // A resume belongs to the scanner identity captured at the last durable
    // boundary. CLI flags must not turn it into a different run; in particular
    // a crashed FrameworkAnalysis is still resumed after architecture.md exists.
    let scanners = effective_scanners_for_run(
        &scanners,
        resume_checkpoint.as_ref(),
        zentra_dir.join("architecture.md").is_file(),
    )
    .context("Cannot determine scanner set for interactive scan")?;

    // Decide full vs incremental from the prior manifest + current env.
    let prior_manifest = ScanManifest::load(&zentra_dir);
    let head_commit = git_head_commit(&target_root);
    let is_git = head_commit.is_some() || git_is_repo(&target_root);
    let engine_version = env!("CARGO_PKG_VERSION");
    let model_id = format!("{} · {}", profile.model, profile_name);
    let abandoned_checkpoint_forces_full =
        abandoned_checkpoint_present && !full && !pack_options.pack && !resume;
    let decision = decide_scan_mode(
        ModeInputs {
            // Pack mode sends the whole repository, so an incremental baseline has
            // nothing to narrow. The two modes are mutually exclusive by definition.
            // Resume replays completed scanner state. It must never enter the
            // incremental reconciliation path.
            forced_full: full || pack_options.pack || resume || abandoned_checkpoint_forces_full,
            is_git_repo: is_git,
            current_engine_version: engine_version,
            current_model_id: &model_id,
            prior: prior_manifest.as_ref(),
        },
        abandoned_checkpoint_forces_full,
    );
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
        StateWriter::open(&target_root, resume)
            .context("Failed to initialize .zentra/ directory")?,
    );
    let tool_registry = Arc::new(ToolRegistry::new());

    // Security envelope: tamper-evident audit log, response binding, tool gate,
    // and prompt-injection guard. Defaults are balanced; override with
    // ZENTRA_SECURITY=off (disable) or ZENTRA_SECURITY=hardened (strictest).
    let security_config = SecurityConfig::load();
    // The audit session remains per invocation. A resumed chat runtime instead
    // retains the durable checkpoint session so pending actions cannot migrate
    // to a newly-created conversation.
    let audit_session_id = security::new_session_id();
    let mut audit = AuditLog::new(&zentra_dir, &audit_session_id, security_config.audit_log)
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

    let scanners_for_agent = scanners.clone();

    // Establish the complete interactive runtime identity before either the
    // coordinator or orchestrator can observe it. In particular, a fresh
    // checkpoint replaces any abandoned checkpoint only here, immediately
    // before the scan task can be launched.
    let prepared_chat = prepare_chat_runtime(
        &zentra_dir,
        resume_checkpoint.clone(),
        &scanners_for_agent,
        &audit_session_id,
    )
    .context("Cannot initialize interactive chat runtime")?;
    let runtime_session_id = prepared_chat.session_id;
    // Pass the same migrated checkpoint that backs chat to the orchestrator,
    // rather than the pre-migration strict-load copy.
    let orchestrator_resume_checkpoint = resume.then(|| prepared_chat.checkpoint.clone());
    let checkpoint = Arc::new(Mutex::new(prepared_chat.checkpoint));
    let snapshot = Arc::new(Mutex::new(prepared_chat.snapshot));
    let action_eligible = Arc::new(AtomicBool::new(true));

    // Incremental chat may only name valid, in-root paths. Keep the allowed
    // list bounded independently from the wider scanner impact set.
    let incremental_paths = incremental.as_ref().map(|(_, change_set)| {
        let mut paths: Vec<_> = change_set
            .impact
            .iter()
            .filter_map(|path| NormalizedRepoPath::normalize(path).ok())
            .filter(|path| path.validate_within_root(&target_root).is_ok())
            .collect();
        paths.sort();
        paths.dedup();
        paths.truncate(20);
        paths
    });

    let cancel_token = CancellationToken::new();
    let token_for_ui = cancel_token.clone();
    let token_for_orchestrator = cancel_token.clone();

    // The UI owns only its command sender and event receiver. The coordinator
    // owns the opposite ends; scan actions and their outcomes are separately
    // bounded so neither lane can silently consume the other.
    let (chat_command_tx, chat_command_rx, chat_event_tx, chat_event_rx) =
        chat_coordinator::channels();
    let (pending_tx, pending_actions) = mpsc::channel(chat_coordinator::MAX_PENDING_CHAT_ACTIONS);
    let (outcome_tx, outcome_rx) = mpsc::channel(1);
    let chat_store = crate::agent::chat::ChatStore::new(&zentra_dir, runtime_session_id.clone())
        .context("Cannot initialize interactive chat transcript store")?;
    let chat_agent = chat_agent_with_scan_provider(
        provider.clone(),
        tool_registry.clone(),
        security_ctx.clone(),
        cancel_token.clone(),
    );
    let coordinator = ChatCoordinator::new(
        chat_agent,
        security_ctx.clone(),
        chat_store,
        snapshot.clone(),
        target_root.clone(),
        zentra_dir.clone(),
        scanners_for_agent.clone(),
        incremental_paths,
        checkpoint.clone(),
        pending_tx,
        cancel_token.clone(),
    )
    .with_outcomes(outcome_rx)
    .with_action_eligibility(action_eligible.clone());
    let mut coordinator_task = tokio::spawn(coordinator.run(chat_command_rx, chat_event_tx));

    let scanners_for_task = scanners_for_agent.clone();
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
        .with_pack(pack)
        .with_resume(orchestrator_resume_checkpoint)
        .with_chat_runtime(OrchestratorChatRuntime {
            session_id: runtime_session_id,
            pending_actions,
            outcome_tx,
            checkpoint,
            snapshot,
            action_eligible,
        });
        if let Some((prior, cs)) = incremental {
            orch = orch.with_incremental(prior, cs);
        }
        orch.run(&scanners_for_task).await
    });

    // Print incremental banner before launching TUI
    if let Some((changed, impacted, carried, baseline)) = banner_info {
        println!(
            "{}",
            crate::tui::scan_ui::incremental_banner(changed, impacted, carried, &baseline)
        );
    }

    let ui_result = run_scan_ui_with_chat(
        rx,
        scanners_for_agent.clone(),
        model_id.clone(),
        context_window,
        token_for_ui,
        profiles,
        branch.clone(),
        project_name.clone(),
        provider_kind,
        Some(ChatUiChannels {
            command_tx: chat_command_tx,
            event_rx: chat_event_rx,
        }),
    )
    .await;
    let outcome = match ui_result {
        Ok(outcome) => outcome,
        Err(error) => {
            stop_interactive_runtime(&cancel_token, scan_task, &mut coordinator_task).await;
            return Err(error);
        }
    };

    match outcome {
        ScanOutcome::Completed => {
            let summary = match scan_task.await {
                Ok(Ok(summary)) => summary,
                Ok(Err(error)) => {
                    stop_interactive_coordinator(&cancel_token, &mut coordinator_task).await;
                    return Err(error);
                }
                Err(error) => {
                    stop_interactive_coordinator(&cancel_token, &mut coordinator_task).await;
                    return Err(error.into());
                }
            };
            finish_interactive_coordinator(&cancel_token, &mut coordinator_task).await;
            let failed = summary.failed;

            // Persist the new baseline for the next scan.
            let manifest = ScanManifest {
                last_scan_commit: head_commit.clone(),
                was_dirty: git_is_dirty(&target_root),
                scanned_at: chrono::Utc::now().to_rfc3339(),
                scanner_set: scanners_for_agent
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
            if let Ok(path) = write_findings_html_to_dir(
                &zentra_dir,
                &findings,
                &project_name,
                &branch,
                &model_id,
            ) {
                println!("  HTML:  {}", path.display());
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
            stop_interactive_runtime(&cancel_token, scan_task, &mut coordinator_task).await;
        }
    }

    Ok(outcome)
}

const INTERACTIVE_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(750);

#[derive(Debug)]
struct PreparedChatRuntime {
    session_id: String,
    checkpoint: Checkpoint,
    snapshot: ChatSnapshot,
}

/// Make the durable checkpoint the identity authority before any task starts.
/// A legacy checkpoint with no actions may be safely assigned this invocation's
/// new runtime identity; actions without an owner remain fail-closed.
fn prepare_chat_runtime(
    zentra_dir: &Path,
    resume_checkpoint: Option<Checkpoint>,
    selected: &[ScannerType],
    fresh_session_id: &str,
) -> Result<PreparedChatRuntime> {
    let selected_names = canonical_scanner_names(selected)?;
    let (session_id, checkpoint) = match resume_checkpoint {
        Some(mut checkpoint) => {
            if checkpoint.session_id.is_empty() {
                if !checkpoint.confirmed_chat_actions.is_empty() {
                    bail!(
                        "Cannot resume interactive scan: checkpoint actions have no owning session"
                    );
                }
                crate::agent::chat::validate_session_id(fresh_session_id)
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                checkpoint.session_id = fresh_session_id.to_string();
                checkpoint.updated_at = chrono::Utc::now().to_rfc3339();
                checkpoint
                    .save_strict(zentra_dir)
                    .context("failed to persist migrated interactive checkpoint session")?;
            }
            crate::agent::chat::validate_session_id(&checkpoint.session_id)
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            checkpoint
                .confirmed_chat_actions_for_resume(&checkpoint.session_id, selected)
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            (checkpoint.session_id.clone(), checkpoint)
        }
        None => {
            crate::agent::chat::validate_session_id(fresh_session_id)
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            let mut checkpoint = Checkpoint {
                session_id: fresh_session_id.to_string(),
                scanner_set: selected_names.clone(),
                ..Checkpoint::default()
            };
            checkpoint.updated_at = chrono::Utc::now().to_rfc3339();
            checkpoint
                .save_strict(zentra_dir)
                .context("failed to persist interactive checkpoint session")?;
            (checkpoint.session_id.clone(), checkpoint)
        }
    };

    let snapshot = ChatSnapshot {
        session_id: session_id.clone(),
        boundary: PhaseBoundary::default(),
        selected_scanners: selected_names.clone(),
        scanner_status: selected_names
            .iter()
            .map(|scanner| ChatScannerStatus {
                scanner: scanner.clone(),
                status: ChatScannerState::NotStarted,
            })
            .collect(),
        checkpoint_completed: checkpoint.completed.iter().cloned().collect(),
        action_eligible: true,
        ..ChatSnapshot::default()
    };
    Ok(PreparedChatRuntime {
        session_id,
        checkpoint,
        snapshot,
    })
}

fn canonical_scanner_names(selected: &[ScannerType]) -> Result<Vec<String>> {
    let mut names: Vec<_> = selected
        .iter()
        .map(|scanner| scanner.name().to_string())
        .collect();
    names.sort();
    if names.windows(2).any(|pair| pair[0] == pair[1]) {
        bail!("interactive scan selected duplicate scanners");
    }
    Ok(names)
}

/// Detect a stale checkpoint without treating its contents as resume authority.
/// We inspect the link itself, rather than following it, so only a regular file
/// is considered an abandoned checkpoint for the one-shot full-scan policy.
/// Replacement occurs later through `Checkpoint::save_strict` when the fresh
/// interactive runtime is durably initialized.
fn detect_abandoned_checkpoint(zentra_dir: &Path) -> Result<bool> {
    let checkpoint_path = zentra_dir.join("checkpoint.json");
    let abandoned_regular_checkpoint = match std::fs::symlink_metadata(&checkpoint_path) {
        Ok(metadata) => metadata.file_type().is_file(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    Ok(abandoned_regular_checkpoint)
}

/// Determine the mode for one invocation. A detected regular checkpoint is a
/// one-shot full-scan trigger; later fresh scans may use the manifest written by
/// a successful completion as normal.
fn decide_scan_mode(
    mode_inputs: ModeInputs<'_>,
    abandoned_checkpoint_forces_full: bool,
) -> crate::incremental::ModeDecision {
    let mut decision = decide_mode(mode_inputs);
    if abandoned_checkpoint_forces_full {
        decision.reason = "abandoned checkpoint present — running full scan".to_string();
    }
    decision
}

/// Return the one scanner set that all interactive participants share. On a
/// resume, the durable checkpoint is authoritative; requested CLI scanners are
/// intentionally not merged into it.
fn effective_scanners_for_run(
    requested: &[ScannerType],
    resume_checkpoint: Option<&Checkpoint>,
    architecture_exists: bool,
) -> Result<Vec<ScannerType>> {
    ensure_unique_scanners(requested)?;
    match resume_checkpoint {
        Some(checkpoint) => scanners_from_checkpoint(&checkpoint.scanner_set),
        None => {
            let mut selected = requested.to_vec();
            if !architecture_exists && !selected.contains(&ScannerType::FrameworkAnalysis) {
                selected.insert(0, ScannerType::FrameworkAnalysis);
            }
            ensure_unique_scanners(&selected)?;
            Ok(selected)
        }
    }
}

fn scanners_from_checkpoint(scanner_set: &[String]) -> Result<Vec<ScannerType>> {
    if scanner_set.is_empty() {
        bail!("Cannot resume interactive scan: checkpoint scanner set is empty");
    }
    let scanners: Vec<_> = scanner_set
        .iter()
        .map(|name| scanner_from_canonical_name(name))
        .collect::<Result<_>>()?;
    let canonical_names = canonical_scanner_names(&scanners)?;
    if scanner_set != canonical_names.as_slice() {
        bail!("Cannot resume interactive scan: checkpoint scanner set is not canonical");
    }
    Ok(scanners)
}

fn scanner_from_canonical_name(name: &str) -> Result<ScannerType> {
    match name {
        "framework" => Ok(ScannerType::FrameworkAnalysis),
        "threat_model" => Ok(ScannerType::ThreatModel),
        "sast" => Ok(ScannerType::Sast),
        "supply_chain" => Ok(ScannerType::SupplyChain),
        "api_scan" => Ok(ScannerType::ApiScan),
        "iac_scan" => Ok(ScannerType::IacScan),
        "report" => Ok(ScannerType::Report),
        _ => bail!("Cannot resume interactive scan: checkpoint contains unknown scanner '{name}'"),
    }
}

fn ensure_unique_scanners(selected: &[ScannerType]) -> Result<()> {
    let _ = canonical_scanner_names(selected)?;
    Ok(())
}

/// The scan provider has already crossed the single security-envelope boundary.
/// Keep this helper separate from `ChatAgent::from_raw_provider` so interactive
/// wiring cannot accidentally add a second `GuardedProvider` layer.
fn chat_agent_with_scan_provider(
    guarded_scan_provider: Arc<dyn LLMProvider>,
    tools: Arc<ToolRegistry>,
    security: SecurityContext,
    cancel_token: CancellationToken,
) -> ChatAgent {
    ChatAgent::new(guarded_scan_provider, tools, security, cancel_token)
}

async fn finish_interactive_coordinator(
    cancel_token: &CancellationToken,
    coordinator_task: &mut tokio::task::JoinHandle<()>,
) {
    if tokio::time::timeout(INTERACTIVE_SHUTDOWN_TIMEOUT, &mut *coordinator_task)
        .await
        .is_ok()
    {
        return;
    }
    cancel_token.cancel();
    if tokio::time::timeout(INTERACTIVE_SHUTDOWN_TIMEOUT, &mut *coordinator_task)
        .await
        .is_ok()
    {
        return;
    }
    crate::logging::warn(
        "scan",
        "interactive chat coordinator did not stop after cancellation; aborting task",
    );
    coordinator_task.abort();
    let _ = tokio::time::timeout(INTERACTIVE_SHUTDOWN_TIMEOUT, coordinator_task).await;
}

async fn stop_interactive_coordinator(
    cancel_token: &CancellationToken,
    coordinator_task: &mut tokio::task::JoinHandle<()>,
) {
    cancel_token.cancel();
    if tokio::time::timeout(INTERACTIVE_SHUTDOWN_TIMEOUT, &mut *coordinator_task)
        .await
        .is_ok()
    {
        return;
    }
    crate::logging::warn(
        "scan",
        "interactive chat coordinator did not drain after cancellation; aborting task",
    );
    coordinator_task.abort();
    let _ = tokio::time::timeout(INTERACTIVE_SHUTDOWN_TIMEOUT, coordinator_task).await;
}

async fn stop_interactive_runtime(
    cancel_token: &CancellationToken,
    scan_task: tokio::task::JoinHandle<Result<RunSummary>>,
    coordinator_task: &mut tokio::task::JoinHandle<()>,
) {
    cancel_token.cancel();
    let mut scan_task = scan_task;
    if tokio::time::timeout(INTERACTIVE_SHUTDOWN_TIMEOUT, &mut scan_task)
        .await
        .is_err()
    {
        crate::logging::warn(
            "scan",
            "scan task did not stop after cancellation; aborting task",
        );
        scan_task.abort();
        let _ = tokio::time::timeout(INTERACTIVE_SHUTDOWN_TIMEOUT, &mut scan_task).await;
    }
    // The scan task owns the last outcome sender. Joining (or aborting) it
    // first closes that lane before the coordinator performs its graceful
    // cancellation drain.
    stop_interactive_coordinator(cancel_token, coordinator_task).await;
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

/// Write a styled HTML report to `<zentra_dir>/reports/findings.html`. The
/// `reports` subdirectory is created if it is absent. Return the written path.
fn write_findings_html_to_dir(
    zentra_dir: &Path,
    findings: &[crate::state::Finding],
    project_name: &str,
    branch: &str,
    model_id: &str,
) -> Result<std::path::PathBuf> {
    use std::fs;
    let reports_dir = zentra_dir.join("reports");
    fs::create_dir_all(&reports_dir)?;
    let path = reports_dir.join("findings.html");
    let meta = [
        ("Project", project_name),
        ("Branch", branch),
        ("Model", model_id),
    ];
    fs::write(
        &path,
        crate::state::html::render_report_html(findings, "Zentra SAST Report", &meta),
    )?;
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
    use crate::agent::chat::{
        ChatAction, ChatActionOutcome, ChatActionOutcomeEnvelope, ChatCommand, ChatOutcomeAck,
        ConfirmedChatAction, VulnerabilityCategory,
    };
    use crate::config::{AuthMethod, ProviderProfile};
    use crate::provider::openai_compat::OpenAICompatProvider;
    use crate::provider::{AgentMessage, CompletionRequest, CompletionResponse, ToolDefinition};
    use async_trait::async_trait;
    use tokio::sync::Notify;

    struct BlockingProvider {
        started: Arc<Notify>,
    }

    #[async_trait]
    impl LLMProvider for BlockingProvider {
        async fn complete(&self, _: CompletionRequest) -> Result<CompletionResponse> {
            anyhow::bail!("not used")
        }

        async fn complete_with_tools(
            &self,
            _: &str,
            _: &[AgentMessage],
            _: &[ToolDefinition],
            _: u32,
            _: Option<&CancellationToken>,
        ) -> Result<CompletionResponse> {
            self.started.notify_one();
            std::future::pending().await
        }

        fn context_window(&self) -> u32 {
            32_000
        }

        fn model_name(&self) -> &str {
            "blocking"
        }
    }

    fn selected_scanners() -> Vec<ScannerType> {
        vec![ScannerType::Sast, ScannerType::Report]
    }

    fn lifecycle_snapshot(session_id: &str) -> Arc<Mutex<ChatSnapshot>> {
        Arc::new(Mutex::new(ChatSnapshot {
            session_id: session_id.to_string(),
            selected_scanners: vec!["report".to_string(), "sast".to_string()],
            scanner_status: vec![
                ChatScannerStatus {
                    scanner: "report".to_string(),
                    status: ChatScannerState::NotStarted,
                },
                ChatScannerStatus {
                    scanner: "sast".to_string(),
                    status: ChatScannerState::NotStarted,
                },
            ],
            ..ChatSnapshot::default()
        }))
    }

    fn lifecycle_checkpoint(session_id: &str, actions: Vec<ConfirmedChatAction>) -> Checkpoint {
        Checkpoint {
            session_id: session_id.to_string(),
            scanner_set: vec!["report".to_string(), "sast".to_string()],
            confirmed_chat_actions: actions,
            ..Checkpoint::default()
        }
    }

    fn matching_prior_manifest() -> ScanManifest {
        ScanManifest {
            last_scan_commit: Some("old-successful-commit".to_string()),
            was_dirty: false,
            scanned_at: "2026-01-01T00:00:00Z".to_string(),
            scanner_set: vec!["threat_model".to_string()],
            engine_version: "test-engine".to_string(),
            model_id: "test-model".to_string(),
            mode: "full".to_string(),
            file_hashes: None,
        }
    }

    fn mode_for_test(
        prior: &ScanManifest,
        full: bool,
        resume: bool,
        abandoned_checkpoint_present: bool,
    ) -> crate::incremental::ModeDecision {
        let abandoned_checkpoint_forces_full = abandoned_checkpoint_present && !full && !resume;
        decide_scan_mode(
            ModeInputs {
                forced_full: full || resume || abandoned_checkpoint_forces_full,
                is_git_repo: true,
                current_engine_version: "test-engine",
                current_model_id: "test-model",
                prior: Some(prior),
            },
            abandoned_checkpoint_forces_full,
        )
    }

    fn simulated_pre_runtime_failure() -> Result<()> {
        bail!("simulated pre-runtime setup failure")
    }

    #[test]
    fn fresh_scan_without_checkpoint_keeps_automatic_incremental_mode() {
        let temp = tempfile::TempDir::new().unwrap();
        let zentra_dir = temp.path().join(".zentra");
        std::fs::create_dir_all(&zentra_dir).unwrap();
        matching_prior_manifest().save(&zentra_dir).unwrap();
        let prior = ScanManifest::load(&zentra_dir).unwrap();

        assert!(!detect_abandoned_checkpoint(&zentra_dir).unwrap());
        assert_eq!(
            mode_for_test(&prior, false, false, false).mode,
            ScanMode::Incremental
        );
    }

    #[test]
    fn abandoned_checkpoint_survives_pack_dry_run_and_forces_full_scan() {
        let temp = tempfile::TempDir::new().unwrap();
        let zentra_dir = temp.path().join(".zentra");
        std::fs::create_dir_all(&zentra_dir).unwrap();
        matching_prior_manifest().save(&zentra_dir).unwrap();
        std::fs::write(zentra_dir.join("checkpoint.json"), "abandoned checkpoint").unwrap();
        let prior = ScanManifest::load(&zentra_dir).unwrap();
        let requested = vec![ScannerType::ThreatModel, ScannerType::Report];
        let selected = effective_scanners_for_run(&requested, None, true).unwrap();

        // Pack dry-run returns before fresh runtime preparation, so detection
        // must not consume the checkpoint or its one-shot full-scan policy.
        assert!(detect_abandoned_checkpoint(&zentra_dir).unwrap());
        assert!(zentra_dir.join("checkpoint.json").is_file());
        assert_eq!(
            mode_for_test(&prior, false, false, true).mode,
            ScanMode::Full
        );
        assert!(selected.contains(&ScannerType::ThreatModel));
    }

    #[test]
    fn abandoned_checkpoint_survives_pre_runtime_failure_and_still_forces_full() {
        let temp = tempfile::TempDir::new().unwrap();
        let zentra_dir = temp.path().join(".zentra");
        std::fs::create_dir_all(&zentra_dir).unwrap();
        let prior = matching_prior_manifest();
        std::fs::write(zentra_dir.join("checkpoint.json"), "abandoned checkpoint").unwrap();

        assert!(detect_abandoned_checkpoint(&zentra_dir).unwrap());
        assert!(simulated_pre_runtime_failure().is_err());
        assert!(zentra_dir.join("checkpoint.json").is_file());
        assert_eq!(
            mode_for_test(&prior, false, false, true).mode,
            ScanMode::Full
        );
    }

    #[test]
    fn resume_and_explicit_full_keep_their_full_mode_behavior() {
        let prior = matching_prior_manifest();
        assert_eq!(
            mode_for_test(&prior, false, true, false).mode,
            ScanMode::Full
        );
        assert_eq!(
            mode_for_test(&prior, true, false, false).mode,
            ScanMode::Full
        );
    }

    #[test]
    fn corrupt_regular_checkpoint_is_retained_until_fresh_runtime_handoff() {
        let temp = tempfile::TempDir::new().unwrap();
        let zentra_dir = temp.path().join(".zentra");
        std::fs::create_dir_all(&zentra_dir).unwrap();
        let manifest_path = zentra_dir.join("scan-manifest.json");
        std::fs::write(&manifest_path, "prior manifest").unwrap();
        std::fs::write(zentra_dir.join("checkpoint.json"), "not checkpoint json").unwrap();

        assert!(detect_abandoned_checkpoint(&zentra_dir).unwrap());
        assert_eq!(
            std::fs::read_to_string(zentra_dir.join("checkpoint.json")).unwrap(),
            "not checkpoint json"
        );
        assert_eq!(
            std::fs::read_to_string(manifest_path).unwrap(),
            "prior manifest"
        );
    }

    #[test]
    fn nonregular_checkpoint_is_not_trusted_or_removed_before_fresh_handoff() {
        let temp = tempfile::TempDir::new().unwrap();
        let zentra_dir = temp.path().join(".zentra");
        let checkpoint_path = zentra_dir.join("checkpoint.json");
        std::fs::create_dir_all(&checkpoint_path).unwrap();

        assert!(!detect_abandoned_checkpoint(&zentra_dir).unwrap());
        assert!(prepare_chat_runtime(&zentra_dir, None, &selected_scanners(), "fresh").is_err());
        assert!(checkpoint_path.is_dir());
    }

    #[test]
    fn fresh_chat_runtime_replaces_abandoned_checkpoint_state_and_persists_new_session() {
        let temp = tempfile::TempDir::new().unwrap();
        let zentra_dir = temp.path().join(".zentra");
        std::fs::create_dir_all(&zentra_dir).unwrap();
        let stale_action = ConfirmedChatAction::new(
            uuid::Uuid::new_v4(),
            1,
            ChatAction::prioritize(VulnerabilityCategory::Injection),
            selected_scanners(),
        )
        .unwrap();
        let mut stale = lifecycle_checkpoint("abandoned-chat", vec![stale_action]);
        stale.completed.insert("sast".to_string());
        stale.save_strict(&zentra_dir).unwrap();
        let prior = matching_prior_manifest();

        assert!(detect_abandoned_checkpoint(&zentra_dir).unwrap());
        assert_eq!(
            mode_for_test(&prior, false, false, true).mode,
            ScanMode::Full
        );
        let prepared =
            prepare_chat_runtime(&zentra_dir, None, &selected_scanners(), "fresh-chat").unwrap();

        let persisted = Checkpoint::load_strict(&zentra_dir).unwrap();
        assert_eq!(prepared.session_id, "fresh-chat");
        assert_eq!(persisted.session_id, prepared.session_id);
        assert_eq!(persisted.scanner_set, vec!["report", "sast"]);
        assert!(persisted.completed.is_empty());
        assert!(persisted.confirmed_chat_actions.is_empty());
        // If setup fails after this durable replacement but before launch, the
        // new regular checkpoint remains a trigger for the next fresh run.
        assert!(detect_abandoned_checkpoint(&zentra_dir).unwrap());
        assert_eq!(prepared.snapshot.session_id, prepared.session_id);
        assert_eq!(prepared.snapshot.selected_scanners, vec!["report", "sast"]);
        assert!(prepared
            .snapshot
            .scanner_status
            .iter()
            .all(|status| matches!(status.status, ChatScannerState::NotStarted)));
        assert!(matches!(
            prepared.snapshot.boundary,
            PhaseBoundary::AfterFramework
        ));
    }

    #[test]
    fn resumed_chat_runtime_uses_checkpoint_session_and_rejects_bad_identity() {
        let temp = tempfile::TempDir::new().unwrap();
        let zentra_dir = temp.path().join(".zentra");
        std::fs::create_dir_all(&zentra_dir).unwrap();
        let checkpoint = Checkpoint {
            session_id: "resumed-chat".to_string(),
            scanner_set: vec!["report".to_string(), "sast".to_string()],
            ..Checkpoint::default()
        };

        let prepared = prepare_chat_runtime(
            &zentra_dir,
            Some(checkpoint.clone()),
            &selected_scanners(),
            "new-audit-session",
        )
        .unwrap();
        assert_eq!(prepared.session_id, "resumed-chat");
        assert_eq!(prepared.snapshot.session_id, "resumed-chat");

        let missing = Checkpoint::default();
        assert!(
            prepare_chat_runtime(&zentra_dir, Some(missing), &selected_scanners(), "fresh")
                .is_err()
        );
        let mismatched = Checkpoint {
            scanner_set: vec!["sast".to_string()],
            ..checkpoint.clone()
        };
        assert!(
            prepare_chat_runtime(&zentra_dir, Some(mismatched), &selected_scanners(), "fresh")
                .is_err()
        );
        let invalid = Checkpoint {
            session_id: "../invalid".to_string(),
            ..checkpoint
        };
        assert!(
            prepare_chat_runtime(&zentra_dir, Some(invalid), &selected_scanners(), "fresh")
                .is_err()
        );
    }

    #[test]
    fn resume_uses_durable_scanner_set_and_keeps_framework_after_architecture_exists() {
        let temp = tempfile::TempDir::new().unwrap();
        let zentra_dir = temp.path().join(".zentra");
        std::fs::create_dir_all(&zentra_dir).unwrap();
        std::fs::write(zentra_dir.join("architecture.md"), "cached architecture").unwrap();
        let checkpoint = Checkpoint {
            session_id: "crash-session".to_string(),
            scanner_set: vec![
                "framework".to_string(),
                "report".to_string(),
                "sast".to_string(),
            ],
            ..Checkpoint::default()
        };

        let effective = effective_scanners_for_run(
            &selected_scanners(),
            Some(&checkpoint),
            zentra_dir.join("architecture.md").is_file(),
        )
        .unwrap();
        assert_eq!(
            canonical_scanner_names(&effective).unwrap(),
            checkpoint.scanner_set
        );
        assert!(effective.contains(&ScannerType::FrameworkAnalysis));

        let prepared = prepare_chat_runtime(
            &zentra_dir,
            Some(checkpoint),
            &effective,
            "unused-fresh-session",
        )
        .unwrap();
        assert_eq!(
            prepared.snapshot.selected_scanners,
            vec!["framework", "report", "sast"]
        );
    }

    #[test]
    fn legacy_empty_session_without_actions_is_migrated_before_resume() {
        let temp = tempfile::TempDir::new().unwrap();
        let zentra_dir = temp.path().join(".zentra");
        std::fs::create_dir_all(&zentra_dir).unwrap();
        let checkpoint = Checkpoint {
            scanner_set: vec!["report".to_string(), "sast".to_string()],
            ..Checkpoint::default()
        };

        let prepared = prepare_chat_runtime(
            &zentra_dir,
            Some(checkpoint),
            &selected_scanners(),
            "migrated",
        )
        .unwrap();
        assert_eq!(prepared.session_id, "migrated");
        assert_eq!(
            Checkpoint::load_strict(&zentra_dir).unwrap().session_id,
            "migrated"
        );
    }

    #[test]
    fn legacy_empty_session_with_pending_actions_is_rejected() {
        use crate::agent::chat::{ChatAction, ConfirmedChatAction, VulnerabilityCategory};

        let temp = tempfile::TempDir::new().unwrap();
        let zentra_dir = temp.path().join(".zentra");
        std::fs::create_dir_all(&zentra_dir).unwrap();
        let pending = ConfirmedChatAction::new(
            uuid::Uuid::new_v4(),
            1,
            ChatAction::prioritize(VulnerabilityCategory::Injection),
            selected_scanners(),
        )
        .unwrap();
        let checkpoint = Checkpoint {
            scanner_set: vec!["report".to_string(), "sast".to_string()],
            confirmed_chat_actions: vec![pending],
            ..Checkpoint::default()
        };

        let error = prepare_chat_runtime(
            &zentra_dir,
            Some(checkpoint),
            &selected_scanners(),
            "must-not-migrate",
        )
        .unwrap_err();
        assert!(error.to_string().contains("no owning session"));
    }

    #[test]
    fn resume_rejects_unknown_duplicate_or_noncanonical_scanner_names() {
        for scanner_set in [
            vec!["report".to_string(), "unknown".to_string()],
            vec!["report".to_string(), "report".to_string()],
            vec!["sast".to_string(), "report".to_string()],
        ] {
            assert!(scanners_from_checkpoint(&scanner_set).is_err());
        }
    }

    #[test]
    fn chat_agent_uses_the_already_guarded_scan_provider_path() {
        let temp = tempfile::TempDir::new().unwrap();
        let raw: Arc<dyn LLMProvider> = Arc::new(OpenAICompatProvider::new(
            "https://example.test/v1".to_string(),
            "test-model".to_string(),
            "not-used".to_string(),
        ));
        let security = SecurityContext::new(
            SecurityConfig::hardened(),
            AuditLog::new(temp.path(), "guarded-test", true).unwrap(),
        );
        let guarded = security::GuardedProvider::wrap(raw, &security);
        let _agent = chat_agent_with_scan_provider(
            guarded,
            Arc::new(ToolRegistry::new()),
            security,
            CancellationToken::new(),
        );
    }

    #[test]
    fn interactive_wiring_channels_are_independent_from_scan_events() {
        let (command_tx, mut command_rx, event_tx, mut event_rx) = chat_coordinator::channels();
        command_tx
            .try_send(crate::agent::chat::ChatCommand::Close)
            .unwrap();
        assert!(matches!(
            command_rx.blocking_recv(),
            Some(crate::agent::chat::ChatCommand::Close)
        ));

        let request_id = uuid::Uuid::new_v4();
        event_tx
            .try_send(crate::agent::chat::ChatEvent::Cancelled { request_id })
            .unwrap();
        assert!(matches!(
            event_rx.blocking_recv(),
            Some(crate::agent::chat::ChatEvent::Cancelled { request_id: id }) if id == request_id
        ));
    }

    #[tokio::test]
    async fn completed_navigation_drains_terminal_outcome_without_cancellation() {
        let temp = tempfile::TempDir::new().unwrap();
        let zentra_dir = temp.path().join(".zentra");
        std::fs::create_dir_all(&zentra_dir).unwrap();
        let session_id = "completed-lifecycle";
        let mut action = ConfirmedChatAction::new(
            uuid::Uuid::new_v4(),
            1,
            ChatAction::prioritize(VulnerabilityCategory::Injection),
            selected_scanners(),
        )
        .unwrap();
        // This models the orchestrator's completed scanner attribution before
        // it sends the terminal Applied outcome to the coordinator.
        action.remaining_scanners.clear();
        let proposal_id = action.proposal_id;
        let checkpoint = Arc::new(Mutex::new(lifecycle_checkpoint(
            session_id,
            vec![action.clone()],
        )));
        checkpoint.lock().unwrap().save_strict(&zentra_dir).unwrap();
        let store = crate::agent::chat::ChatStore::new(&zentra_dir, session_id).unwrap();
        let inspect_store = store.clone();
        let cancel = CancellationToken::new();
        let (command_tx, command_rx, event_tx, _event_rx) = chat_coordinator::channels();
        let (pending_tx, _pending_rx) = mpsc::channel(chat_coordinator::MAX_PENDING_CHAT_ACTIONS);
        let (outcome_tx, outcome_rx) = mpsc::channel(1);
        let coordinator = ChatCoordinator::new(
            ChatAgent::new(
                Arc::new(OpenAICompatProvider::new(
                    "https://example.test/v1".to_string(),
                    "test-model".to_string(),
                    "not-used".to_string(),
                )),
                Arc::new(ToolRegistry::new()),
                SecurityContext::disabled(),
                cancel.clone(),
            ),
            SecurityContext::disabled(),
            store,
            lifecycle_snapshot(session_id),
            temp.path().to_path_buf(),
            zentra_dir.clone(),
            selected_scanners(),
            None,
            checkpoint.clone(),
            pending_tx,
            cancel.clone(),
        )
        .with_outcomes(outcome_rx);
        let mut coordinator_task = tokio::spawn(coordinator.run(command_rx, event_tx));

        let mut state = crate::tui::UiState::new(
            selected_scanners(),
            "model".to_string(),
            1,
            vec![],
            String::new(),
            String::new(),
            String::new(),
        );
        state.mark_complete();
        assert_eq!(
            crate::tui::scan_ui::exit_outcome(&state),
            ScanOutcome::Completed
        );

        // This real producer owns the last outcome sender, just like the scan
        // task. Command completion awaits it before gracefully joining chat.
        let scan_task = tokio::spawn(async move {
            let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
            outcome_tx
                .send(ChatActionOutcomeEnvelope {
                    expected: action,
                    outcome: ChatActionOutcome::Applied {
                        proposal_id,
                        boundary: PhaseBoundary::AfterParallel,
                    },
                    ack: ack_tx,
                })
                .await
                .unwrap();
            assert_eq!(ack_rx.await.unwrap().unwrap(), ChatOutcomeAck::Committed);
        });
        command_tx.try_send(ChatCommand::Close).unwrap();
        drop(command_tx);

        scan_task.await.unwrap(); // closes the outcome sender before coordinator join
        finish_interactive_coordinator(&cancel, &mut coordinator_task).await;

        assert!(!cancel.is_cancelled());
        assert!(coordinator_task.is_finished());
        assert!(checkpoint.lock().unwrap().confirmed_chat_actions.is_empty());
        assert!(Checkpoint::load_strict(&zentra_dir)
            .unwrap()
            .confirmed_chat_actions
            .is_empty());
        assert_eq!(
            inspect_store
                .terminal_proposal_lifecycle(proposal_id)
                .unwrap(),
            Some(crate::agent::chat::ProposalLifecycle::Applied)
        );
    }

    #[tokio::test]
    async fn aborted_navigation_cancels_live_request_after_producer_closes() {
        let temp = tempfile::TempDir::new().unwrap();
        let zentra_dir = temp.path().join(".zentra");
        std::fs::create_dir_all(&zentra_dir).unwrap();
        let session_id = "aborted-lifecycle";
        let checkpoint = Arc::new(Mutex::new(lifecycle_checkpoint(session_id, Vec::new())));
        checkpoint.lock().unwrap().save_strict(&zentra_dir).unwrap();
        let store = crate::agent::chat::ChatStore::new(&zentra_dir, session_id).unwrap();
        let inspect_store = store.clone();
        let cancel = CancellationToken::new();
        let provider_started = Arc::new(Notify::new());
        let (command_tx, command_rx, event_tx, mut event_rx) = chat_coordinator::channels();
        let (pending_tx, _pending_rx) = mpsc::channel(chat_coordinator::MAX_PENDING_CHAT_ACTIONS);
        let (outcome_tx, outcome_rx) = mpsc::channel(1);
        let coordinator = ChatCoordinator::new(
            ChatAgent::new(
                Arc::new(BlockingProvider {
                    started: provider_started.clone(),
                }),
                Arc::new(ToolRegistry::new()),
                SecurityContext::disabled(),
                cancel.clone(),
            ),
            SecurityContext::disabled(),
            store,
            lifecycle_snapshot(session_id),
            temp.path().to_path_buf(),
            zentra_dir.clone(),
            selected_scanners(),
            None,
            checkpoint,
            pending_tx,
            cancel.clone(),
        )
        .with_outcomes(outcome_rx);
        let mut coordinator_task = tokio::spawn(coordinator.run(command_rx, event_tx));

        let state = crate::tui::UiState::new(
            selected_scanners(),
            "model".to_string(),
            1,
            vec![],
            String::new(),
            String::new(),
            String::new(),
        );
        assert_eq!(
            crate::tui::scan_ui::exit_outcome(&state),
            ScanOutcome::Aborted
        );
        let request_id = uuid::Uuid::new_v4();
        let provider_wait = provider_started.notified();
        command_tx
            .send(ChatCommand::ask(request_id, "hold this request".to_string()).unwrap())
            .await
            .unwrap();
        // A queued event proves the coordinator durably accepted the request;
        // the provider notification proves it is live when cancellation starts.
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(1), event_rx.recv())
                .await
                .unwrap(),
            Some(crate::agent::chat::ChatEvent::RequestQueued { request_id: id, .. }) if id == request_id
        ));
        tokio::time::timeout(std::time::Duration::from_secs(1), provider_wait)
            .await
            .unwrap();

        let (producer_closed_tx, producer_closed_rx) = tokio::sync::oneshot::channel();
        let scan_cancel = cancel.clone();
        let scan_task = tokio::spawn(async move {
            scan_cancel.cancelled().await;
            drop(outcome_tx);
            let _ = producer_closed_tx.send(());
            Err(anyhow::anyhow!("scan cancelled"))
        });

        stop_interactive_runtime(&cancel, scan_task, &mut coordinator_task).await;

        assert!(producer_closed_rx.await.is_ok());
        assert!(cancel.is_cancelled());
        assert!(coordinator_task.is_finished());
        let transcript = std::fs::read_to_string(inspect_store.path()).unwrap();
        assert!(transcript.contains("\"cancelled\""), "{transcript}");
    }

    #[tokio::test]
    async fn normal_coordinator_teardown_does_not_cancel_a_finished_scan() {
        let cancel = CancellationToken::new();
        let mut coordinator = tokio::spawn(async {});

        finish_interactive_coordinator(&cancel, &mut coordinator).await;

        assert!(coordinator.is_finished());
        assert!(!cancel.is_cancelled());
    }

    #[tokio::test]
    async fn abort_teardown_cancels_and_joins_both_runtime_tasks() {
        let cancel = CancellationToken::new();
        let scan = tokio::spawn(async { std::future::pending::<Result<RunSummary>>().await });
        let mut coordinator = tokio::spawn(async { std::future::pending::<()>().await });

        stop_interactive_runtime(&cancel, scan, &mut coordinator).await;

        assert!(cancel.is_cancelled());
        assert!(coordinator.is_finished());
    }

    #[tokio::test]
    async fn cancellation_is_observed_before_runtime_teardown_aborts() {
        let cancel = CancellationToken::new();
        let (scan_observed_tx, scan_observed_rx) = tokio::sync::oneshot::channel();
        let scan_cancel = cancel.clone();
        let scan = tokio::spawn(async move {
            scan_cancel.cancelled().await;
            let _ = scan_observed_tx.send(());
            Err(anyhow::anyhow!("scan cancelled"))
        });
        let (coordinator_observed_tx, coordinator_observed_rx) = tokio::sync::oneshot::channel();
        let coordinator_cancel = cancel.clone();
        let mut coordinator = tokio::spawn(async move {
            coordinator_cancel.cancelled().await;
            let _ = coordinator_observed_tx.send(());
        });

        stop_interactive_runtime(&cancel, scan, &mut coordinator).await;

        assert!(scan_observed_rx.await.is_ok());
        assert!(coordinator_observed_rx.await.is_ok());
        assert!(coordinator.is_finished());
    }

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
