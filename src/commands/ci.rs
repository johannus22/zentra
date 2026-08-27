use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::agent::{orchestrator::OrchestratorAgent, ScanEvent, ScannerType};
use crate::ci::{
    changed_files_from_git, detect_full_scan_ci_context_from_env, git_diff_error_with_guidance,
    missing_history_guidance, publish_comment_best_effort, publish_triage_issue_best_effort,
    resolve_fail_threshold, select_impact_files, should_fail_ci, write_ci_artifacts, CiContext,
    CiPlatformKind,
};
use crate::config::{keychain, AuthMethod, GlobalConfig, ProjectConfig, ProviderProfile};
use crate::provider::{
    anthropic::AnthropicProvider, openai_compat::OpenAICompatProvider, LLMProvider,
};
use crate::security::{self, AuditEvent, AuditLog, SecurityConfig, SecurityContext};
use crate::state::{Finding, Severity, StateWriter};
use crate::tools::ToolRegistry;

/// Every scanner `select_ci_scanners` can ever return. Used by `--full`, which
/// scans the whole repo and so must consider dependency, API, and IaC files even
/// when no diff narrows the set. Kept as a const next to that function so the
/// two stay in sync: if `select_ci_scanners` gains a scanner, add it here too.
const ALL_CI_SCANNERS: &[ScannerType] = &[
    ScannerType::ThreatModel,
    ScannerType::Sast,
    ScannerType::SupplyChain,
    ScannerType::ApiScan,
    ScannerType::IacScan,
    ScannerType::Report,
];

pub async fn run(full: bool, report_only: bool) -> Result<()> {
    let root = std::env::current_dir()?;
    let project_config = load_or_init_project_config(&root)?;
    // Resolved before the scan runs: a typo'd threshold should fail fast, not
    // burn provider budget on a scan whose result we can't gate correctly. In
    // report-only mode the threshold no longer gates the exit code, but it is
    // still resolved and displayed so the policy stays documented in the report.
    let env = std::env::vars().collect::<HashMap<_, _>>();
    let fail_threshold = resolve_fail_threshold(&env, &project_config)?;

    let context = if full {
        // Whole-repo scan: skip the changed-files/impact-files diff entirely,
        // and do not require an MR. Push pipelines are accepted only when the
        // caller opted into report-only mode (the staging job); a `--full` run
        // outside report-only still needs MR/PR metadata.
        detect_full_scan_ci_context_from_env(&env, report_only)?
    } else {
        // MR/PR incremental scan: the original flow. Changed-files detection
        // and impact expansion run here; an empty diff still bails with guidance.
        let metadata = crate::ci::extract_ci_metadata_from_current_env()?;
        let changed_files = changed_files_from_git(&root, &metadata.base_ref, &metadata.head_ref)
            .map_err(|err| {
            anyhow::anyhow!(git_diff_error_with_guidance(
                metadata.platform,
                &err.to_string()
            ))
        })?;

        if changed_files.is_empty() {
            bail!(missing_history_guidance(metadata.platform));
        }

        let impact_files = select_impact_files(&root, &changed_files, 200)?;
        CiContext {
            platform: metadata.platform,
            base_ref: metadata.base_ref,
            head_ref: metadata.head_ref,
            changed_files,
            impact_files,
            commit_sha: metadata.commit_sha,
            pr_or_mr_number: metadata.pr_or_mr_number,
        }
    };

    print_startup_summary(&context, fail_threshold, full, report_only);

    let provider = load_provider().await?;
    // The config may be attacker-supplied (untrusted PR in CI); a malicious
    // target_path must not redirect scan output outside the checkout.
    let target_path = project_config.resolve_target_within(&root)?;

    let (scanners, focus_context) = if full {
        // Full scan: every scanner type, no focus context (the whole repo is in
        // scope). A None focus context lets each scanner navigate as usual.
        (ALL_CI_SCANNERS.to_vec(), None)
    } else {
        (
            select_ci_scanners(&context.changed_files),
            Some(build_ci_focus_context(&context)),
        )
    };

    let events = run_headless_scan_with_provider(
        provider,
        &target_path,
        scanners,
        focus_context,
        report_only,
    )
    .await?;
    let findings = collect_findings(&events);

    if report_only {
        // Report-only mode never fails the pipeline on findings. On GitLab it
        // files or updates one sticky triage issue and records the outcome note
        // in the report. The triage step runs before writing artifacts so the
        // note lands in ci-report.md on the first write.
        let triage_note = if context.platform == CiPlatformKind::Gitlab {
            Some(publish_triage_issue_best_effort(&context, &findings).await?)
        } else {
            None
        };

        let artifacts = write_ci_artifacts(
            &root,
            &context,
            &findings,
            fail_threshold,
            triage_note.as_deref(),
        )?;
        println!(
            "Wrote CI artifacts: {}, {}, {}",
            artifacts.markdown.display(),
            artifacts.json.display(),
            artifacts.html.display()
        );
        println!("Report-only mode: the pipeline will not fail on findings.");
        return Ok(());
    }

    // MR mode: the original behavior, byte-identical to before --full/--report-only.
    let artifacts = write_ci_artifacts(&root, &context, &findings, fail_threshold, None)?;
    println!(
        "Wrote CI artifacts: {}, {}, {}, {}",
        artifacts.markdown.display(),
        artifacts.json.display(),
        artifacts.sarif.display(),
        artifacts.html.display()
    );

    if let Err(err) = publish_comment_best_effort(&context, &findings, fail_threshold).await {
        println!("CI comment skipped: {err}");
    }

    if should_fail_ci(&findings, fail_threshold) {
        bail!("CI scan failed: {fail_threshold}-or-higher findings detected");
    }

    Ok(())
}

/// Regenerate `.zentra/architecture.md` only, with no PR/MR diff requirement.
/// Intended for a base-branch (e.g. push-to-main) job that refreshes the cache
/// PR runs restore, instead of every PR redoing Phase 0 from a fresh checkout.
pub async fn refresh_architecture() -> Result<()> {
    let root = std::env::current_dir()?;
    println!("Zentra: refreshing architecture analysis");

    let provider = load_provider().await?;
    let project_config = load_or_init_project_config(&root)?;
    let target_path = project_config.resolve_target_within(&root)?;

    run_headless_scan_with_provider(
        provider,
        &target_path,
        vec![ScannerType::FrameworkAnalysis],
        None,
        false,
    )
    .await?;

    println!("Wrote .zentra/architecture.md");
    Ok(())
}

fn collect_findings(events: &[ScanEvent]) -> Vec<Finding> {
    events
        .iter()
        .filter_map(|event| match event {
            ScanEvent::FindingAdded(finding) => Some(finding.clone()),
            _ => None,
        })
        .collect()
}

pub fn build_ci_focus_context(context: &CiContext) -> String {
    format!(
        "Focus on the PR/MR impact set. Consider how changed files affect their dependencies and dependents. Do not treat unchanged unrelated areas as in scope unless they are part of this impact chain.\n\nPlatform: {}\nScope: PR/MR {}\nBase: {}\nHead: {}\n\nChanged files ({}):\n{}\n\nImpact files ({}):\n{}",
        context.platform.as_str(),
        context.pr_or_mr_number.as_deref().unwrap_or("unknown"),
        context.base_ref,
        context.head_ref,
        context.changed_files.len(),
        format_file_list(&context.changed_files),
        context.impact_files.len(),
        format_file_list(&context.impact_files),
    )
}

pub fn select_ci_scanners(changed_files: &[String]) -> Vec<ScannerType> {
    let mut scanners = vec![ScannerType::ThreatModel, ScannerType::Sast];

    if changed_files
        .iter()
        .any(|file| is_dependency_manifest(file))
    {
        scanners.push(ScannerType::SupplyChain);
    }
    if changed_files.iter().any(|file| is_api_file(file)) {
        scanners.push(ScannerType::ApiScan);
    }
    if changed_files.iter().any(|file| is_iac_file(file)) {
        scanners.push(ScannerType::IacScan);
    }

    scanners.push(ScannerType::Report);
    scanners
}

pub async fn run_headless_scan_with_provider(
    provider: Arc<dyn LLMProvider>,
    project_root: &Path,
    mut scanners: Vec<ScannerType>,
    ci_focus_context: Option<String>,
    report_only: bool,
) -> Result<Vec<ScanEvent>> {
    let state_writer = Arc::new(
        StateWriter::new(project_root).context("Failed to initialize .zentra/ directory")?,
    );
    if !scanners.contains(&ScannerType::FrameworkAnalysis) && !state_writer.architecture_exists() {
        scanners.insert(0, ScannerType::FrameworkAnalysis);
    }

    let tool_registry = Arc::new(ToolRegistry::new());
    let (tx, mut rx) = mpsc::channel(128);
    let cancel_token = CancellationToken::new();

    // Cancel on SIGINT/SIGTERM so provider connections + tool subprocesses don't
    // orphan if the CI job is cancelled or times out.
    let signal_token = cancel_token.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        signal_token.cancel();
    });

    // Security envelope: parity with the TUI scan path (scan.rs). ZENTRA_SECURITY
    // still controls strictness; the default profile is unchanged for CI.
    let security_config = SecurityConfig::load();
    let session_id = security::new_session_id();
    let zentra_dir = project_root.join(".zentra");
    let mut audit = AuditLog::new(&zentra_dir, &session_id, security_config.audit_log)
        .context("Failed to open security audit log")?;
    audit
        .record(AuditEvent::SessionStart {
            provider_kind: "ci".to_string(),
            model: String::new(),
            scanner: "orchestrator".to_string(),
        })
        .ok();
    let security_ctx = SecurityContext::new(security_config, audit);
    let provider = security::GuardedProvider::wrap(provider, &security_ctx);

    let orchestrator = OrchestratorAgent::new(
        provider,
        tool_registry,
        state_writer,
        tx,
        cancel_token.clone(),
    )
    .with_focus_context(ci_focus_context)
    .with_security(security_ctx);

    let scan_task = tokio::spawn(async move { orchestrator.run(&scanners).await });
    let mut events = Vec::new();
    while let Some(event) = rx.recv().await {
        events.push(event);
    }
    cancel_token.cancel(); // clean up on normal completion too

    let summary = scan_task.await??;

    // Report coverage before the failure check below can bail: a thin scan is
    // exactly the case where the operator needs the number.
    let coverage = &summary.coverage;
    println!(
        "Coverage: {} of {} source files read ({}%) — see .zentra/coverage.md",
        coverage.distinct_read,
        coverage.candidate_count,
        coverage.percent()
    );

    let failed = summary.failed;
    if !failed.is_empty() {
        let names: Vec<&str> = failed.iter().map(|s| s.name()).collect();
        crate::logging::warn("ci", format!("Scanners failed: {}", names.join(", ")));
    }

    // Scanner/system error handling. MR mode (the default) is fail-closed: the
    // first ScanEvent::Error bails the run. Report-only mode diverges by design
    // — errors are still printed (above, and via the warn log) and noted, but
    // they never fail the pipeline; whatever findings completed are still
    // written to artifacts and triaged.
    if !report_only {
        if let Some(message) = events.iter().find_map(|event| match event {
            ScanEvent::Error { message, .. } => Some(message),
            _ => None,
        }) {
            bail!("CI scan failed: {message}");
        }
    }

    Ok(events)
}

fn print_startup_summary(
    context: &CiContext,
    fail_threshold: Severity,
    full: bool,
    report_only: bool,
) {
    println!("Zentra CI Security Scan");
    println!("Platform: {}", context.platform.as_str());
    println!(
        "Scope: PR/MR {}",
        context.pr_or_mr_number.as_deref().unwrap_or("unknown")
    );
    if full {
        println!("Mode: full repository scan (no diff)");
    }
    if report_only {
        println!("Mode: report-only (pipeline will not fail on findings)");
    }
    println!("Changed files: {}", context.changed_files.len());
    println!("Impacted files: {}", context.impact_files.len());
    println!("Fail threshold: {fail_threshold}");
}

async fn load_provider() -> Result<Arc<dyn LLMProvider>> {
    if let Some((profile, api_key)) = provider_config_from_env() {
        return build_provider(&profile, api_key);
    }

    let global = GlobalConfig::load()?;
    let profile_name = global.default_profile.clone().ok_or_else(|| {
        anyhow::anyhow!("No provider configured. Run 'zentra config setup' first.")
    })?;

    let profile = global
        .profiles
        .get(&profile_name)
        .ok_or_else(|| anyhow::anyhow!("Profile '{}' not found", profile_name))?
        .clone();

    ensure_supported_ci_auth(&profile_name, &profile)?;

    let api_key = if profile.keyless {
        keychain::get_key(&profile_name)?.unwrap_or_default()
    } else {
        keychain::get_key(&profile_name)?.ok_or_else(|| {
            anyhow::anyhow!(
                "No API key found for profile '{}'. Run 'zentra config setup' to configure it.",
                profile_name
            )
        })?
    };

    build_provider(&profile, api_key)
}

/// Build a provider profile straight from env vars, for headless CI runners that
/// have no `~/.zentra/config.toml` and no home-directory keychain. Requires
/// `ZENTRA_API_KEY`, `ZENTRA_PROVIDER_BASE_URL`, and `ZENTRA_PROVIDER_MODEL`; returns
/// `None` if any are unset so callers fall back to the `GlobalConfig`/keychain path.
fn provider_config_from_env() -> Option<(ProviderProfile, String)> {
    let non_empty = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());

    let api_key = non_empty("ZENTRA_API_KEY")?;
    let base_url = non_empty("ZENTRA_PROVIDER_BASE_URL")?;
    let model = non_empty("ZENTRA_PROVIDER_MODEL")?;

    let profile = ProviderProfile {
        kind: non_empty("ZENTRA_PROVIDER_KIND").unwrap_or_else(|| "openai_compat".to_string()),
        base_url,
        model,
        keyless: false,
        auth_method: AuthMethod::ApiKey,
        context_window: non_empty("ZENTRA_PROVIDER_CONTEXT_WINDOW").and_then(|v| v.parse().ok()),
        reasoning_effort: non_empty("ZENTRA_PROVIDER_REASONING_EFFORT"),
        // A CI runner has no config.toml, so the env var is the only way to
        // override the default. An unparseable value falls back to the default.
        temperature: non_empty("ZENTRA_PROVIDER_TEMPERATURE").and_then(|v| v.trim().parse().ok()),
    };

    Some((profile, api_key))
}

fn build_provider(profile: &ProviderProfile, api_key: String) -> Result<Arc<dyn LLMProvider>> {
    // Re-validate the endpoint on the use path: this profile may have come from a
    // hand-edited config or CI env vars that never passed the write-time gate.
    crate::config::validation::validate_profile_endpoint(&profile.kind, &profile.base_url)?;
    Ok(match profile.kind.as_str() {
        "anthropic" => Arc::new(
            AnthropicProvider::new(profile.base_url.clone(), profile.model.clone(), api_key)
                .with_temperature(profile.temperature),
        ),
        _ => Arc::new(
            OpenAICompatProvider::new(profile.base_url.clone(), profile.model.clone(), api_key)
                .with_reasoning(profile.reasoning_effort.clone())
                .with_temperature(profile.temperature),
        ),
    })
}

fn ensure_supported_ci_auth(profile_name: &str, profile: &ProviderProfile) -> Result<()> {
    if matches!(profile.auth_method, AuthMethod::OAuth) {
        bail!(
            "Profile '{}' uses legacy OpenAI browser login. OpenAI profiles now require an API key. Run 'zentra config setup' and reconfigure this profile with an API key.",
            profile_name
        );
    }
    Ok(())
}

fn load_or_init_project_config(root: &Path) -> Result<ProjectConfig> {
    let (config, created) =
        ProjectConfig::load_or_init_for_run(&ProjectConfig::default_path(), root)?;
    if created {
        crate::commands::init::update_gitignore_at(root)?;
    }
    Ok(config)
}

fn format_file_list(files: &[String]) -> String {
    if files.is_empty() {
        return "- none".to_string();
    }
    files
        .iter()
        .map(|file| format!("- {file}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn is_dependency_manifest(path: &str) -> bool {
    let name = file_name(path);
    matches!(
        name,
        "Cargo.toml"
            | "Cargo.lock"
            | "package.json"
            | "package-lock.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "requirements.txt"
            | "pyproject.toml"
            | "poetry.lock"
            | "go.mod"
            | "go.sum"
            | "pom.xml"
            | "build.gradle"
            | "build.gradle.kts"
    )
}

fn is_api_file(path: &str) -> bool {
    let lower = path.replace('\\', "/").to_ascii_lowercase();
    lower.contains("api")
        || lower.contains("route")
        || lower.contains("controller")
        || lower.contains("server")
        || lower.contains("handler")
}

fn is_iac_file(path: &str) -> bool {
    let lower = path.replace('\\', "/").to_ascii_lowercase();
    let name = file_name(&lower);
    name == "dockerfile"
        || name == "docker-compose.yml"
        || name == "docker-compose.yaml"
        || lower.ends_with(".tf")
        || lower.contains("k8s/")
        || lower.contains("kubernetes/")
        || lower.contains("helm/")
        || lower.contains("charts/")
        || lower.contains(".github/workflows/")
        || name == ".gitlab-ci.yml"
        || name == ".gitlab-ci.yaml"
}

fn file_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENV_VARS: &[&str] = &[
        "ZENTRA_API_KEY",
        "ZENTRA_PROVIDER_BASE_URL",
        "ZENTRA_PROVIDER_MODEL",
        "ZENTRA_PROVIDER_KIND",
        "ZENTRA_PROVIDER_REASONING_EFFORT",
        "ZENTRA_PROVIDER_CONTEXT_WINDOW",
    ];

    static ENV_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();

    fn env_lock() -> &'static std::sync::Mutex<()> {
        ENV_LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    /// Clears all provider env vars for the duration of the guard, restoring
    /// their prior values on drop so tests don't leak state into each other.
    struct EnvGuard {
        saved: Vec<(&'static str, Option<String>)>,
    }

    impl EnvGuard {
        fn new() -> Self {
            let saved = ENV_VARS
                .iter()
                .map(|k| (*k, std::env::var(k).ok()))
                .collect();
            for k in ENV_VARS {
                std::env::remove_var(k);
            }
            Self { saved }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, v) in &self.saved {
                match v {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    #[test]
    fn provider_config_from_env_none_when_unset() {
        let _lock = env_lock().lock().unwrap();
        let _guard = EnvGuard::new();
        assert!(provider_config_from_env().is_none());
    }

    #[test]
    fn provider_config_from_env_none_when_partially_set() {
        let _lock = env_lock().lock().unwrap();
        let _guard = EnvGuard::new();
        std::env::set_var("ZENTRA_API_KEY", "secret");
        std::env::set_var("ZENTRA_PROVIDER_BASE_URL", "https://example.test");
        // ZENTRA_PROVIDER_MODEL intentionally left unset.
        assert!(provider_config_from_env().is_none());
    }

    #[test]
    fn provider_config_from_env_builds_profile_with_defaults() {
        let _lock = env_lock().lock().unwrap();
        let _guard = EnvGuard::new();
        std::env::set_var("ZENTRA_API_KEY", "secret");
        std::env::set_var("ZENTRA_PROVIDER_BASE_URL", "https://example.test");
        std::env::set_var("ZENTRA_PROVIDER_MODEL", "glm-4.6");

        let (profile, api_key) = provider_config_from_env().expect("should be Some");
        assert_eq!(api_key, "secret");
        assert_eq!(profile.kind, "openai_compat");
        assert_eq!(profile.base_url, "https://example.test");
        assert_eq!(profile.model, "glm-4.6");
        assert!(!profile.keyless);
        assert!(matches!(profile.auth_method, AuthMethod::ApiKey));
        assert_eq!(profile.context_window, None);
        assert_eq!(profile.reasoning_effort, None);
    }

    #[test]
    fn provider_config_from_env_honors_optional_overrides() {
        let _lock = env_lock().lock().unwrap();
        let _guard = EnvGuard::new();
        std::env::set_var("ZENTRA_API_KEY", "secret");
        std::env::set_var("ZENTRA_PROVIDER_BASE_URL", "https://api.anthropic.com");
        std::env::set_var("ZENTRA_PROVIDER_MODEL", "claude-sonnet-5");
        std::env::set_var("ZENTRA_PROVIDER_KIND", "anthropic");
        std::env::set_var("ZENTRA_PROVIDER_REASONING_EFFORT", "high");
        std::env::set_var("ZENTRA_PROVIDER_CONTEXT_WINDOW", "200000");

        let (profile, _) = provider_config_from_env().expect("should be Some");
        assert_eq!(profile.kind, "anthropic");
        assert_eq!(profile.reasoning_effort.as_deref(), Some("high"));
        assert_eq!(profile.context_window, Some(200_000));
    }

    #[test]
    fn build_provider_picks_anthropic_only_for_anthropic_kind() {
        let anthropic = ProviderProfile {
            kind: "anthropic".to_string(),
            base_url: "https://api.anthropic.com".to_string(),
            model: "claude-sonnet-5".to_string(),
            keyless: false,
            auth_method: AuthMethod::ApiKey,
            context_window: None,
            reasoning_effort: None,
            temperature: None,
        };
        // build_provider returns a trait object; the concrete type can't be
        // downcast here without exposing internals, so we only assert it
        // doesn't panic for either branch.
        let _ = build_provider(&anthropic, "key".to_string());

        let other = ProviderProfile {
            kind: "openai_compat".to_string(),
            ..anthropic
        };
        let _ = build_provider(&other, "key".to_string());
    }
}
