use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::agent::{orchestrator::OrchestratorAgent, ScanEvent, ScannerType};
use crate::ci::{
    changed_files_from_git, git_diff_error_with_guidance, missing_history_guidance,
    publish_comment_best_effort, select_impact_files, should_fail_ci, write_ci_artifacts,
    CiContext,
};
use crate::config::{keychain, AuthMethod, GlobalConfig, ProjectConfig, ProviderProfile};
use crate::provider::{
    anthropic::AnthropicProvider, openai_compat::OpenAICompatProvider, LLMProvider,
};
use crate::security::{self, AuditEvent, AuditLog, SecurityConfig, SecurityContext};
use crate::state::{Finding, Severity, StateWriter};
use crate::tools::ToolRegistry;

pub async fn run() -> Result<()> {
    let root = std::env::current_dir()?;
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
    let context = CiContext {
        platform: metadata.platform,
        base_ref: metadata.base_ref,
        head_ref: metadata.head_ref,
        changed_files,
        impact_files,
        commit_sha: metadata.commit_sha,
        pr_or_mr_number: metadata.pr_or_mr_number,
    };

    print_startup_summary(&context);

    let provider = load_provider().await?;
    let project_config = load_or_init_project_config(&root)?;
    let target_path = root.join(&project_config.target_path);
    let scanners = select_ci_scanners(&context.changed_files);
    let focus_context = build_ci_focus_context(&context);

    let events =
        run_headless_scan_with_provider(provider, &target_path, scanners, Some(focus_context))
            .await?;
    let findings = collect_findings(&events);
    let artifacts = write_ci_artifacts(&root, &context, &findings)?;
    println!(
        "Wrote CI artifacts: {}, {}",
        artifacts.markdown.display(),
        artifacts.json.display()
    );

    if let Err(err) = publish_comment_best_effort(&context, &findings).await {
        println!("CI comment skipped: {err}");
    }

    if should_fail_ci(&findings, Severity::Critical) {
        bail!("CI scan failed: critical findings detected");
    }

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
    let failed = summary.failed;
    if !failed.is_empty() {
        let names: Vec<&str> = failed.iter().map(|s| s.name()).collect();
        crate::logging::warn("ci", format!("Scanners failed: {}", names.join(", ")));
    }

    if let Some(message) = events.iter().find_map(|event| match event {
        ScanEvent::Error { message, .. } => Some(message),
        _ => None,
    }) {
        bail!("CI scan failed: {message}");
    }

    Ok(events)
}

fn print_startup_summary(context: &CiContext) {
    println!("Zentra CI Security Scan");
    println!("Platform: {}", context.platform.as_str());
    println!(
        "Scope: PR/MR {}",
        context.pr_or_mr_number.as_deref().unwrap_or("unknown")
    );
    println!("Changed files: {}", context.changed_files.len());
    println!("Impacted files: {}", context.impact_files.len());
    println!("Fail threshold: Critical");
}

async fn load_provider() -> Result<Arc<dyn LLMProvider>> {
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

    let provider: Arc<dyn LLMProvider> = match profile.kind.as_str() {
        "anthropic" => Arc::new(AnthropicProvider::new(
            profile.base_url.clone(),
            profile.model.clone(),
            api_key,
        )),
        _ => Arc::new(
            OpenAICompatProvider::new(profile.base_url.clone(), profile.model.clone(), api_key)
                .with_reasoning(profile.reasoning_effort.clone()),
        ),
    };

    Ok(provider)
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
    if ProjectConfig::exists() {
        return ProjectConfig::load_from(&ProjectConfig::default_path()).or_else(|_| {
            let stack = ProjectConfig::detect_stack(root);
            let cfg = ProjectConfig::new(&stack, vec![]);
            cfg.save_to(&ProjectConfig::default_path())?;
            Ok(cfg)
        });
    }

    let stack = ProjectConfig::detect_stack(root);
    let config = ProjectConfig::new(&stack, vec![]);
    config.save_to(&ProjectConfig::default_path())?;
    crate::commands::init::update_gitignore_at(root)?;
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
