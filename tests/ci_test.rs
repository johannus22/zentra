use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;
use zentra_cli::agent::{ScanEvent, ScannerType};
use zentra_cli::ci::{
    build_sticky_comment_body, build_triage_issue_body, candidate_git_diff_ranges,
    comment_http_timeout, detect_ci_context_from_env, detect_full_scan_ci_context_from_env,
    finding_fingerprint, generate_ci_workflow_at, git_diff_error_with_guidance,
    gitlab_auth_header_from_env, parse_git_diff_name_only, parse_prior_fingerprints,
    prepare_comment_request_from_env, publish_triage_issue_best_effort, redact_token,
    resolve_fail_threshold, select_impact_files, select_sticky_comment_action, severity_counts,
    should_fail_ci, write_ci_artifacts, CiCommentPlan, CiContext, CiPlatformKind, GitlabAuthHeader,
    StickyCommentAction, TRIAGE_ISSUE_MARKER, FAIL_THRESHOLD_ENV,
};
use zentra_cli::commands::ci::{
    build_ci_focus_context, run_headless_scan_with_provider, select_ci_scanners,
};
use zentra_cli::config::ProjectConfig;
use zentra_cli::provider::{
    AgentMessage, CompletionRequest, CompletionResponse, LLMProvider, TokenUsage, ToolDefinition,
};
use zentra_cli::state::{Finding, Severity};

#[derive(Default)]
struct CapturingProvider {
    systems: Mutex<Vec<String>>,
}

#[async_trait]
impl LLMProvider for CapturingProvider {
    async fn complete(&self, _req: CompletionRequest) -> anyhow::Result<CompletionResponse> {
        Ok(done_response())
    }

    async fn complete_with_tools(
        &self,
        system: &str,
        _messages: &[AgentMessage],
        _tools: &[ToolDefinition],
        _max_tokens: u32,
        _cancel_token: Option<&CancellationToken>,
    ) -> anyhow::Result<CompletionResponse> {
        self.systems.lock().unwrap().push(system.to_string());
        Ok(done_response())
    }

    fn context_window(&self) -> u32 {
        128_000
    }

    fn model_name(&self) -> &str {
        "mock"
    }
}

fn done_response() -> CompletionResponse {
    CompletionResponse {
        content: "done".to_string(),
        tool_calls: Vec::new(),
        usage: TokenUsage::default(),
    }
}

fn sample_context() -> CiContext {
    CiContext {
        platform: CiPlatformKind::Github,
        base_ref: "main".to_string(),
        head_ref: "feature/auth".to_string(),
        changed_files: vec!["src/auth.rs".to_string(), "Cargo.lock".to_string()],
        impact_files: vec!["src/auth.rs".to_string(), "src/routes.rs".to_string()],
        commit_sha: Some("abc123".to_string()),
        pr_or_mr_number: Some("77".to_string()),
    }
}

fn sample_finding(severity: Severity, title: &str) -> Finding {
    Finding {
        scanner: "sast".to_string(),
        severity,
        title: title.to_string(),
        description: "User-controlled input reaches SQL query construction.".to_string(),
        location: Some("src/auth.rs:42".to_string()),
        recommendation: "Use parameterized queries.".to_string(),
        corroborated_by: vec![],
        cwe: None,
        secondary_cwe: vec![],
        cvss_vector: None,
        cvss_score: None,
        owasp: None,
        confidence: None,
        screening: None,
        evidence: None,
    }
}

#[test]
fn detects_github_pull_request_env() {
    let env = HashMap::from([
        ("GITHUB_ACTIONS".to_string(), "true".to_string()),
        ("GITHUB_EVENT_NAME".to_string(), "pull_request".to_string()),
        ("GITHUB_REF".to_string(), "refs/pull/123/merge".to_string()),
        ("GITHUB_BASE_REF".to_string(), "main".to_string()),
        ("GITHUB_HEAD_REF".to_string(), "feature/ci".to_string()),
        ("GITHUB_SHA".to_string(), "abc123".to_string()),
    ]);

    let context = detect_ci_context_from_env(
        &env,
        vec!["src/lib.rs".to_string()],
        vec!["src/lib.rs".to_string()],
    )
    .unwrap();

    assert_eq!(context.platform, CiPlatformKind::Github);
    assert_eq!(context.base_ref, "main");
    assert_eq!(context.head_ref, "feature/ci");
    assert_eq!(context.commit_sha.as_deref(), Some("abc123"));
    assert_eq!(context.pr_or_mr_number.as_deref(), Some("123"));
}

#[test]
fn writes_ci_markdown_and_json_artifacts_with_summary_shape() {
    let dir = TempDir::new().unwrap();
    let context = sample_context();
    let findings = vec![
        sample_finding(Severity::Critical, "SQL injection"),
        sample_finding(Severity::High, "Missing authorization"),
    ];

    let paths =
        write_ci_artifacts(dir.path(), &context, &findings, Severity::Critical, None).unwrap();

    assert_eq!(
        paths.markdown,
        dir.path().join(".zentra").join("ci-report.md")
    );
    assert_eq!(
        paths.json,
        dir.path().join(".zentra").join("ci-report.json")
    );
    assert_eq!(paths.html, dir.path().join(".zentra").join("ci-report.html"));

    let markdown = std::fs::read_to_string(paths.markdown).unwrap();
    let html = std::fs::read_to_string(paths.html).unwrap();
    assert!(html.starts_with("<!DOCTYPE html>"));
    assert!(html.contains("Zentra CI Security Report"));
    assert!(html.contains("github"));
    assert!(html.contains("feature/auth"));
    assert!(html.contains("SQL injection"));
    assert!(html.contains("Missing authorization"));
    assert!(html.contains("src/auth.rs:42"));
    assert!(markdown.contains("# Zentra CI Security Report"));
    assert!(markdown.contains("Platform: github"));
    assert!(markdown.contains("Scope: PR/MR 77"));
    assert!(markdown.contains("Base: main"));
    assert!(markdown.contains("Head: feature/auth"));
    assert!(markdown.contains("Changed files: 2"));
    assert!(markdown.contains("Impact files: 2"));
    assert!(markdown.contains("Fail threshold: CRITICAL"));
    assert!(markdown.contains("Critical: 1"));
    assert!(markdown.contains("High: 1"));
    assert!(markdown.contains("SQL injection"));
    assert!(markdown.contains("src/auth.rs:42"));

    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(paths.json).unwrap()).unwrap();
    assert_eq!(json["context"]["platform"], "github");
    assert_eq!(json["context"]["base_ref"], "main");
    assert_eq!(json["context"]["head_ref"], "feature/auth");
    assert_eq!(json["context"]["changed_files_count"], 2);
    assert_eq!(json["context"]["impact_files_count"], 2);
    assert_eq!(json["fail_threshold"], "CRITICAL");
    assert_eq!(json["summary"]["critical"], 1);
    assert_eq!(json["summary"]["high"], 1);
    assert_eq!(json["findings"][0]["title"], "SQL injection");
}

#[test]
fn severity_summary_counts_all_levels() {
    let counts = severity_counts(&[
        sample_finding(Severity::Critical, "critical"),
        sample_finding(Severity::High, "high"),
        sample_finding(Severity::Medium, "medium"),
        sample_finding(Severity::Low, "low"),
        sample_finding(Severity::Info, "info"),
        sample_finding(Severity::Low, "another low"),
    ]);

    assert_eq!(counts.critical, 1);
    assert_eq!(counts.high, 1);
    assert_eq!(counts.medium, 1);
    assert_eq!(counts.low, 2);
    assert_eq!(counts.info, 1);
}

#[test]
fn critical_only_exit_policy_fails_but_high_only_passes() {
    assert!(should_fail_ci(
        &[sample_finding(Severity::Critical, "critical")],
        Severity::Critical
    ));
    assert!(!should_fail_ci(
        &[sample_finding(Severity::High, "high")],
        Severity::Critical
    ));
}

#[test]
fn high_threshold_also_fails_on_high_findings() {
    assert!(should_fail_ci(
        &[sample_finding(Severity::High, "high")],
        Severity::High
    ));
    assert!(should_fail_ci(
        &[sample_finding(Severity::Critical, "critical")],
        Severity::High
    ));
    assert!(!should_fail_ci(
        &[sample_finding(Severity::Medium, "medium")],
        Severity::High
    ));
}

#[test]
fn severity_parse_is_case_insensitive_and_rejects_unknown_values() {
    assert_eq!(Severity::parse("critical").unwrap().order(), 0);
    assert_eq!(Severity::parse("HIGH").unwrap().order(), 1);
    assert_eq!(Severity::parse("  Medium  ").unwrap().order(), 2);
    assert_eq!(Severity::parse("low").unwrap().order(), 3);
    assert_eq!(Severity::parse("info").unwrap().order(), 4);
    assert!(Severity::parse("severe").is_none());
    assert!(Severity::parse("").is_none());
}

fn project_config_with_threshold(threshold: Option<&str>) -> ProjectConfig {
    ProjectConfig {
        target_path: ".".to_string(),
        stack: "rust".to_string(),
        exclusions: vec![],
        fail_threshold: threshold.map(str::to_string),
    }
}

#[test]
fn resolve_fail_threshold_defaults_to_high_when_unset() {
    let env = HashMap::new();
    let cfg = project_config_with_threshold(None);

    assert_eq!(resolve_fail_threshold(&env, &cfg).unwrap(), Severity::High);
}

#[test]
fn resolve_fail_threshold_honors_project_config_over_default() {
    let env = HashMap::new();
    let cfg = project_config_with_threshold(Some("medium"));

    assert_eq!(
        resolve_fail_threshold(&env, &cfg).unwrap(),
        Severity::Medium
    );
}

#[test]
fn resolve_fail_threshold_env_overrides_project_config() {
    let env = HashMap::from([(FAIL_THRESHOLD_ENV.to_string(), "critical".to_string())]);
    let cfg = project_config_with_threshold(Some("low"));

    assert_eq!(
        resolve_fail_threshold(&env, &cfg).unwrap(),
        Severity::Critical
    );
}

#[test]
fn resolve_fail_threshold_rejects_invalid_env_value() {
    let env = HashMap::from([(FAIL_THRESHOLD_ENV.to_string(), "yolo".to_string())]);
    let cfg = project_config_with_threshold(None);

    let err = resolve_fail_threshold(&env, &cfg).unwrap_err();
    assert!(err.to_string().contains(FAIL_THRESHOLD_ENV));
}

#[test]
fn resolve_fail_threshold_rejects_invalid_project_config_value() {
    let env = HashMap::new();
    let cfg = project_config_with_threshold(Some("yolo"));

    let err = resolve_fail_threshold(&env, &cfg).unwrap_err();
    assert!(err.to_string().contains("fail_threshold"));
}

#[test]
fn comment_request_skips_without_token_or_pr_metadata_and_redacts_tokens() {
    let context = CiContext {
        pr_or_mr_number: None,
        ..sample_context()
    };
    let env = HashMap::new();

    let plan = prepare_comment_request_from_env(&env, &context, &[], Severity::Critical);

    assert!(matches!(plan, CiCommentPlan::Skip { reason } if reason.contains("token")));
    assert_eq!(redact_token("ghp_secret-token"), "[redacted]");
}

#[test]
fn github_comment_request_skips_without_repository_metadata_and_redacts_token() {
    let env = HashMap::from([("GITHUB_TOKEN".to_string(), "ghp_secret-token".to_string())]);

    let plan = prepare_comment_request_from_env(&env, &sample_context(), &[], Severity::Critical);

    match plan {
        CiCommentPlan::Skip { reason } => {
            assert!(reason.contains("GITHUB_REPOSITORY"), "{reason}");
            assert!(!reason.contains("ghp_secret-token"), "{reason}");
        }
        CiCommentPlan::Publish { .. } => panic!("expected missing repository metadata to skip"),
    }
}

#[test]
fn gitlab_comment_request_skips_without_project_metadata_and_redacts_token() {
    let context = CiContext {
        platform: CiPlatformKind::Gitlab,
        pr_or_mr_number: Some("42".to_string()),
        ..sample_context()
    };
    let env = HashMap::from([("GITLAB_TOKEN".to_string(), "glpat_secret-token".to_string())]);

    let plan = prepare_comment_request_from_env(&env, &context, &[], Severity::Critical);

    match plan {
        CiCommentPlan::Skip { reason } => {
            assert!(reason.contains("CI_PROJECT_ID"), "{reason}");
            assert!(!reason.contains("glpat_secret-token"), "{reason}");
        }
        CiCommentPlan::Publish { .. } => panic!("expected missing project metadata to skip"),
    }
}

#[test]
fn gitlab_comment_auth_header_uses_bearer_for_gitlab_token() {
    let env = HashMap::from([("GITLAB_TOKEN".to_string(), "glpat_secret-token".to_string())]);

    let header = gitlab_auth_header_from_env(&env).unwrap();

    assert_eq!(
        header,
        GitlabAuthHeader {
            name: "Authorization",
            value: "Bearer glpat_secret-token".to_string(),
        }
    );
}

#[test]
fn gitlab_comment_auth_header_uses_job_token_for_ci_job_token() {
    let env = HashMap::from([("CI_JOB_TOKEN".to_string(), "job-secret-token".to_string())]);

    let header = gitlab_auth_header_from_env(&env).unwrap();

    assert_eq!(
        header,
        GitlabAuthHeader {
            name: "JOB-TOKEN",
            value: "job-secret-token".to_string(),
        }
    );
}

#[test]
fn gitlab_comment_auth_header_prefers_gitlab_token_when_both_are_present() {
    let env = HashMap::from([
        ("GITLAB_TOKEN".to_string(), "glpat_secret-token".to_string()),
        ("CI_JOB_TOKEN".to_string(), "job-secret-token".to_string()),
    ]);

    let header = gitlab_auth_header_from_env(&env).unwrap();

    assert_eq!(header.name, "Authorization");
    assert_eq!(header.value, "Bearer glpat_secret-token");
}

#[test]
fn comment_http_timeout_is_bounded_for_best_effort_requests() {
    assert_eq!(comment_http_timeout(), std::time::Duration::from_secs(10));
}

#[test]
fn sticky_comment_body_lists_every_finding_with_severity_location_and_artifacts() {
    let body = build_sticky_comment_body(
        &sample_context(),
        &[
            sample_finding(Severity::Critical, "SQL injection"),
            sample_finding(Severity::Low, "Verbose error"),
        ],
        Severity::Critical,
    );

    assert!(body.contains("<!-- zentra-ci-comment -->"));
    assert!(body.contains("❌ Failed"));
    assert!(body.contains("2 total"));
    assert!(body.contains("🔴 1 Critical"));
    assert!(body.contains("🔵 1 Low"));
    assert!(body.contains("| 🔴 CRITICAL | SQL injection | `src/auth.rs:42` |"));
    assert!(body.contains("| 🔵 LOW | Verbose error | `src/auth.rs:42` |"));
    assert!(body.contains(".zentra/ci-report.md"));
    assert!(body.contains(".zentra/ci-report.json"));
    assert!(body.contains("Fail threshold: CRITICAL"));
}

#[test]
fn sticky_comment_body_shows_passed_status_and_no_critical_rows_when_none_found() {
    let body = build_sticky_comment_body(
        &sample_context(),
        &[sample_finding(Severity::Low, "Verbose error")],
        Severity::Critical,
    );

    assert!(body.contains("✅ Passed"));
    assert!(!body.contains("❌ Failed"));
    assert!(!body.contains("| 🔴 CRITICAL |"));
}

#[test]
fn sticky_comment_body_reports_no_findings_when_scan_is_clean() {
    let body = build_sticky_comment_body(&sample_context(), &[], Severity::Critical);

    assert!(body.contains("✅ Passed"));
    assert!(body.contains("0 total"));
    assert!(body.contains("No findings."));
}

#[test]
fn sticky_comment_body_fails_on_high_when_threshold_is_high() {
    let body = build_sticky_comment_body(
        &sample_context(),
        &[sample_finding(Severity::High, "Missing authorization")],
        Severity::High,
    );

    assert!(body.contains("❌ Failed"));
    assert!(body.contains("Fix 1 HIGH-or-higher finding before you merge this."));
    assert!(body.contains("Fail threshold: HIGH"));
}

#[test]
fn sticky_comment_action_updates_existing_marker_comment_or_creates_new_one() {
    let update = select_sticky_comment_action(
        &[
            (10, "human comment".to_string()),
            (11, "<!-- zentra-ci-comment -->\nold body".to_string()),
        ],
        "new body".to_string(),
    );
    assert_eq!(
        update,
        StickyCommentAction::Update {
            id: 11,
            body: "new body".to_string()
        }
    );

    let create =
        select_sticky_comment_action(&[(10, "human comment".to_string())], "new body".to_string());
    assert_eq!(
        create,
        StickyCommentAction::Create {
            body: "new body".to_string()
        }
    );
}

#[test]
fn detects_gitlab_merge_request_env() {
    let env = HashMap::from([
        ("GITLAB_CI".to_string(), "true".to_string()),
        ("CI_MERGE_REQUEST_IID".to_string(), "42".to_string()),
        (
            "CI_MERGE_REQUEST_TARGET_BRANCH_NAME".to_string(),
            "main".to_string(),
        ),
        (
            "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME".to_string(),
            "feature/gitlab".to_string(),
        ),
        ("CI_COMMIT_SHA".to_string(), "def456".to_string()),
    ]);

    let context = detect_ci_context_from_env(
        &env,
        vec!["src/lib.rs".to_string()],
        vec!["src/lib.rs".to_string()],
    )
    .unwrap();

    assert_eq!(context.platform, CiPlatformKind::Gitlab);
    assert_eq!(context.base_ref, "main");
    assert_eq!(context.head_ref, "feature/gitlab");
    assert_eq!(context.commit_sha.as_deref(), Some("def456"));
    assert_eq!(context.pr_or_mr_number.as_deref(), Some("42"));
}

#[test]
fn rejects_branch_push_without_pr_or_mr_metadata() {
    let env = HashMap::from([
        ("GITHUB_ACTIONS".to_string(), "true".to_string()),
        ("GITHUB_EVENT_NAME".to_string(), "push".to_string()),
        ("GITHUB_SHA".to_string(), "abc123".to_string()),
    ]);

    let err = detect_ci_context_from_env(&env, Vec::new(), Vec::new()).unwrap_err();

    assert_eq!(
        err.to_string(),
        "Zentra CI supports pull request and merge request pipelines only."
    );
}

#[test]
fn git_diff_error_preserves_underlying_error_and_appends_guidance() {
    let message = git_diff_error_with_guidance(
        CiPlatformKind::Github,
        "fatal: ambiguous argument 'main...feature': unknown revision",
    );

    assert!(message.contains("fatal: ambiguous argument"));
    assert!(message.contains("fetch-depth: 0"));
}

#[test]
fn parses_git_diff_name_only_output() {
    let changed = parse_git_diff_name_only("src/lib.rs\r\n\nCargo.toml\nsrc/main.rs\n");

    assert_eq!(changed, vec!["src/lib.rs", "Cargo.toml", "src/main.rs"]);
}

#[test]
fn candidate_git_diff_ranges_prefer_origin_base_to_head_for_branch_refs() {
    let ranges = candidate_git_diff_ranges("main", "feature/ci");

    let origin_head = ranges
        .iter()
        .position(|range| range == "origin/main...HEAD")
        .unwrap();
    let raw_branch_pair = ranges
        .iter()
        .position(|range| range == "main...feature/ci")
        .unwrap();

    assert!(origin_head < raw_branch_pair, "{ranges:?}");
}

// Iter-3 defense-in-depth: no candidate range may start with '-' (git would treat
// it as an option), even for a pathological dash-leading base ref.
#[test]
fn candidate_git_diff_ranges_never_start_with_dash() {
    let ranges = candidate_git_diff_ranges("-oProxy", "-evil");
    assert!(
        ranges.iter().all(|r| !r.starts_with('-')),
        "a range started with '-': {ranges:?}"
    );
}

#[test]
fn candidate_git_diff_ranges_normalize_full_base_branch_refs() {
    let ranges = candidate_git_diff_ranges("refs/heads/main", "refs/heads/feature/ci");

    assert!(
        ranges.contains(&"origin/main...HEAD".to_string()),
        "{ranges:?}"
    );
    assert!(
        !ranges.contains(&"origin/refs/heads/main...HEAD".to_string()),
        "{ranges:?}"
    );
}

#[test]
fn missing_history_guidance_mentions_platform_fetch_depth() {
    let github_err = detect_ci_context_from_env(
        &HashMap::from([
            ("GITHUB_ACTIONS".to_string(), "true".to_string()),
            ("GITHUB_EVENT_NAME".to_string(), "pull_request".to_string()),
            ("GITHUB_BASE_REF".to_string(), "main".to_string()),
            ("GITHUB_HEAD_REF".to_string(), "feature/ci".to_string()),
        ]),
        Vec::new(),
        Vec::new(),
    )
    .unwrap_err();
    assert!(github_err.to_string().contains("fetch-depth: 0"));

    let gitlab_err = detect_ci_context_from_env(
        &HashMap::from([
            ("GITLAB_CI".to_string(), "true".to_string()),
            ("CI_MERGE_REQUEST_IID".to_string(), "42".to_string()),
            (
                "CI_MERGE_REQUEST_TARGET_BRANCH_NAME".to_string(),
                "main".to_string(),
            ),
            (
                "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME".to_string(),
                "feature/gitlab".to_string(),
            ),
        ]),
        Vec::new(),
        Vec::new(),
    )
    .unwrap_err();
    assert!(gitlab_err.to_string().contains("GIT_DEPTH: \"0\""));
}

#[test]
fn impact_expands_to_manifest_config_imports_and_dependents() {
    let dir = TempDir::new().unwrap();
    std::fs::create_dir_all(dir.path().join("src")).unwrap();
    std::fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"demo\"\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("zentra.yml"), "scan: true\n").unwrap();
    std::fs::write(dir.path().join("src/shared.rs"), "pub fn helper() {}\n").unwrap();
    std::fs::write(
        dir.path().join("src/main.rs"),
        "mod shared;\nfn main() { shared::helper(); }\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("src/feature.rs"),
        "use crate::shared;\npub fn run() { shared::helper(); }\n",
    )
    .unwrap();

    let impact = select_impact_files(
        dir.path(),
        &["src/shared.rs".to_string(), "Cargo.toml".to_string()],
        10,
    )
    .unwrap();

    assert!(impact.contains(&"src/shared.rs".to_string()));
    assert!(impact.contains(&"Cargo.toml".to_string()));
    assert!(impact.contains(&"zentra.yml".to_string()));
    assert!(impact.contains(&"src/main.rs".to_string()));
    assert!(impact.contains(&"src/feature.rs".to_string()));
}

#[tokio::test]
async fn ci_focus_context_is_injected_with_architecture_context() {
    let dir = TempDir::new().unwrap();
    let provider = Arc::new(CapturingProvider::default());
    let context = CiContext {
        platform: CiPlatformKind::Github,
        base_ref: "main".to_string(),
        head_ref: "feature/auth".to_string(),
        changed_files: vec!["src/auth.rs".to_string()],
        impact_files: vec!["src/auth.rs".to_string(), "src/routes.rs".to_string()],
        commit_sha: Some("abc123".to_string()),
        pr_or_mr_number: Some("77".to_string()),
    };

    std::fs::create_dir_all(dir.path().join(".zentra")).unwrap();
    std::fs::write(
        dir.path().join(".zentra").join("architecture.md"),
        "Project uses Axum route handlers",
    )
    .unwrap();

    let focus_context = build_ci_focus_context(&context);
    let events = run_headless_scan_with_provider(
        provider.clone(),
        dir.path(),
        vec![ScannerType::Sast],
        Some(focus_context),
        false,
    )
    .await
    .unwrap();

    assert!(events
        .iter()
        .any(|event| matches!(event, ScanEvent::ScannerCompleted(ScannerType::Sast))));

    let systems = provider.systems.lock().unwrap();
    let prompt = systems.join("\n---\n");
    assert!(
        prompt.contains("Project uses Axum route handlers"),
        "{prompt}"
    );
    assert!(
        prompt.contains("Focus on the PR/MR impact set. Consider how changed files affect their dependencies and dependents. Do not treat unchanged unrelated areas as in scope unless they are part of this impact chain."),
        "{prompt}"
    );
    assert!(prompt.contains("Base: main"), "{prompt}");
    assert!(prompt.contains("Head: feature/auth"), "{prompt}");
    assert!(prompt.contains("Changed files"), "{prompt}");
    assert!(prompt.contains("src/auth.rs"), "{prompt}");
    assert!(prompt.contains("Impact files"), "{prompt}");
    assert!(prompt.contains("src/routes.rs"), "{prompt}");
}

#[test]
fn selects_ci_scanners_from_changed_files() {
    let scanners = select_ci_scanners(&[
        "src/routes/user_controller.rs".to_string(),
        "Cargo.lock".to_string(),
        "Dockerfile".to_string(),
        ".github/workflows/zentra.yml".to_string(),
    ]);

    assert_eq!(scanners.first(), Some(&ScannerType::ThreatModel));
    assert!(scanners.contains(&ScannerType::Sast));
    assert!(scanners.contains(&ScannerType::SupplyChain));
    assert!(scanners.contains(&ScannerType::ApiScan));
    assert!(scanners.contains(&ScannerType::IacScan));
    assert_eq!(scanners.last(), Some(&ScannerType::Report));
}

#[tokio::test]
async fn headless_ci_scan_collects_events_without_tui() {
    let dir = TempDir::new().unwrap();
    let provider = Arc::new(CapturingProvider::default());

    let events = run_headless_scan_with_provider(
        provider,
        Path::new(dir.path()),
        vec![ScannerType::ThreatModel, ScannerType::Report],
        None,
        false,
    )
    .await
    .unwrap();

    assert!(events
        .iter()
        .any(|event| matches!(event, ScanEvent::ScannerStarted(ScannerType::ThreatModel))));
    assert!(events
        .iter()
        .any(|event| matches!(event, ScanEvent::ScannerCompleted(ScannerType::Report))));
    assert!(events
        .iter()
        .all(|event| !matches!(event, ScanEvent::Error { .. })));
}

#[tokio::test]
async fn headless_ci_scan_runs_framework_analysis_first_when_architecture_is_missing() {
    let dir = TempDir::new().unwrap();
    let provider = Arc::new(CapturingProvider::default());

    let events = run_headless_scan_with_provider(
        provider,
        Path::new(dir.path()),
        vec![ScannerType::ThreatModel, ScannerType::Report],
        None,
        false,
    )
    .await
    .unwrap();

    let started = events
        .iter()
        .filter_map(|event| match event {
            ScanEvent::ScannerStarted(scanner) => Some(*scanner),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert_eq!(started.first(), Some(&ScannerType::FrameworkAnalysis));
    assert_eq!(
        started
            .iter()
            .filter(|scanner| **scanner == ScannerType::FrameworkAnalysis)
            .count(),
        1
    );
}

#[tokio::test]
async fn headless_ci_scan_does_not_add_framework_analysis_when_architecture_exists() {
    let dir = TempDir::new().unwrap();
    std::fs::create_dir_all(dir.path().join(".zentra")).unwrap();
    std::fs::write(dir.path().join(".zentra").join("architecture.md"), "known").unwrap();
    let provider = Arc::new(CapturingProvider::default());

    let events = run_headless_scan_with_provider(
        provider,
        Path::new(dir.path()),
        vec![ScannerType::ThreatModel, ScannerType::Report],
        None,
        false,
    )
    .await
    .unwrap();

    assert!(!events.iter().any(|event| matches!(
        event,
        ScanEvent::ScannerStarted(ScannerType::FrameworkAnalysis)
    )));
}

#[test]
fn generates_github_workflow() {
    let dir = TempDir::new().unwrap();

    generate_ci_workflow_at(dir.path(), CiPlatformKind::Github).unwrap();

    let workflow_path = dir.path().join(".github/workflows/zentra.yml");
    assert!(workflow_path.exists());
    let workflow = std::fs::read_to_string(workflow_path).unwrap();
    assert!(workflow.contains("pull_request:"));
    assert!(workflow.contains("actions/checkout@v4"));
    assert!(workflow.contains("fetch-depth: 0"));
    assert!(workflow.contains("contents: read"));
    assert!(workflow.contains("pull-requests: write"));
    assert!(workflow.contains("zentra ci"));
    assert!(workflow.contains(".zentra/ci-report.md"));
    assert!(workflow.contains(".zentra/ci-report.json"));
}

#[test]
fn generates_minimal_gitlab_ci() {
    let dir = TempDir::new().unwrap();

    generate_ci_workflow_at(dir.path(), CiPlatformKind::Gitlab).unwrap();

    let workflow_path = dir.path().join(".gitlab-ci.yml");
    assert!(workflow_path.exists());
    let workflow = std::fs::read_to_string(workflow_path).unwrap();
    assert!(workflow.contains("zentra_security_scan:"));
    assert!(workflow.contains("merge_request_event"));
    assert!(workflow.contains("GIT_DEPTH: \"0\""));
    assert!(workflow.contains("zentra ci"));
    assert!(workflow.contains(".zentra/ci-report.md"));
    assert!(workflow.contains(".zentra/ci-report.json"));
}

#[test]
fn does_not_overwrite_existing_github_workflow() {
    let dir = TempDir::new().unwrap();
    let workflow_dir = dir.path().join(".github/workflows");
    std::fs::create_dir_all(&workflow_dir).unwrap();
    let workflow_path = workflow_dir.join("zentra.yml");
    std::fs::write(&workflow_path, "name: Existing\n").unwrap();

    let err = generate_ci_workflow_at(dir.path(), CiPlatformKind::Github).unwrap_err();

    assert!(err.to_string().contains("already exists"));
    assert_eq!(
        std::fs::read_to_string(workflow_path).unwrap(),
        "name: Existing\n"
    );
}

#[test]
fn does_not_overwrite_existing_gitlab_ci() {
    let dir = TempDir::new().unwrap();
    let workflow_path = dir.path().join(".gitlab-ci.yml");
    std::fs::write(&workflow_path, "existing: true\n").unwrap();

    let err = generate_ci_workflow_at(dir.path(), CiPlatformKind::Gitlab).unwrap_err();

    assert!(err.to_string().contains("already exists"));
    assert_eq!(
        std::fs::read_to_string(workflow_path).unwrap(),
        "existing: true\n"
    );
}

// ---------------------------------------------------------------------------
// Full-scan + report-only / GitLab triage ticket
// ---------------------------------------------------------------------------

fn gitlab_push_env(branch: &str) -> HashMap<String, String> {
    HashMap::from([
        ("GITLAB_CI".to_string(), "true".to_string()),
        ("CI_PIPELINE_SOURCE".to_string(), "push".to_string()),
        ("CI_COMMIT_BRANCH".to_string(), branch.to_string()),
        ("CI_COMMIT_SHA".to_string(), "feedface".to_string()),
        ("CI_PROJECT_ID".to_string(), "42".to_string()),
    ])
}

fn triage_context(branch: &str) -> CiContext {
    CiContext {
        platform: CiPlatformKind::Gitlab,
        base_ref: branch.to_string(),
        head_ref: branch.to_string(),
        changed_files: vec![],
        impact_files: vec![],
        commit_sha: Some("feedface".to_string()),
        pr_or_mr_number: None,
    }
}

fn triage_finding(severity: Severity, title: &str, location: &str) -> Finding {
    Finding {
        scanner: "sast".to_string(),
        severity,
        title: title.to_string(),
        description: "User input reaches a dangerous sink.".to_string(),
        location: Some(location.to_string()),
        recommendation: "Validate and sanitize the input.".to_string(),
        corroborated_by: vec![],
        cwe: Some("CWE-89".to_string()),
        secondary_cwe: vec![],
        cvss_vector: None,
        cvss_score: None,
        owasp: None,
        confidence: None,
        screening: None,
        evidence: None,
    }
}

#[test]
fn fingerprint_is_stable_across_calls_and_distinct_across_inputs() {
    let f = triage_finding(Severity::Critical, "SQL injection", "src/db.rs:10");
    let fp1 = finding_fingerprint(&f);
    let fp2 = finding_fingerprint(&f);

    assert_eq!(fp1, fp2, "fingerprint must be deterministic");
    assert_eq!(fp1.len(), 16, "fingerprint must be 16 hex chars");

    let mut moved = f.clone();
    moved.title = "SQL injection v2".to_string();
    assert_ne!(finding_fingerprint(&moved), fp1, "title change must change fp");

    let mut moved = f.clone();
    moved.location = Some("src/db.rs:99".to_string());
    assert_ne!(
        finding_fingerprint(&moved),
        fp1,
        "location change must change fp"
    );

    let mut moved = f.clone();
    moved.scanner = "iac_scan".to_string();
    assert_ne!(
        finding_fingerprint(&moved),
        fp1,
        "scanner change must change fp"
    );
}

#[test]
fn parse_prior_fingerprints_returns_empty_for_garbage_bodies() {
    assert!(parse_prior_fingerprints("just prose, no marker").is_empty());
    assert!(parse_prior_fingerprints("<!-- zentra-fingerprints: not json -->").is_empty());
    assert!(parse_prior_fingerprints("<!-- zentra-fingerprints: [1, 2").is_empty());
}

#[test]
fn triage_body_roundtrips_fingerprints_and_lists_only_new_findings() {
    let context = triage_context("staging");
    let findings = vec![
        triage_finding(Severity::Critical, "SQL injection", "src/db.rs:10"),
        triage_finding(Severity::High, "Missing authz", "src/api.rs:4"),
    ];

    // Simulate a second run where only the High finding is new.
    let critical_fp = finding_fingerprint(&findings[0]);
    let new_fingerprints = vec![finding_fingerprint(&findings[1])];

    let body = build_triage_issue_body(&context, &findings, &new_fingerprints);

    // Marker present.
    assert!(body.contains(TRIAGE_ISSUE_MARKER), "{body}");

    // "New since last run" lists only the new (High) finding. The full findings
    // table below legitimately still contains the old one, so scope the check to
    // the section between the header and the "All findings" table.
    let new_section = body
        .split("## New since last run")
        .nth(1)
        .and_then(|s| s.split("## All findings").next())
        .unwrap_or("");
    assert!(new_section.contains("Missing authz"), "{new_section}");
    assert!(
        !new_section.contains("SQL injection"),
        "old finding must not be listed as new: {new_section}"
    );

    // The full findings table still holds every finding.
    let all_section = body.split("## All findings").nth(1).unwrap_or("");
    assert!(all_section.contains("SQL injection"), "{all_section}");
    assert!(all_section.contains("Missing authz"), "{all_section}");

    // Hidden fingerprints comment holds ALL current fingerprints.
    let parsed = parse_prior_fingerprints(&body);
    assert_eq!(parsed.len(), 2, "{parsed:?}");
    assert!(parsed.contains(&critical_fp), "{parsed:?}");
}

#[test]
fn triage_body_with_zero_findings_states_clean_scan() {
    let context = triage_context("staging");
    let body = build_triage_issue_body(&context, &[], &[]);

    assert!(body.contains(TRIAGE_ISSUE_MARKER), "{body}");
    assert!(body.contains("clean"), "{body}");
    // Fingerprints array is present but empty.
    let parsed = parse_prior_fingerprints(&body);
    assert!(parsed.is_empty(), "{parsed:?}");
}

#[test]
fn gitlab_push_pipeline_accepted_when_push_allowed() {
    let env = gitlab_push_env("staging");

    let context = detect_full_scan_ci_context_from_env(&env, true).unwrap();

    assert_eq!(context.platform, CiPlatformKind::Gitlab);
    assert_eq!(context.base_ref, "staging");
    assert_eq!(context.head_ref, "staging");
    assert_eq!(context.commit_sha.as_deref(), Some("feedface"));
    assert!(context.pr_or_mr_number.is_none());
    assert!(context.changed_files.is_empty());
    assert!(context.impact_files.is_empty());
}

#[test]
fn gitlab_push_pipeline_rejected_when_push_not_allowed() {
    let env = gitlab_push_env("staging");

    let err = detect_full_scan_ci_context_from_env(&env, false).unwrap_err();

    assert_eq!(
        err.to_string(),
        "Zentra CI supports pull request and merge request pipelines only."
    );
}

#[test]
fn gitlab_mr_pipeline_path_unchanged_for_full_scan() {
    // A merge request env (with CI_MERGE_REQUEST_IID) is still accepted by the
    // full-scan path even without push — the MR path is the default.
    let env = HashMap::from([
        ("GITLAB_CI".to_string(), "true".to_string()),
        ("CI_MERGE_REQUEST_IID".to_string(), "7".to_string()),
        (
            "CI_MERGE_REQUEST_TARGET_BRANCH_NAME".to_string(),
            "main".to_string(),
        ),
        (
            "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME".to_string(),
            "feature/x".to_string(),
        ),
        ("CI_COMMIT_SHA".to_string(), "abc".to_string()),
    ]);

    let context = detect_full_scan_ci_context_from_env(&env, false).unwrap();

    assert_eq!(context.platform, CiPlatformKind::Gitlab);
    assert_eq!(context.pr_or_mr_number.as_deref(), Some("7"));
    assert_eq!(context.base_ref, "main");
    assert_eq!(context.head_ref, "feature/x");
}

#[test]
fn gitlab_ci_workflow_includes_staging_full_scan_job() {
    let dir = TempDir::new().unwrap();

    generate_ci_workflow_at(dir.path(), CiPlatformKind::Gitlab).unwrap();

    let workflow = std::fs::read_to_string(dir.path().join(".gitlab-ci.yml")).unwrap();
    assert!(workflow.contains("zentra_full_scan_staging:"), "{workflow}");
    assert!(workflow.contains("CI_COMMIT_BRANCH == \"staging\""), "{workflow}");
    assert!(workflow.contains("allow_failure: true"), "{workflow}");
    assert!(workflow.contains("zentra ci --full --report-only"), "{workflow}");
    // Original MR job is still present.
    assert!(workflow.contains("zentra_security_scan:"), "{workflow}");
    assert!(workflow.contains("merge_request_event"), "{workflow}");
}

#[test]
fn ci_report_includes_triage_note_line_when_provided() {
    let dir = TempDir::new().unwrap();
    let context = sample_context();

    let paths = write_ci_artifacts(
        dir.path(),
        &context,
        &[sample_finding(Severity::Critical, "SQL injection")],
        Severity::Critical,
        Some("created issue #99"),
    )
    .unwrap();

    let markdown = std::fs::read_to_string(paths.markdown).unwrap();
    assert!(markdown.contains("Triage ticket: created issue #99"), "{markdown}");
}

#[test]
fn ci_report_omits_triage_note_line_when_none() {
    let dir = TempDir::new().unwrap();
    let context = sample_context();

    let paths = write_ci_artifacts(
        dir.path(),
        &context,
        &[sample_finding(Severity::Critical, "SQL injection")],
        Severity::Critical,
        None,
    )
    .unwrap();

    let markdown = std::fs::read_to_string(paths.markdown).unwrap();
    assert!(!markdown.contains("Triage ticket:"), "{markdown}");
}

#[tokio::test]
async fn triage_creates_issue_when_no_sticky_exists() {
    use wiremock::matchers::{header, method, path, query_param};

    let server = wiremock::MockServer::start().await;

    // No open issues with our label yet.
    wiremock::Mock::given(method("GET"))
        .and(path("/projects/42/issues"))
        .and(query_param("labels", "zentra-triage"))
        .and(query_param("state", "opened"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("[]"))
        .mount(&server)
        .await;

    // Token-owner lookup → id 55.
    wiremock::Mock::given(method("GET"))
        .and(path("/user"))
        .and(header("Authorization", "Bearer glpat-secret"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(r#"{"id":55,"username":"sec"}"#))
        .mount(&server)
        .await;

    // Issue creation → iid 12.
    wiremock::Mock::given(method("POST"))
        .and(path("/projects/42/issues"))
        .respond_with(
            wiremock::ResponseTemplate::new(201)
                .set_body_string(r#"{"iid":12,"title":"x"}"#),
        )
        .mount(&server)
        .await;

    let context = triage_context("staging");
    let env_set = env_with_token("glpat-secret", &server.uri());
    let _guard = set_triage_env(&env_set);

    let findings = vec![triage_finding(Severity::High, "Missing authz", "src/api.rs:4")];
    let note = publish_triage_issue_best_effort(&context, &findings)
        .await
        .unwrap();

    assert_eq!(note, "created issue #12");

    // The POST body must carry the labels and the resolved assignee id.
    let posts: Vec<wiremock::Request> = server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.method.as_str() == "POST" && r.url.as_str().contains("/projects/42/issues"))
        .collect();
    assert_eq!(posts.len(), 1);
    let body = String::from_utf8_lossy(&posts[0].body);
    assert!(body.contains("\"labels\":\"security,zentra-triage\""), "{body}");
    assert!(body.contains("\"assignee_ids\":[55]"), "{body}");
    assert!(body.contains(TRIAGE_ISSUE_MARKER), "{body}");
}

#[tokio::test]
async fn triage_updates_existing_sticky_issue() {
    use wiremock::matchers::{method, path};

    let server = wiremock::MockServer::start().await;

    // The sticky issue already exists, with a prior fingerprint for the old
    // finding so only the new one is flagged as "new". Build the response body
    // via serde_json to avoid raw-string brace escaping mistakes.
    let prior_body = format!(
        "{TRIAGE_ISSUE_MARKER}\nold\n<!-- zentra-fingerprints: [\"{}\"] -->",
        finding_fingerprint(&triage_finding(Severity::Critical, "OLD", "src/x.rs:1"))
    );
    let issues_body = serde_json::json!([{
        "iid": 33,
        "description": prior_body,
    }])
    .to_string();
    wiremock::Mock::given(method("GET"))
        .and(path("/projects/42/issues"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(issues_body))
        .mount(&server)
        .await;

    wiremock::Mock::given(method("GET"))
        .and(path("/user"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(r#"{"id":7}"#))
        .mount(&server)
        .await;

    // PUT update on the existing iid.
    wiremock::Mock::given(method("PUT"))
        .and(path("/projects/42/issues/33"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(r#"{"iid":33}"#))
        .mount(&server)
        .await;

    let context = triage_context("staging");
    let env_set = env_with_token("glpat-secret", &server.uri());
    let _guard = set_triage_env(&env_set);

    let findings = vec![
        triage_finding(Severity::Critical, "OLD", "src/x.rs:1"),
        triage_finding(Severity::High, "NEW", "src/y.rs:2"),
    ];
    let note = publish_triage_issue_best_effort(&context, &findings)
        .await
        .unwrap();

    assert_eq!(note, "updated issue #33");

    // Exactly one PUT to the right iid, and no POST (no create).
    let requests = server.received_requests().await.unwrap();
    assert!(
        requests.iter().any(|r| r.method.as_str() == "PUT"
            && r.url.as_str().contains("/projects/42/issues/33")),
        "expected a PUT to /projects/42/issues/33"
    );
    assert!(
        !requests.iter().any(|r| r.method.as_str() == "POST"),
        "must not POST-create when a sticky issue exists"
    );
}

#[tokio::test]
async fn triage_assignee_resolution_uses_env_username_lookup() {
    use wiremock::matchers::{method, path, query_param};

    let server = wiremock::MockServer::start().await;

    wiremock::Mock::given(method("GET"))
        .and(path("/projects/42/issues"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("[]"))
        .mount(&server)
        .await;

    // ZENTRA_TRIAGE_ASSIGNEE path: GET /users?username=sec-engineer → id 88.
    wiremock::Mock::given(method("GET"))
        .and(path("/users"))
        .and(query_param("username", "sec-engineer"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_string(r#"[{"id":88,"username":"sec-engineer"}]"#),
        )
        .mount(&server)
        .await;

    wiremock::Mock::given(method("POST"))
        .and(path("/projects/42/issues"))
        .respond_with(
            wiremock::ResponseTemplate::new(201).set_body_string(r#"{"iid":5}"#),
        )
        .mount(&server)
        .await;

    let context = triage_context("staging");
    let mut env_set = env_with_token("glpat-secret", &server.uri());
    env_set.insert(
        "ZENTRA_TRIAGE_ASSIGNEE".to_string(),
        "sec-engineer".to_string(),
    );
    let _guard = set_triage_env(&env_set);

    let note = publish_triage_issue_best_effort(
        &context,
        &[triage_finding(Severity::High, "X", "a.rs:1")],
    )
    .await
    .unwrap();

    assert_eq!(note, "created issue #5");

    let posts: Vec<wiremock::Request> = server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.method.as_str() == "POST")
        .collect();
    let body = String::from_utf8_lossy(&posts[0].body);
    assert!(body.contains("\"assignee_ids\":[88]"), "{body}");
}

#[tokio::test]
async fn triage_skips_without_token_and_makes_no_http_calls() {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::any())
        .respond_with(wiremock::ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let context = triage_context("staging");
    // No GITLAB_TOKEN, no CI_JOB_TOKEN.
    let mut env_set = HashMap::new();
    env_set.insert("CI_API_V4_URL".to_string(), server.uri());
    env_set.insert("CI_PROJECT_ID".to_string(), "42".to_string());
    let _guard = set_triage_env(&env_set);

    let note = publish_triage_issue_best_effort(
        &context,
        &[triage_finding(Severity::High, "X", "a.rs:1")],
    )
    .await
    .unwrap();

    assert_eq!(note, "not created (no GitLab token configured)");
    // No request should have hit the server.
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn triage_proceeds_with_only_zentra_gitlab_token_set() {
    use wiremock::matchers::{header, method, path, query_param};

    let server = wiremock::MockServer::start().await;

    // No open sticky issue yet → create path.
    wiremock::Mock::given(method("GET"))
        .and(path("/projects/42/issues"))
        .and(query_param("labels", "zentra-triage"))
        .and(query_param("state", "opened"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("[]"))
        .mount(&server)
        .await;

    // Token-owner lookup must be authenticated with the ZENTRA_GITLAB_TOKEN
    // value as a Bearer token — proving the dedicated var is what we sent.
    wiremock::Mock::given(method("GET"))
        .and(path("/user"))
        .and(header("Authorization", "Bearer zentra-pat-secret"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(r#"{"id":9,"username":"owner"}"#))
        .mount(&server)
        .await;

    wiremock::Mock::given(method("POST"))
        .and(path("/projects/42/issues"))
        .respond_with(
            wiremock::ResponseTemplate::new(201).set_body_string(r#"{"iid":77,"title":"x"}"#),
        )
        .mount(&server)
        .await;

    let context = triage_context("staging");
    // Only ZENTRA_GITLAB_TOKEN is set; GITLAB_TOKEN and CI_JOB_TOKEN are absent.
    let mut env_set = HashMap::new();
    env_set.insert(
        "ZENTRA_GITLAB_TOKEN".to_string(),
        "zentra-pat-secret".to_string(),
    );
    env_set.insert("CI_API_V4_URL".to_string(), server.uri());
    env_set.insert("CI_PROJECT_ID".to_string(), "42".to_string());
    let _guard = set_triage_env(&env_set);

    let note = publish_triage_issue_best_effort(
        &context,
        &[triage_finding(Severity::High, "Missing authz", "src/api.rs:4")],
    )
    .await
    .unwrap();

    // The publish path proceeded (did not skip) and created the issue.
    assert_eq!(note, "created issue #77");

    // At least one POST hit the server — proving token resolution succeeded
    // with only the dedicated var set.
    let requests = server.received_requests().await.unwrap();
    assert!(
        requests.iter().any(|r| r.method.as_str() == "POST"),
        "expected a POST create request; got: {:?}",
        requests.iter().map(|r| r.method.as_str().to_string()).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn triage_skips_creation_when_no_findings_and_no_sticky() {
    use wiremock::matchers::{method, path};

    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(method("GET"))
        .and(path("/projects/42/issues"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("[]"))
        .mount(&server)
        .await;

    let context = triage_context("staging");
    let env_set = env_with_token("glpat-secret", &server.uri());
    let _guard = set_triage_env(&env_set);

    let note = publish_triage_issue_best_effort(&context, &[]).await.unwrap();
    assert_eq!(note, "skipped (no findings)");

    let requests = server.received_requests().await.unwrap();
    assert!(
        !requests.iter().any(|r| r.method.as_str() == "POST"),
        "must not create an issue when there are no findings"
    );
}

/// Build a GitLab env map with a token and an API URL pointed at the mock.
fn env_with_token(token: &str, api_url: &str) -> HashMap<String, String> {
    let mut env = HashMap::new();
    env.insert("GITLAB_TOKEN".to_string(), token.to_string());
    env.insert("CI_API_V4_URL".to_string(), api_url.to_string());
    env.insert("CI_PROJECT_ID".to_string(), "42".to_string());
    env
}

/// Sets the process env from `env` for the duration of the guard, restoring the
/// prior values on drop. Holds a process-wide lock so concurrent env-mutating
/// triage tests do not race. The stored `MutexGuard` makes the guard `!Send`;
/// that is fine because these tests use the default current-thread tokio runtime.
struct TriageEnvGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    saved: HashMap<String, Option<String>>,
}

static TRIAGE_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn set_triage_env(env: &HashMap<String, String>) -> TriageEnvGuard {
    // Recover from poison: if a prior test panicked while holding this lock,
    // we still need to run. Test isolation is preserved by the save/restore below.
    let lock = TRIAGE_ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let keys = [
        "GITLAB_TOKEN",
        "CI_JOB_TOKEN",
        "CI_API_V4_URL",
        "CI_PROJECT_ID",
        "ZENTRA_TRIAGE_ASSIGNEE",
        "ZENTRA_GITLAB_TOKEN",
    ];
    let mut saved = HashMap::new();
    for key in keys {
        saved.insert(key.to_string(), std::env::var(key).ok());
        std::env::remove_var(key);
    }
    for (k, v) in env {
        std::env::set_var(k, v);
    }
    TriageEnvGuard {
        _lock: lock,
        saved,
    }
}

impl Drop for TriageEnvGuard {
    fn drop(&mut self) {
        for (k, v) in &self.saved {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
    }
}
