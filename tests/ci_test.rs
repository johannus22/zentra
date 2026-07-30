use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;
use zentra_cli::agent::{ScanEvent, ScannerType};
use zentra_cli::ci::{
    build_sticky_comment_body, candidate_git_diff_ranges, comment_http_timeout,
    detect_ci_context_from_env, generate_ci_workflow_at, git_diff_error_with_guidance,
    gitlab_auth_header_from_env, parse_git_diff_name_only, prepare_comment_request_from_env,
    redact_token, select_impact_files, select_sticky_comment_action, severity_counts,
    should_fail_ci, write_ci_artifacts, CiCommentPlan, CiContext, CiPlatformKind, GitlabAuthHeader,
    StickyCommentAction,
};
use zentra_cli::commands::ci::{
    build_ci_focus_context, run_headless_scan_with_provider, select_ci_scanners,
};
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

    let paths = write_ci_artifacts(dir.path(), &context, &findings).unwrap();

    assert_eq!(
        paths.markdown,
        dir.path().join(".zentra").join("ci-report.md")
    );
    assert_eq!(
        paths.json,
        dir.path().join(".zentra").join("ci-report.json")
    );

    let markdown = std::fs::read_to_string(paths.markdown).unwrap();
    assert!(markdown.contains("# Zentra CI Security Report"));
    assert!(markdown.contains("Platform: github"));
    assert!(markdown.contains("Scope: PR/MR 77"));
    assert!(markdown.contains("Base: main"));
    assert!(markdown.contains("Head: feature/auth"));
    assert!(markdown.contains("Changed files: 2"));
    assert!(markdown.contains("Impact files: 2"));
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
fn comment_request_skips_without_token_or_pr_metadata_and_redacts_tokens() {
    let context = CiContext {
        pr_or_mr_number: None,
        ..sample_context()
    };
    let env = HashMap::new();

    let plan = prepare_comment_request_from_env(&env, &context, &[]);

    assert!(matches!(plan, CiCommentPlan::Skip { reason } if reason.contains("token")));
    assert_eq!(redact_token("ghp_secret-token"), "[redacted]");
}

#[test]
fn github_comment_request_skips_without_repository_metadata_and_redacts_token() {
    let env = HashMap::from([("GITHUB_TOKEN".to_string(), "ghp_secret-token".to_string())]);

    let plan = prepare_comment_request_from_env(&env, &sample_context(), &[]);

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

    let plan = prepare_comment_request_from_env(&env, &context, &[]);

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
}

#[test]
fn sticky_comment_body_shows_passed_status_and_no_critical_rows_when_none_found() {
    let body = build_sticky_comment_body(
        &sample_context(),
        &[sample_finding(Severity::Low, "Verbose error")],
    );

    assert!(body.contains("✅ Passed"));
    assert!(!body.contains("❌ Failed"));
    assert!(!body.contains("| 🔴 CRITICAL |"));
}

#[test]
fn sticky_comment_body_reports_no_findings_when_scan_is_clean() {
    let body = build_sticky_comment_body(&sample_context(), &[]);

    assert!(body.contains("✅ Passed"));
    assert!(body.contains("0 total"));
    assert!(body.contains("No findings."));
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
