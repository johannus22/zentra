use std::sync::{Arc, Mutex};

use anyhow::Result;
use async_trait::async_trait;
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use zentra_cli::agent::verification;
use zentra_cli::agent::ScanEvent;
use zentra_cli::provider::{
    AgentMessage, CompletionRequest, CompletionResponse, LLMProvider, TokenUsage, ToolCall,
    ToolDefinition,
};
use zentra_cli::security::SecurityContext;
use zentra_cli::state::finding::Screening;
use zentra_cli::state::verification::{Verdict, VerificationRun};
use zentra_cli::state::{Finding, Severity};

fn candidate() -> Finding {
    serde_json::from_value(json!({"scanner":"sast", "severity":"critical",
        "title":"Order authorization", "description":"Possible cross-tenant order access",
        "location":"api.ts:2", "recommendation":"Check access"}))
    .unwrap()
}

fn verdict(kind: &str) -> Value {
    let trace = json!([
        {"path":"api.ts", "line":1, "quote":"export function getOrder(user, id) {"},
        {"path":"api.ts", "line":2, "quote":"  return db.orders.get(id);"},
        {"path":"policy.ts", "line":2, "quote":"  return order.ownerId === user.id;"}
    ]);
    let evidence = json!({"principal":"authenticated tenant", "input":"order id",
        "boundary":"tenant authorization", "resource":"another tenant order",
        "impact":"cross-tenant order read", "controls_reviewed":"owner helper exists but is not called on this path", "trace":trace});
    match kind {
        "source_verified" => {
            json!({"verdict":kind, "evidence":evidence, "severity":"high", "rationale":"The handler does not call its owner helper", "recommendation":"Call the owner policy before returning the order"})
        }
        "needs_validation" => {
            json!({"verdict":kind, "evidence":evidence, "blockers":["The deployed gateway policy is unavailable"], "next_step":"Owner should inspect the gateway authorization policy"})
        }
        "rejected" => {
            json!({"verdict":kind, "reason":"The candidate's claimed policy behavior is contradicted by the source", "trace":trace})
        }
        _ => panic!("unknown fixture verdict"),
    }
}

#[derive(Default)]
struct Scripted {
    mode: String,
    sessions: Mutex<Vec<(String, String)>>,
    tools: Mutex<Vec<Vec<String>>>,
    root: Option<std::path::PathBuf>,
}

fn tool(name: &str, arguments: Value) -> CompletionResponse {
    CompletionResponse {
        content: String::new(),
        tool_calls: vec![ToolCall {
            id: "fixture-call".into(),
            name: name.into(),
            arguments,
        }],
        usage: TokenUsage::default(),
    }
}

fn input(messages: &[AgentMessage]) -> Value {
    let AgentMessage::User(message) = &messages[0] else {
        panic!("fresh user input required")
    };
    serde_json::from_str(&message[message.find('{').unwrap()..=message.rfind('}').unwrap()])
        .unwrap()
}

#[async_trait]
impl LLMProvider for Scripted {
    async fn complete(&self, _: CompletionRequest) -> Result<CompletionResponse> {
        unreachable!()
    }
    async fn complete_with_tools(
        &self,
        system: &str,
        messages: &[AgentMessage],
        tools: &[ToolDefinition],
        _: u32,
        _: Option<&CancellationToken>,
    ) -> Result<CompletionResponse> {
        let final_review = system.starts_with("You are Zentra's independent final-record verifier");
        if messages.len() == 1 {
            self.sessions
                .lock()
                .unwrap()
                .push((system.into(), format!("{:?}", messages[0])));
            self.tools
                .lock()
                .unwrap()
                .push(tools.iter().map(|t| t.name.clone()).collect());
        }
        if self.mode == "provider_failure" {
            anyhow::bail!("synthetic provider outage");
        }
        if self.mode == "forbidden_tool" {
            return Ok(tool("run_audit", json!({"tool":"npm"})));
        }
        if self.mode == "turn_budget" {
            return Ok(tool("list_files", json!({"dir":"."})));
        }
        if self.mode == "final_failure" && final_review {
            anyhow::bail!("synthetic final reviewer outage");
        }
        if self.mode == "no_read" {
            return Ok(tool("submit_verification", verdict("source_verified")));
        }
        if self.mode.starts_with("denied:") {
            if messages.len() == 1 {
                return Ok(tool(
                    "read_file",
                    json!({"path":self.mode.trim_start_matches("denied:")}),
                ));
            }
            let mut record = verdict("rejected");
            record["trace"] = json!([{"path":self.mode.trim_start_matches("denied:"), "line":1, "quote":"secret fixture"}]);
            return Ok(tool("submit_verification", record));
        }
        let data = input(messages);
        if self.mode == "final_no_read" && final_review {
            return Ok(tool(
                "accept_verification",
                json!({"digest":data["digest"]}),
            ));
        }
        let read_count = messages
            .iter()
            .filter(|m| matches!(m, AgentMessage::ToolResult { .. }))
            .count();
        if read_count < 2 {
            return Ok(tool(
                "read_file",
                json!({"path": if read_count == 0 { "api.ts" } else { "policy.ts" }}),
            ));
        }
        if self.mode == "changed_source" && final_review {
            std::fs::write(
                self.root.as_ref().unwrap().join("api.ts"),
                "// changed after independent read\n",
            )?;
        }
        if final_review {
            if self.mode == "final_persistence_failure" {
                let path = self.root.as_ref().unwrap().join(".zentra/verification.md");
                std::fs::remove_file(&path)?;
                std::fs::create_dir(&path)?;
            }
            if self.mode == "replace" && data["proposed_record"]["verdict"] == "source_verified" {
                return Ok(tool("submit_verification", verdict("needs_validation")));
            }
            if self.mode == "disagree" {
                return Ok(tool("submit_verification", verdict("rejected")));
            }
            let digest = if self.mode == "wrong_digest" {
                json!("forged")
            } else {
                data["digest"].clone()
            };
            return Ok(tool("accept_verification", json!({"digest":digest})));
        }
        let mut record = verdict(match self.mode.as_str() {
            "rejected" => "rejected",
            "unresolved" => "needs_validation",
            _ => "source_verified",
        });
        if self.mode == "unknown_field" {
            record["execution"] = json!("invented runtime proof");
        }
        if self.mode == "fabricated_quote" {
            record["evidence"]["trace"][0]["quote"] = json!("a fabricated source line");
        }
        if self.mode == "wrong_line" {
            record["evidence"]["trace"][0]["line"] = json!(0);
        }
        if self.mode == "empty_boundary" {
            record["evidence"]["boundary"] = json!(" ");
        }
        Ok(tool("submit_verification", record))
    }
    fn context_window(&self) -> u32 {
        if self.mode == "context_budget" {
            4096
        } else {
            128_000
        }
    }
    fn model_name(&self) -> &str {
        "scripted-verification"
    }
}

fn fixture() -> TempDir {
    let temp = TempDir::new().unwrap();
    std::fs::write(
        temp.path().join("api.ts"),
        include_str!("fixtures/verification/api.ts"),
    )
    .unwrap();
    std::fs::write(
        temp.path().join("policy.ts"),
        include_str!("fixtures/verification/policy.ts"),
    )
    .unwrap();
    temp
}

async fn run(mode: &str) -> (TempDir, Arc<Scripted>, VerificationRun) {
    let temp = fixture();
    let provider = Arc::new(Scripted {
        mode: mode.into(),
        root: Some(temp.path().into()),
        ..Default::default()
    });
    let dynamic: Arc<dyn LLMProvider> = provider.clone();
    let (tx, _rx) = mpsc::channel(128);
    let result = verification::verify(
        &dynamic,
        temp.path(),
        vec![candidate()],
        &SecurityContext::disabled(),
        &CancellationToken::new(),
        &tx,
    )
    .await
    .unwrap();
    (temp, provider, result)
}

#[tokio::test]
async fn source_verification_requires_two_fresh_reads_and_gates_only_reviewed_severity() {
    let (temp, provider, run) = run("verified").await;
    assert!(run.complete());
    assert_eq!(provider.sessions.lock().unwrap().len(), 2);
    let record = &run.records[0];
    assert_ne!(record.reviewer, record.final_reviewer);
    assert_eq!(record.source_hashes.len(), 2);
    let findings = run.findings();
    assert_eq!(findings[0].screening, Some(Screening::SourceVerified));
    assert_eq!(findings[0].severity, Severity::High);
    assert!(zentra_cli::ci::should_fail_ci(&findings, Severity::High));
    assert!(!zentra_cli::ci::should_fail_ci(
        &findings,
        Severity::Critical
    ));
    let persisted: VerificationRun = serde_json::from_slice(
        &std::fs::read(temp.path().join(".zentra/verification.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(persisted.status, "complete");
    assert!(run.markdown().contains("not runtime reproduction"));
    for tools in provider.tools.lock().unwrap().iter() {
        assert!(tools.iter().all(|t| [
            "read_file",
            "list_files",
            "grep_code",
            "submit_verification",
            "accept_verification"
        ]
        .contains(&t.as_str())));
    }
}

#[tokio::test]
async fn unresolved_and_rejected_are_independently_reviewed_and_never_severity_gates() {
    for mode in ["unresolved", "rejected"] {
        let (_, provider, run) = run(mode).await;
        assert!(run.complete());
        assert_eq!(provider.sessions.lock().unwrap().len(), 2);
        assert!(!zentra_cli::ci::should_fail_ci(
            &run.findings(),
            Severity::Info
        ));
        assert!(!run.markdown().contains("Severity:"));
        let sarif = zentra_cli::state::sarif::write_sarif(&run.findings());
        assert!(sarif["runs"][0]["results"].as_array().unwrap().is_empty());
    }
}

#[tokio::test]
async fn replacement_requires_another_fresh_reviewer() {
    let (_, provider, run) = run("replace").await;
    assert!(run.complete());
    assert_eq!(provider.sessions.lock().unwrap().len(), 3);
    assert!(matches!(
        run.records[0].verdict,
        Some(Verdict::NeedsValidation { .. })
    ));
    assert_ne!(run.records[0].reviewer, run.records[0].final_reviewer);
}

#[tokio::test]
async fn invalid_evidence_failures_and_exhausted_budgets_are_incomplete_not_clean() {
    for mode in [
        "provider_failure",
        "final_failure",
        "no_read",
        "final_no_read",
        "forbidden_tool",
        "unknown_field",
        "fabricated_quote",
        "wrong_line",
        "empty_boundary",
        "wrong_digest",
        "changed_source",
        "disagree",
        "turn_budget",
        "context_budget",
    ] {
        let (_, _, run) = run(mode).await;
        assert!(!run.complete(), "{mode}");
        assert_eq!(run.status, "incomplete", "{mode}");
        assert!(run.records[0].incomplete_reason.is_some(), "{mode}");
        assert_eq!(
            run.findings()[0].screening,
            Some(Screening::Incomplete),
            "{mode}"
        );
        assert!(
            !zentra_cli::ci::should_fail_ci(&run.findings(), Severity::Info),
            "{mode}"
        );
    }
}

#[tokio::test]
async fn cancellation_invalidates_prior_annotations_and_preserves_incomplete_artifact() {
    let temp = fixture();
    let provider: Arc<dyn LLMProvider> = Arc::new(Scripted::default());
    let cancel = CancellationToken::new();
    cancel.cancel();
    let mut prior = candidate();
    prior.screening = Some(Screening::SourceVerified);
    prior.evidence = Some("old source".into());
    let (tx, _rx) = mpsc::channel(16);
    let run = verification::verify(
        &provider,
        temp.path(),
        vec![prior],
        &SecurityContext::disabled(),
        &cancel,
        &tx,
    )
    .await
    .unwrap();
    assert!(!run.complete());
    assert_eq!(run.findings()[0].screening, Some(Screening::Incomplete));
    assert_ne!(run.findings()[0].evidence.as_deref(), Some("old source"));
}

#[tokio::test]
async fn persistence_failure_cannot_publish_verified_results() {
    let temp = fixture();
    std::fs::create_dir_all(temp.path().join(".zentra/verification.json")).unwrap();
    let provider = Arc::new(Scripted::default());
    let dynamic: Arc<dyn LLMProvider> = provider.clone();
    let (tx, _rx) = mpsc::channel(16);
    let result = verification::verify(
        &dynamic,
        temp.path(),
        vec![candidate()],
        &SecurityContext::disabled(),
        &CancellationToken::new(),
        &tx,
    )
    .await;
    assert!(result.is_err());
    assert!(provider.sessions.lock().unwrap().is_empty());
}

#[tokio::test]
async fn final_persistence_failure_leaves_authoritative_run_unpublished() {
    let temp = fixture();
    let provider: Arc<dyn LLMProvider> = Arc::new(Scripted {
        mode: "final_persistence_failure".into(),
        root: Some(temp.path().into()),
        ..Default::default()
    });
    let (tx, _rx) = mpsc::channel(64);
    assert!(verification::verify(
        &provider,
        temp.path(),
        vec![candidate()],
        &SecurityContext::disabled(),
        &CancellationToken::new(),
        &tx
    )
    .await
    .is_err());
    let saved: VerificationRun = serde_json::from_slice(
        &std::fs::read(temp.path().join(".zentra/verification.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(saved.status, "in_progress");
    assert!(!saved.complete());
    assert!(!zentra_cli::ci::should_fail_ci(
        &saved.findings(),
        Severity::Info
    ));
}

#[tokio::test]
async fn read_restrictions_hold_even_when_global_security_is_disabled() {
    for path in [
        "../outside.rs",
        "C:/outside.rs",
        "/etc/passwd",
        ".env",
        ".git/config",
        ".ZENTRA/verification.json",
        "api.ts:stream",
        "src\\api.ts",
    ] {
        let (_, _, run) = run(&format!("denied:{path}")).await;
        assert!(!run.complete(), "{path}");
        assert!(run.records[0].source_hashes.is_empty(), "{path}");
    }
}

#[tokio::test]
async fn candidate_and_session_caps_preserve_every_disposition() {
    for (mode, completed, sessions) in [("verified", 50, 100), ("replace", 40, 120)] {
        let temp = fixture();
        let provider = Arc::new(Scripted {
            mode: mode.into(),
            ..Default::default()
        });
        let dynamic: Arc<dyn LLMProvider> = provider.clone();
        let (tx, _rx) = mpsc::channel(4096);
        let candidates = (0..51)
            .map(|n| {
                let mut finding = candidate();
                finding.title = format!("candidate {n}");
                finding
            })
            .collect();
        let run = verification::verify(
            &dynamic,
            temp.path(),
            candidates,
            &SecurityContext::disabled(),
            &CancellationToken::new(),
            &tx,
        )
        .await
        .unwrap();
        assert_eq!(run.records.len(), 51);
        assert_eq!(
            run.records
                .iter()
                .filter(|r| r.incomplete_reason.is_none())
                .count(),
            completed
        );
        assert_eq!(provider.sessions.lock().unwrap().len(), sessions);
        assert_eq!(run.status, "incomplete");
    }
}

#[test]
fn verified_snapshot_replaces_tui_discoveries_and_counts() {
    let mut ui = zentra_cli::tui::UiState::new(
        vec![zentra_cli::agent::ScannerType::Sast],
        "fixture".into(),
        128_000,
        vec![],
        String::new(),
        String::new(),
        String::new(),
    );
    ui.apply_event(ScanEvent::FindingAdded(candidate()));
    ui.apply_event(ScanEvent::FindingAdded(candidate()));
    let mut verified = candidate();
    verified.screening = Some(Screening::SourceVerified);
    verified.severity = Severity::Medium;
    let mut rejected = candidate();
    rejected.screening = Some(Screening::Rejected);
    ui.apply_event(ScanEvent::FindingsVerified(vec![verified, rejected]));
    assert_eq!(ui.findings.len(), 1);
    assert_eq!(ui.scanners[0].critical_count, 0);
    assert_eq!(ui.scanners[0].medium_count, 1);
    assert!(ui.activity.contains("1 other candidate"));
}

#[test]
fn legacy_screening_and_discovery_severity_do_not_gate_ci() {
    for screening in [
        None,
        Some(Screening::Confirmed),
        Some(Screening::Disputed),
        Some(Screening::Unclear),
        Some(Screening::Rejected),
        Some(Screening::NeedsValidation),
        Some(Screening::Incomplete),
    ] {
        let mut finding = candidate();
        finding.screening = screening;
        assert!(!zentra_cli::ci::should_fail_ci(&[finding], Severity::Info));
    }
}

#[test]
fn verdict_contract_rejects_severity_on_unresolved_or_rejected_records() {
    for kind in ["needs_validation", "rejected"] {
        let mut value = verdict(kind);
        value["severity"] = json!("critical");
        assert!(serde_json::from_value::<Verdict>(value).is_err());
    }
    let value: Verdict = serde_json::from_value(verdict("source_verified")).unwrap();
    value.validate().unwrap();
}

struct PipelineProvider(Scripted);

#[async_trait]
impl LLMProvider for PipelineProvider {
    async fn complete(&self, _: CompletionRequest) -> Result<CompletionResponse> {
        unreachable!()
    }
    async fn complete_with_tools(
        &self,
        system: &str,
        messages: &[AgentMessage],
        tools: &[ToolDefinition],
        max_tokens: u32,
        cancel: Option<&CancellationToken>,
    ) -> Result<CompletionResponse> {
        if system.starts_with("You are Zentra's independent") {
            return self
                .0
                .complete_with_tools(system, messages, tools, max_tokens, cancel)
                .await;
        }
        if system.starts_with("You are a static application") {
            let results = messages
                .iter()
                .filter(|m| matches!(m, AgentMessage::ToolResult { .. }))
                .count();
            if results == 0 {
                return Ok(tool("read_file", json!({"path":"Cargo.toml"})));
            }
            if results == 1 {
                return Ok(tool(
                    "write_finding",
                    serde_json::to_value(candidate()).unwrap(),
                ));
            }
        }
        Ok(CompletionResponse {
            content: String::new(),
            tool_calls: vec![],
            usage: TokenUsage::default(),
        })
    }
    fn context_window(&self) -> u32 {
        128_000
    }
    fn model_name(&self) -> &str {
        "pipeline-fixture"
    }
}

#[tokio::test]
async fn headless_pipeline_replaces_raw_critical_discovery_before_gating() {
    for mode in ["verified", "rejected", "unresolved"] {
        let temp = fixture();
        let provider: Arc<dyn LLMProvider> = Arc::new(PipelineProvider(Scripted {
            mode: mode.into(),
            ..Default::default()
        }));
        let events = zentra_cli::commands::ci::run_headless_scan_with_provider(
            provider,
            temp.path(),
            vec![
                zentra_cli::agent::ScannerType::Sast,
                zentra_cli::agent::ScannerType::Report,
            ],
            None,
            false,
        )
        .await
        .unwrap();
        let findings: Vec<_> = events
            .into_iter()
            .filter_map(|event| match event {
                ScanEvent::FindingAdded(finding) => Some(finding),
                _ => None,
            })
            .collect();
        assert_eq!(findings.len(), 1);
        assert!(!zentra_cli::ci::should_fail_ci(
            &findings,
            Severity::Critical
        ));
        assert_eq!(
            zentra_cli::ci::should_fail_ci(&findings, Severity::High),
            mode == "verified"
        );
        let raw =
            std::fs::read_to_string(temp.path().join(".zentra/detailed-findings.md")).unwrap();
        assert_eq!(
            zentra_cli::state::parse_findings(&raw)[0].screening,
            findings[0].screening
        );
    }
}

#[tokio::test]
async fn incomplete_verification_fails_ordinary_ci_but_preserves_report_only_policy() {
    for report_only in [false, true] {
        let temp = fixture();
        let provider: Arc<dyn LLMProvider> = Arc::new(PipelineProvider(Scripted {
            mode: "final_failure".into(),
            ..Default::default()
        }));
        let result = zentra_cli::commands::ci::run_headless_scan_with_provider(
            provider,
            temp.path(),
            vec![
                zentra_cli::agent::ScannerType::Sast,
                zentra_cli::agent::ScannerType::Report,
            ],
            None,
            report_only,
        )
        .await;
        assert_eq!(result.is_ok(), report_only);
        let run: VerificationRun = serde_json::from_slice(
            &std::fs::read(temp.path().join(".zentra/verification.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(run.status, "incomplete");
        assert!(temp.path().join(".zentra/checkpoint.json").exists());
    }
}
