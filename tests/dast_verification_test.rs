use anyhow::Result;
use async_trait::async_trait;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use zentra_cli::pentest::report::PentestReportWriter;
use zentra_cli::pentest::sandbox::exploit_tools::ExploitAttempt;
use zentra_cli::pentest::sandbox::tools::SandboxExecutor;
use zentra_cli::pentest::sandbox::verification::{
    publish, verify_attempts, DastRecord, DastVerificationRun,
};
use zentra_cli::pentest::{PentestConfig, PentestEvent, PentestScope};
use zentra_cli::provider::{
    AgentMessage, CompletionRequest, CompletionResponse, LLMProvider, TokenUsage, ToolCall,
    ToolDefinition,
};

fn candidate() -> ExploitAttempt {
    ExploitAttempt {
        candidate_title: "Tenant read".into(),
        category: "idor".into(),
        endpoint: "https://target.test/x".into(),
        payload_summary: "GET another tenant record".into(),
        success: true,
        evidence_path: "model-note.txt".into(),
        impact: "possible tenant data read".into(),
    }
}
fn record(kind: &str, id: Option<&str>) -> Value {
    json!({"candidate_title":"Tenant read", "category":"idor", "endpoint":"https://target.test/x", "verdict":kind,
        "principal":"tenant A", "boundary":"tenant isolation", "expected":"deny tenant B data", "impact":"tenant B data returned",
        "controls_reviewed":"compared baseline and response", "reason":"Observed response to tenant A request",
        "evidence":id.map(|id| vec![json!({"id":id,"quote":"other tenant record"})]).unwrap_or_default(),
        "cvss_vector": if kind == "runtime_verified" {"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"} else {""},
        "next_step":if kind == "needs_validation" {"Owner must confirm tenant ownership of this record"} else {""}})
}
fn tool(name: &str, arguments: Value) -> CompletionResponse {
    CompletionResponse {
        content: String::new(),
        tool_calls: vec![ToolCall {
            id: "call".into(),
            name: name.into(),
            arguments,
        }],
        usage: TokenUsage::default(),
    }
}
fn input(messages: &[AgentMessage]) -> Value {
    let AgentMessage::User(text) = &messages[0] else {
        panic!("expected fresh user input")
    };
    serde_json::from_str(&text[text.find('{').unwrap()..=text.rfind('}').unwrap()]).unwrap()
}

struct Scripted {
    mode: String,
    root: PathBuf,
    sessions: Mutex<Vec<(String, Vec<String>)>>,
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
        cancel: Option<&CancellationToken>,
    ) -> Result<CompletionResponse> {
        if self.mode == "upstream_failure" {
            return Ok(tool(
                if system.contains("Recon agent") {
                    "http_probe"
                } else {
                    "http_request"
                },
                json!({"url":"https://target.test/x", "method":"GET"}),
            ));
        }
        let final_review = system.contains("final-record verifier");
        if messages.len() == 1 {
            self.sessions.lock().unwrap().push((
                system.into(),
                tools.iter().map(|t| t.name.clone()).collect(),
            ));
            assert!(
                !system.contains("Tenant read"),
                "candidate data must not enter the system prompt"
            );
        }
        if self.mode == "provider_failure" || (final_review && self.mode == "final_failure") {
            anyhow::bail!("synthetic provider outage");
        }
        if self.mode == "cancel" {
            cancel.unwrap().cancel();
            return Ok(tool("complete", json!({})));
        }
        if self.mode == "prose" {
            let mut response = tool("complete", json!({}));
            response.tool_calls.clear();
            return Ok(response);
        }
        if self.mode == "call_budget" {
            let mut response = tool("http_request", json!({}));
            response.tool_calls = vec![response.tool_calls[0].clone(); 5];
            return Ok(response);
        }
        let data = input(messages);
        if final_review {
            let id = data["available_receipts"][0].as_str();
            if self.mode == "forbidden" {
                return Ok(tool("http_request", json!({"url":"https://target.test/x"})));
            }
            if self.mode == "no_read" {
                return Ok(tool(
                    "accept_verification",
                    json!({"digest":data["digest"]}),
                ));
            }
            if self.mode == "foreign_receipt" {
                return Ok(tool("read_evidence", json!({"id":"../../foreign.json"})));
            }
            if id.is_some() && (messages.len() == 1 || self.mode == "final_turn_budget") {
                return Ok(tool("read_evidence", json!({"id":id})));
            }
            if self.mode == "changed_receipt" {
                std::fs::write(self.root.join(id.unwrap()), "changed")?;
            }
            if self.mode == "final_persistence" {
                std::fs::remove_file(self.root.join("verification.json"))?;
                std::fs::create_dir(self.root.join("verification.json"))?;
            }
            if self.mode == "replace" && data["proposed_record"]["verdict"] == "runtime_verified" {
                return Ok(tool("submit_verification", record("needs_validation", id)));
            }
            if self.mode == "disagree" {
                return Ok(tool("submit_verification", record("rejected", id)));
            }
            return Ok(tool(
                "accept_verification",
                json!({"digest":if self.mode == "wrong_digest" {json!("wrong")} else {data["digest"].clone()}}),
            ));
        }
        if self.mode == "unresolved_no_execution" {
            return Ok(tool("record_validation", record("needs_validation", None)));
        }
        if messages.len() == 1 || self.mode == "turn_budget" {
            return Ok(tool(
                "http_request",
                json!({"url":"https://target.test/x","method":"GET"}),
            ));
        }
        let AgentMessage::ToolResult { content, .. } = messages.last().unwrap() else {
            panic!("expected execution result")
        };
        let ids = content.split("Runtime receipt IDs: ").nth(1).unwrap();
        let ids: Vec<String> = serde_json::from_str(&ids[..=ids.find(']').unwrap()]).unwrap();
        let kind = match self.mode.as_str() {
            "rejected" => "rejected",
            "needs_validation" => "needs_validation",
            _ => "runtime_verified",
        };
        let mut proposed = record(kind, Some(&ids[0]));
        if self.mode == "wrong_candidate" {
            proposed["candidate_title"] = json!("another candidate");
        }
        if self.mode == "wrong_endpoint" {
            proposed["endpoint"] = json!("https://target.test/y");
        }
        if self.mode == "fake_quote" {
            proposed["evidence"][0]["quote"] = json!("not actually observed");
        }
        Ok(tool("record_validation", proposed))
    }
    fn context_window(&self) -> u32 {
        if self.mode == "context_budget" {
            256
        } else {
            128000
        }
    }
    fn model_name(&self) -> &str {
        "scripted-dast"
    }
}
struct Executor {
    mode: String,
}
#[async_trait]
impl SandboxExecutor for Executor {
    async fn execute(&self, _: &str) -> std::result::Result<String, String> {
        if self.mode == "execution_failure" {
            return Err("synthetic execution failure".into());
        }
        if self.mode == "output_budget" {
            return Ok("x".repeat(256 * 1024 + 1));
        }
        Ok("HTTP/1.1 200 OK\n\nother tenant record".into())
    }
}
struct Fixture {
    dir: TempDir,
    provider: Arc<Scripted>,
    config: PentestConfig,
    run: DastVerificationRun,
    tx: mpsc::Sender<PentestEvent>,
    rx: mpsc::Receiver<PentestEvent>,
    cancel: CancellationToken,
}
impl Fixture {
    fn new(mode: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let provider = Arc::new(Scripted {
            mode: mode.into(),
            root: dir.path().into(),
            sessions: Mutex::new(vec![]),
        });
        let (tx, rx) = mpsc::channel(4096);
        Self {
            dir,
            provider,
            config: PentestConfig {
                target_url: "https://target.test".into(),
                scope: PentestScope::default_for_url("https://target.test").unwrap(),
                auth: Default::default(),
                authorized: true,
            },
            run: DastVerificationRun {
                records: vec![DastRecord::pending(candidate())],
                ..Default::default()
            },
            tx,
            rx,
            cancel: CancellationToken::new(),
        }
    }
    async fn verify(&mut self) -> Result<()> {
        let provider: Arc<dyn LLMProvider> = self.provider.clone();
        verify_attempts(
            &mut self.run,
            &self.config,
            &provider,
            Arc::new(Executor {
                mode: self.provider.mode.clone(),
            }),
            self.dir.path(),
            &self.tx,
            &self.cancel,
        )
        .await
    }
    async fn publish(&mut self) -> Result<()> {
        let writer = PentestReportWriter::from_output_root(self.dir.path())?;
        publish(&mut self.run, &self.config, &writer, &self.tx, &self.cancel).await
    }
    fn events(&mut self) -> Vec<PentestEvent> {
        let mut events = vec![];
        while let Ok(event) = self.rx.try_recv() {
            events.push(event);
        }
        events
    }
    fn artifact(&self, name: &str) -> Value {
        serde_json::from_slice(&std::fs::read(self.dir.path().join(name)).unwrap()).unwrap()
    }
    fn assert_no_publication(&mut self) {
        assert!(self.events().iter().all(|e| !matches!(
            e,
            PentestEvent::Completed
                | PentestEvent::FindingAdded(_)
                | PentestEvent::VerificationCompleted { .. }
        )));
    }
}

#[tokio::test]
async fn only_saved_independently_reviewed_execution_becomes_findings() {
    let mut f = Fixture::new("verified");
    f.verify().await.unwrap();
    assert!(f.run.complete());
    f.assert_no_publication();
    let sessions = f.provider.sessions.lock().unwrap().clone();
    assert_eq!(sessions.len(), 2);
    assert_eq!(
        sessions[1].1,
        [
            "read_evidence",
            "accept_verification",
            "submit_verification"
        ]
    );
    assert_ne!(f.run.records[0].reviewer, f.run.records[0].final_reviewer);
    f.publish().await.unwrap();
    let findings = f.artifact("findings.json");
    assert_eq!(findings.as_array().unwrap().len(), 1);
    assert!(findings[0]["evidence_paths"][0]
        .as_str()
        .unwrap()
        .starts_with("evidence/runtime/"));
    assert_eq!(
        f.artifact("findings.sarif")["runs"][0]["results"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(f.artifact("verification.json")["status"], "complete");
    let events = f.events();
    assert!(matches!(events.last(), Some(PentestEvent::Completed)));
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, PentestEvent::FindingAdded(_)))
            .count(),
        1
    );
}

#[tokio::test]
async fn replacement_requires_third_fresh_review_and_removes_severity() {
    let mut f = Fixture::new("replace");
    f.verify().await.unwrap();
    assert_eq!(f.provider.sessions.lock().unwrap().len(), 3);
    assert_eq!(f.run.records[0].disposition(), "needs_validation");
    assert_ne!(
        f.run.records[0].reviewer,
        f.run.records[0].reproduction_session
    );
    f.publish().await.unwrap();
    assert!(f.artifact("findings.json").as_array().unwrap().is_empty());
    assert!(f.artifact("findings.sarif")["runs"][0]["results"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(
        !std::fs::read_to_string(f.dir.path().join("verification.md"))
            .unwrap()
            .contains("CVSS:")
    );
}

#[tokio::test]
async fn rejected_and_unresolved_are_visible_but_not_findings() {
    for mode in ["rejected", "needs_validation", "unresolved_no_execution"] {
        let mut f = Fixture::new(mode);
        f.verify().await.unwrap();
        assert!(f.run.complete());
        f.publish().await.unwrap();
        assert!(f.artifact("findings.json").as_array().unwrap().is_empty());
        assert!(f.events().iter().any(|e| matches!(e, PentestEvent::VerificationCompleted { verdict, .. } if verdict == "rejected" || verdict == "needs_validation")));
    }
}

#[tokio::test]
async fn invalid_reviews_and_operational_failures_stay_incomplete() {
    for mode in [
        "provider_failure",
        "final_failure",
        "execution_failure",
        "forbidden",
        "no_read",
        "foreign_receipt",
        "wrong_candidate",
        "wrong_endpoint",
        "fake_quote",
        "wrong_digest",
        "changed_receipt",
        "disagree",
        "prose",
        "context_budget",
        "call_budget",
        "turn_budget",
        "final_turn_budget",
        "output_budget",
        "cancel",
    ] {
        let mut f = Fixture::new(mode);
        f.verify().await.unwrap();
        assert!(!f.run.complete(), "{mode}");
        assert_eq!(f.run.records[0].disposition(), "incomplete", "{mode}");
        f.assert_no_publication();
        assert!(f.publish().await.is_err(), "{mode}");
        assert!(
            f.artifact("findings.json").as_array().unwrap().is_empty(),
            "{mode}"
        );
        assert!(
            f.events()
                .iter()
                .all(|e| !matches!(e, PentestEvent::Completed | PentestEvent::FindingAdded(_))),
            "{mode}"
        );
        assert_eq!(f.artifact("verification.json")["status"], "incomplete");
    }
}

#[tokio::test]
async fn stale_receipts_or_records_cannot_publish() {
    for mutate_record in [false, true] {
        let mut f = Fixture::new("verified");
        f.verify().await.unwrap();
        if mutate_record {
            f.run.records[0].outcome.as_mut().unwrap().impact = "invented impact".into();
        } else {
            let id = f.run.records[0].evidence_hashes.keys().next().unwrap();
            std::fs::write(f.dir.path().join(id), "changed after review").unwrap();
        }
        f.assert_no_publication();
        assert!(f.publish().await.is_err());
        assert!(f.artifact("findings.json").as_array().unwrap().is_empty());
        assert_eq!(f.run.records[0].disposition(), "incomplete");
    }
}

#[tokio::test]
async fn persistence_failures_never_emit_success() {
    for stage in ["initial", "final_persistence", "report"] {
        let mut f = Fixture::new(stage);
        if stage == "initial" {
            std::fs::create_dir(f.dir.path().join("verification.json")).unwrap();
        }
        let result = f.verify().await;
        if stage == "report" {
            result.unwrap();
            std::fs::create_dir(f.dir.path().join("findings.sarif")).unwrap();
            assert!(f.publish().await.is_err());
            assert_eq!(f.artifact("verification.json")["status"], "incomplete");
        } else {
            assert!(result.is_err(), "{stage}");
        }
        f.assert_no_publication();
        assert!(!f.run.complete());
    }
}

#[tokio::test]
async fn cancellation_after_review_cannot_publish() {
    let mut f = Fixture::new("verified");
    f.verify().await.unwrap();
    f.cancel.cancel();
    assert!(f.publish().await.is_err());
    f.assert_no_publication();
    assert!(f.artifact("findings.json").as_array().unwrap().is_empty());
    assert_eq!(f.artifact("verification.json")["status"], "incomplete");
}

#[tokio::test]
async fn candidate_cap_and_upstream_failures_cannot_appear_clean() {
    let mut f = Fixture::new("unresolved_no_execution");
    f.run.records = (0..21).map(|_| DastRecord::pending(candidate())).collect();
    f.run.records[0].incomplete_reason = Some("upstream exploit failed".into());
    f.verify().await.unwrap();
    assert_eq!(f.provider.sessions.lock().unwrap().len(), 38);
    assert_eq!(f.run.records[0].disposition(), "incomplete");
    assert_eq!(f.run.records[20].disposition(), "incomplete");
    assert!(!f.run.complete());
    assert!(f.publish().await.is_err());
}

#[tokio::test]
async fn cancelled_empty_run_is_not_clean() {
    let mut f = Fixture::new("verified");
    f.run.records.clear();
    f.cancel.cancel();
    f.verify().await.unwrap();
    assert!(f.publish().await.is_err());
    assert_eq!(f.artifact("verification.json")["status"], "incomplete");
    f.assert_no_publication();
}

#[tokio::test]
async fn mixed_run_retains_verified_findings_but_cannot_complete_cleanly() {
    let mut f = Fixture::new("verified");
    f.run.records[0].candidate.success = false; // Discovery's claim is not the final verdict.
    let mut failed = DastRecord::pending(candidate());
    failed.incomplete_reason = Some("upstream execution failed".into());
    f.run.records.push(failed);
    f.verify().await.unwrap();
    assert!(f.publish().await.is_err());
    assert_eq!(f.artifact("findings.json").as_array().unwrap().len(), 1);
    assert_eq!(
        f.artifact("findings.sarif")["runs"][0]["results"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(std::fs::read_to_string(f.dir.path().join("report.md"))
        .unwrap()
        .contains("Status: **incomplete**"));
    assert!(!f
        .events()
        .iter()
        .any(|e| matches!(e, PentestEvent::Completed)));
}

#[tokio::test]
async fn blocked_publication_observes_cancellation() {
    let mut f = Fixture::new("verified");
    f.verify().await.unwrap();
    f.assert_no_publication();
    let (tx, mut rx) = mpsc::channel(1);
    tx.send(PentestEvent::TokensUsed {
        input: 0,
        output: 0,
    })
    .await
    .unwrap();
    let cancel = f.cancel.clone();
    f.tx = tx;
    let cancel_task = tokio::spawn(async move {
        tokio::task::yield_now().await;
        cancel.cancel();
    });
    assert!(f.publish().await.is_err());
    cancel_task.await.unwrap();
    assert!(matches!(rx.try_recv(), Ok(PentestEvent::TokensUsed { .. })));
    assert!(rx.try_recv().is_err());
    assert_eq!(f.artifact("verification.json")["status"], "incomplete");
}

#[tokio::test]
async fn upstream_execution_failures_propagate_instead_of_appearing_clean() {
    use zentra_cli::pentest::sandbox::{
        exploit::SandboxExploitAgent,
        exploit_tools::ExploitToolRegistry,
        recon::SandboxReconAgent,
        tools::{ReconCandidate, SandboxToolRegistry},
        SandboxHandle, SandboxImage,
    };
    let mut f = Fixture::new("upstream_failure");
    let executor: Arc<dyn SandboxExecutor> = Arc::new(Executor {
        mode: "execution_failure".into(),
    });
    let recon = Arc::new(SandboxToolRegistry::with_executor(
        f.config.scope.clone(),
        executor.clone(),
        f.dir.path().into(),
        f.tx.clone(),
    ));
    let handle = SandboxHandle {
        container_id: "unused-fixture".into(),
        engine: Default::default(),
        image: SandboxImage::pinned(),
    };
    let result = SandboxReconAgent::new(
        f.config.clone(),
        f.provider.clone(),
        recon,
        f.tx.clone(),
        f.cancel.clone(),
        handle,
    )
    .run()
    .await;
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("recon tool failed"));
    let exploit = Arc::new(ExploitToolRegistry::with_executor(
        f.config.scope.clone(),
        executor,
        f.dir.path().into(),
        f.tx.clone(),
    ));
    let candidate = ReconCandidate {
        title: "Tenant read".into(),
        category: "idor".into(),
        endpoint: "https://target.test/x".into(),
        rationale: "Possible tenant access".into(),
    };
    let result = SandboxExploitAgent::new(
        200,
        f.config.clone(),
        candidate,
        f.provider.clone(),
        exploit,
        f.tx.clone(),
        f.cancel.clone(),
    )
    .run()
    .await;
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("exploit tool failed"));
    f.assert_no_publication();
}
