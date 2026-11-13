use async_trait::async_trait;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use tokio::sync::mpsc;
use zentra_cli::pentest::sandbox::orchestrator::format_rejected_entry;
use zentra_cli::pentest::sandbox::tools::SandboxExecutor;
use zentra_cli::pentest::sandbox::validator_tools::ValidatorToolRegistry;
use zentra_cli::pentest::{PentestEvent, PentestScope};

struct FakeExecutor {
    calls: Arc<Mutex<Vec<String>>>,
}
#[async_trait]
impl SandboxExecutor for FakeExecutor {
    async fn execute(&self, command: &str) -> Result<String, String> {
        self.calls.lock().unwrap().push(command.to_string());
        Ok("HTTP/1.1 200 OK\n\nother tenant record".into())
    }
}
fn registry() -> (
    ValidatorToolRegistry,
    Arc<Mutex<Vec<String>>>,
    mpsc::Receiver<PentestEvent>,
    TempDir,
) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let (tx, rx) = mpsc::channel(16);
    let dir = tempfile::tempdir().unwrap();
    let registry = ValidatorToolRegistry::with_executor(
        PentestScope::default_for_url("https://target.test").unwrap(),
        Arc::new(FakeExecutor {
            calls: calls.clone(),
        }),
        dir.path().into(),
        tx,
    );
    (registry, calls, rx, dir)
}
fn record(id: &str) -> Value {
    json!({"candidate_title":"Tenant read", "category":"idor", "endpoint":"https://target.test/x",
        "verdict":"runtime_verified", "principal":"tenant A", "boundary":"tenant isolation", "expected":"deny access to tenant B",
        "impact":"read tenant B record", "controls_reviewed":"unauthorized baseline compared with attack",
        "evidence":[{"id":id, "quote":"other tenant record"}], "reason":"Observed another tenant record",
        "cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", "next_step":""})
}
async fn observe(registry: &ValidatorToolRegistry) -> String {
    let result = registry
        .dispatch(
            "http_request",
            &json!({"url":"https://target.test/x", "method":"GET"}),
        )
        .await;
    assert!(!result.starts_with("Error:"), "{result}");
    registry.evidence.ids().unwrap()[0].clone()
}

#[tokio::test]
async fn validation_proposal_requires_execution_receipt_and_does_not_publish_confirmation() {
    let (registry, calls, mut rx, _dir) = registry();
    assert!(registry
        .dispatch("record_validation", &record("forged.txt"))
        .await
        .starts_with("Error:"));
    let id = observe(&registry).await;
    assert!(registry
        .dispatch("record_validation", &record(&id))
        .await
        .contains("Recorded proposed"));
    assert_eq!(registry.outcomes_snapshot().len(), 1);
    assert_eq!(calls.lock().unwrap().len(), 1);
    assert!(
        rx.try_recv().is_err(),
        "proposed verdict must not update confirmed TUI state"
    );
}

#[tokio::test]
async fn confirmation_rejects_invalid_and_zero_impact_cvss() {
    for vector in ["critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"] {
        let (registry, _, _, _dir) = registry();
        let id = observe(&registry).await;
        let mut value = record(&id);
        value["cvss_vector"] = json!(vector);
        let result = registry.dispatch("record_validation", &value).await;
        assert!(result.contains("CVSS"), "{result}");
        assert!(registry.outcomes_snapshot().is_empty());
    }
}

#[tokio::test]
async fn rejects_wrong_endpoint_fabricated_quote_and_model_written_notes() {
    let (registry, _, _, _dir) = registry();
    let id = observe(&registry).await;
    for (field, value) in [
        ("endpoint", json!("https://target.test/another")),
        ("evidence", json!([{"id":id,"quote":"fabricated impact"}])),
    ] {
        let mut proposed = record(&id);
        proposed[field] = value;
        assert!(registry
            .dispatch("record_validation", &proposed)
            .await
            .starts_with("Error:"));
    }
    assert!(registry
        .dispatch(
            "capture_evidence",
            &json!({"label":"fake", "content":"fabricated impact"})
        )
        .await
        .contains("unknown validator tool"));
}

#[tokio::test]
async fn http_request_rejects_delete_and_out_of_scope_before_exec() {
    let (registry, calls, _, _dir) = registry();
    assert!(registry
        .dispatch(
            "http_request",
            &json!({"url":"https://target.test/x","method":"DELETE"})
        )
        .await
        .contains("not allowed"));
    assert!(registry
        .dispatch(
            "http_request",
            &json!({"url":"https://outside.test/x","method":"GET"})
        )
        .await
        .contains("outside pentest scope"));
    assert!(calls.lock().unwrap().is_empty());
    assert!(registry.evidence.ids().unwrap().is_empty());
}

#[tokio::test]
async fn execution_receipts_detect_changed_artifacts() {
    let (registry, _, _, dir) = registry();
    let id = observe(&registry).await;
    std::fs::write(dir.path().join(&id), "tampered").unwrap();
    assert!(registry
        .dispatch("record_validation", &record(&id))
        .await
        .contains("changed since capture"));
}

#[test]
fn rejected_entry_has_expected_markdown() {
    assert_eq!(
        format_rejected_entry("Debug endpoint", "https://target.test/debug", "No impact"),
        "## Debug endpoint\n- Endpoint: https://target.test/debug\n- Reason: No impact\n"
    );
}

#[tokio::test]
async fn receipts_are_session_bound_and_headers_are_redacted() {
    let (first, _, _, _dir) = registry();
    let result = first.dispatch("http_request", &json!({"url":"https://target.test/x", "method":"GET", "headers":{"Cookie":"sid=fixture-secret", "Authorization":"Bearer fixture-token"}})).await;
    assert!(!result.starts_with("Error:"), "{result}");
    let id = first.evidence.ids().unwrap()[0].clone();
    let receipt = first.evidence.read(&id).unwrap();
    assert_eq!(receipt.arguments["headers"]["Cookie"], "[redacted]");
    assert!(!receipt.command.contains("fixture-secret"));
    let (second, _, _, _other_dir) = registry();
    assert!(second.evidence.read(&id).is_err());
    assert!(second
        .dispatch("record_validation", &record(&id))
        .await
        .starts_with("Error:"));
}

#[tokio::test]
async fn payload_receipt_includes_source_and_confines_payload_path() {
    let (registry, calls, _, dir) = registry();
    std::fs::create_dir(dir.path().join("workspace")).unwrap();
    std::fs::write(
        dir.path().join("workspace/probe.py"),
        "print('a claim is not proof')",
    )
    .unwrap();
    assert!(registry
        .dispatch("run_payload", &json!({"path":"../probe.py"}))
        .await
        .starts_with("Error:"));
    assert!(calls.lock().unwrap().is_empty());
    let result = registry
        .dispatch("run_payload", &json!({"path":"probe.py"}))
        .await;
    assert!(!result.starts_with("Error:"), "{result}");
    let receipt = registry
        .evidence
        .read(&registry.evidence.ids().unwrap()[0])
        .unwrap();
    assert_eq!(
        receipt.payload.as_deref(),
        Some("print('a claim is not proof')")
    );
    assert!(receipt.command.contains("/workspace/probe.py"));
}

#[test]
fn evidence_artifact_paths_reject_traversal_and_absolute_paths() {
    use zentra_cli::pentest::sandbox::runtime_evidence::confined;
    let dir = tempfile::tempdir().unwrap();
    for path in ["../escape", "/absolute", "C:/escape", "evidence\\escape"] {
        assert!(
            confined(dir.path(), std::path::Path::new(path)).is_err(),
            "{path}"
        );
    }
}

#[cfg(unix)]
#[test]
fn evidence_artifact_paths_reject_symlink_parents() {
    use zentra_cli::pentest::sandbox::runtime_evidence::confined;
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), dir.path().join("evidence")).unwrap();
    assert!(confined(dir.path(), std::path::Path::new("evidence/new.json")).is_err());
}
