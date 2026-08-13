use async_trait::async_trait;
use serde_json::json;
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
        Ok("HTTP/1.1 200 OK\n\nbody".to_string())
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
    let scope = PentestScope::default_for_url("https://target.test").unwrap();
    let executor = FakeExecutor {
        calls: Arc::clone(&calls),
    };
    let registry = ValidatorToolRegistry::with_executor(
        scope,
        Arc::new(executor),
        dir.path().to_path_buf(),
        tx,
    );
    (registry, calls, rx, dir)
}

#[tokio::test]
async fn record_validation_emits_event_and_stores_outcomes() {
    let (registry, _calls, mut rx, _dir) = registry();
    let confirmed = registry
        .dispatch(
            "record_validation",
            &json!({
                "candidate_title":"SQL error",
                "category":"sqli",
                "endpoint":"https://target.test/x",
                "confirmed":true,
                "impact":"Database error exposes attacker input",
                "evidence_path":"validation-1.txt",
                "reason":"reproduced"
            }),
        )
        .await;
    assert!(confirmed.contains("Recorded"));
    assert!(matches!(
        rx.recv().await,
        Some(PentestEvent::ValidationCompleted { title, confirmed: true, .. })
            if title == "SQL error"
    ));

    let rejected = registry
        .dispatch(
            "record_validation",
            &json!({
                "candidate_title":"Debug endpoint",
                "category":"misconfig",
                "endpoint":"https://target.test/debug",
                "confirmed":false,
                "impact":"",
                "evidence_path":"validation-2.txt",
                "reason":"Response did not expose the claimed data"
            }),
        )
        .await;
    assert!(rejected.contains("Recorded"));
    assert!(matches!(
        rx.recv().await,
        Some(PentestEvent::ValidationCompleted { title, confirmed: false, .. })
            if title == "Debug endpoint"
    ));
    let outcomes = registry.outcomes_snapshot();
    assert_eq!(outcomes.len(), 2);
    assert_eq!(
        outcomes[1].reason,
        "Response did not expose the claimed data"
    );
}

#[tokio::test]
async fn http_request_rejects_delete_and_out_of_scope_before_exec() {
    let (registry, calls, _rx, _dir) = registry();
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
}

#[tokio::test]
async fn capture_evidence_writes_validation_file() {
    let (registry, _calls, _rx, dir) = registry();
    let path = registry
        .dispatch(
            "capture_evidence",
            &json!({"label":"SQL error","content":"raw validation evidence"}),
        )
        .await;
    assert!(path.contains("evidence"));
    assert_eq!(
        std::fs::read_to_string(path.trim()).unwrap(),
        "raw validation evidence"
    );
    assert!(dir.path().join("evidence/validation").exists());
}

#[test]
fn rejected_entry_has_expected_markdown() {
    assert_eq!(
        format_rejected_entry("Debug endpoint", "https://target.test/debug", "No impact"),
        "## Debug endpoint\n- Endpoint: https://target.test/debug\n- Reason: No impact\n"
    );
}
