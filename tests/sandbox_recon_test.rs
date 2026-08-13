use async_trait::async_trait;
use serde_json::json;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use tokio::sync::mpsc;
use zentra_cli::pentest::sandbox::tools::{SandboxExecutor, SandboxToolRegistry};
use zentra_cli::pentest::{PentestEvent, PentestScope};

struct FakeExecutor {
    output: String,
    calls: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl SandboxExecutor for FakeExecutor {
    async fn execute(&self, command: &str) -> Result<String, String> {
        self.calls.lock().unwrap().push(command.to_string());
        Ok(self.output.clone())
    }
}

fn registry(
    output: String,
) -> (
    SandboxToolRegistry,
    Arc<Mutex<Vec<String>>>,
    mpsc::Receiver<PentestEvent>,
    TempDir,
) {
    let scope = PentestScope::default_for_url("https://target.test").unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let (tx, rx) = mpsc::channel(8);
    let dir = tempfile::tempdir().unwrap();
    let executor = FakeExecutor {
        output,
        calls: Arc::clone(&calls),
    };
    let registry =
        SandboxToolRegistry::with_executor(scope, Arc::new(executor), dir.path().to_path_buf(), tx);
    (registry, calls, rx, dir)
}

#[tokio::test]
async fn scope_blocks_url_tools_before_executor() {
    let (registry, calls, _rx, _dir) = registry(String::new());
    let result = registry
        .dispatch("http_probe", &json!({"url": "https://outside.test/"}))
        .await;
    assert!(result.contains("outside pentest scope"));
    let result = registry
        .dispatch("dir_brute", &json!({"base_url": "https://outside.test/"}))
        .await;
    assert!(result.contains("outside pentest scope"));
    assert!(calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn shell_exec_enforces_allowlist_and_metacharacters() {
    let (registry, calls, _rx, _dir) = registry(String::new());
    let result = registry
        .dispatch("shell_exec", &json!({"command": "rm -rf /"}))
        .await;
    assert!(result.contains("not allowlisted"));
    let result = registry
        .dispatch("shell_exec", &json!({"command": "curl http://x; rm y"}))
        .await;
    assert!(result.contains("metacharacters"));
    assert!(calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn records_candidate_and_emits_event() {
    let (registry, _calls, mut rx, _dir) = registry(String::new());
    let result = registry
        .dispatch(
            "record_recon_candidate",
            &json!({
                "title": "Debug endpoint",
                "category": "information disclosure",
                "endpoint": "https://target.test/debug",
                "rationale": "The endpoint exposes runtime details."
            }),
        )
        .await;
    assert!(result.contains("Recorded"));
    assert_eq!(registry.candidates_snapshot().len(), 1);
    assert!(matches!(
        rx.recv().await,
        Some(PentestEvent::ReconCandidateAdded { title, .. }) if title == "Debug endpoint"
    ));
}

#[tokio::test]
async fn bounds_output_and_writes_full_result() {
    let full = "x".repeat(40 * 1024);
    let (registry, _calls, _rx, dir) = registry(full.clone());
    let result = registry
        .dispatch("shell_exec", &json!({"command": "cat /tmp/output"}))
        .await;
    assert!(result.contains("truncated; full output at"));
    assert!(result.len() <= 18 * 1024 + 256);
    let path = std::fs::read_dir(dir.path().join("internal/tool-output"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert_eq!(std::fs::read_to_string(path).unwrap(), full);
}
