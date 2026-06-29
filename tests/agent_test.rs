// tests/agent_test.rs
use zentra_cli::scanners;
use zentra_cli::tools::fs_tools::{grep_code, list_files, read_file};
use zentra_cli::tools::git_tools::{git_log, git_status};
use zentra_cli::{agent, state, tools};

use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use zentra_cli::agent::scanner::ScannerAgent;
use zentra_cli::provider::openai_compat::OpenAICompatProvider;

#[test]
fn modules_exist() {
    // compile-time verification that all new modules are declared
    let _ = std::any::type_name::<agent::ScannerType>();
    let _ = std::any::type_name::<state::Finding>();
    let _ = std::any::type_name::<tools::ToolRegistry>();
}

use tempfile::TempDir;
use zentra_cli::state::{Finding, Severity, StateWriter};

#[test]
fn state_writer_creates_findings_file() {
    let dir = TempDir::new().unwrap();
    let writer = StateWriter::new(dir.path()).unwrap();

    writer
        .write_finding(&Finding {
            scanner: "sast".to_string(),
            severity: Severity::Critical,
            title: "SQL Injection".to_string(),
            description: "User input concatenated into SQL".to_string(),
            location: Some("src/db.rs:42".to_string()),
            recommendation: "Use parameterized queries.".to_string(),
            corroborated_by: vec![],
        })
        .unwrap();

    let findings_path = dir.path().join(".zentra").join("detailed-findings.md");
    assert!(findings_path.exists(), "detailed-findings.md should exist");

    let content = std::fs::read_to_string(&findings_path).unwrap();
    assert!(
        content.contains("SQL Injection"),
        "should contain finding title"
    );
    assert!(content.contains("CRITICAL"), "should contain severity");
    assert!(content.contains("src/db.rs:42"), "should contain location");
}

#[test]
fn state_writer_appends_multiple_findings() {
    let dir = TempDir::new().unwrap();
    let writer = StateWriter::new(dir.path()).unwrap();

    for i in 0..3 {
        writer
            .write_finding(&Finding {
                scanner: "sast".to_string(),
                severity: Severity::High,
                title: format!("Finding {}", i),
                description: "desc".to_string(),
                location: None,
                recommendation: "fix it".to_string(),
                corroborated_by: vec![],
            })
            .unwrap();
    }

    let content =
        std::fs::read_to_string(dir.path().join(".zentra").join("detailed-findings.md")).unwrap();
    assert!(content.contains("Finding 0"));
    assert!(content.contains("Finding 1"));
    assert!(content.contains("Finding 2"));
}

#[test]
fn state_writer_sorts_findings_by_severity_in_markdown() {
    let dir = TempDir::new().unwrap();
    let writer = StateWriter::new(dir.path()).unwrap();

    writer
        .write_finding(&Finding {
            scanner: "sast".to_string(),
            severity: Severity::Low,
            title: "Low Finding".to_string(),
            description: "low".to_string(),
            location: None,
            recommendation: "fix low".to_string(),
            corroborated_by: vec![],
        })
        .unwrap();
    writer
        .write_finding(&Finding {
            scanner: "iac_scan".to_string(),
            severity: Severity::Critical,
            title: "Critical Finding".to_string(),
            description: "critical".to_string(),
            location: None,
            recommendation: "fix critical".to_string(),
            corroborated_by: vec![],
        })
        .unwrap();

    let content =
        std::fs::read_to_string(dir.path().join(".zentra").join("detailed-findings.md")).unwrap();
    let critical_idx = content.find("## [CRITICAL] Critical Finding").unwrap();
    let low_idx = content.find("## [LOW] Low Finding").unwrap();
    assert!(
        critical_idx < low_idx,
        "critical findings should be ordered before low findings"
    );
}

#[test]
fn state_writer_writes_report() {
    let dir = TempDir::new().unwrap();
    let writer = StateWriter::new(dir.path()).unwrap();
    writer
        .write_report("# Executive Summary\n\nAll clear.")
        .unwrap();

    let reports_dir = dir.path().join(".zentra").join("reports");
    let entries: Vec<_> = std::fs::read_dir(&reports_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(entries.len(), 1, "should have one report file");

    let filename = entries[0].file_name();
    let name = filename.to_string_lossy();
    assert!(
        name.ends_with("-report.md"),
        "filename should end with -report.md, got: {}",
        name
    );

    let content = std::fs::read_to_string(entries[0].path()).unwrap();
    assert!(
        content.contains("Executive Summary"),
        "report should contain written content"
    );
}

#[test]
fn read_findings_raw_returns_empty_when_no_findings() {
    let dir = TempDir::new().unwrap();
    let writer = StateWriter::new(dir.path()).unwrap();
    let result = writer.read_findings_raw().unwrap();
    assert!(
        result.is_empty(),
        "should return empty string when no findings written"
    );
}

#[test]
fn read_findings_raw_returns_written_findings() {
    let dir = TempDir::new().unwrap();
    let writer = StateWriter::new(dir.path()).unwrap();
    writer
        .write_finding(&Finding {
            scanner: "sast".to_string(),
            severity: Severity::Low,
            title: "Test".to_string(),
            description: "desc".to_string(),
            location: None,
            recommendation: "fix".to_string(),
            corroborated_by: vec![],
        })
        .unwrap();

    let content = writer.read_findings_raw().unwrap();
    assert!(
        content.contains("Test"),
        "should contain the written finding title"
    );
}

#[test]
fn read_file_returns_content() {
    let _guard = cwd_lock().lock().unwrap_or_else(|e| e.into_inner());
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("test.txt"), "hello world").unwrap();
    let original = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();

    let content = read_file("test.txt");

    std::env::set_current_dir(original).unwrap();
    assert_eq!(content, "hello world");
}

#[test]
fn read_file_returns_error_message_for_missing_file() {
    let content = read_file("/nonexistent/path/to/file.txt");
    assert!(
        content.starts_with("Error:"),
        "should return error message, got: {}",
        content
    );
}

#[test]
fn read_file_blocks_path_traversal() {
    let content = read_file("../../etc/passwd");
    assert!(
        content.contains("path must be relative"),
        "got: {}",
        content
    );
}

#[test]
fn list_files_finds_files_in_dir() {
    let _guard = cwd_lock().lock().unwrap_or_else(|e| e.into_inner());
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("a.rs"), "").unwrap();
    std::fs::write(dir.path().join("b.rs"), "").unwrap();
    let original = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();

    let result = list_files(".", None);

    std::env::set_current_dir(original).unwrap();
    assert!(result.contains("a.rs"), "should list a.rs");
    assert!(result.contains("b.rs"), "should list b.rs");
}

#[test]
fn list_files_filters_by_pattern() {
    let _guard = cwd_lock().lock().unwrap_or_else(|e| e.into_inner());
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("main.rs"), "").unwrap();
    std::fs::write(dir.path().join("config.toml"), "").unwrap();
    let original = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();

    let result = list_files(".", Some(".rs"));

    std::env::set_current_dir(original).unwrap();
    assert!(result.contains("main.rs"), "should include .rs files");
    assert!(
        !result.contains("config.toml"),
        "should exclude .toml files"
    );
}

#[test]
fn grep_code_finds_pattern() {
    let _guard = cwd_lock().lock().unwrap_or_else(|e| e.into_inner());
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("main.rs"),
        "fn main() {\n    let secret = \"abc\";\n}\n",
    )
    .unwrap();
    let original = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();

    let result = grep_code("secret", Some("."));

    std::env::set_current_dir(original).unwrap();
    assert!(result.contains("secret"), "should find 'secret'");
    assert!(result.contains("main.rs"), "should reference the file");
}

#[test]
fn grep_code_returns_no_matches_message() {
    let _guard = cwd_lock().lock().unwrap_or_else(|e| e.into_inner());
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("a.rs"), "fn main() {}").unwrap();
    let original = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();

    let result = grep_code("VERY_UNLIKELY_PATTERN_XYZ123", Some("."));

    std::env::set_current_dir(original).unwrap();
    assert!(result.contains("No matches"), "should say no matches");
}

use zentra_cli::tools::audit::run_audit;

#[test]
fn run_audit_returns_string_when_tool_not_installed() {
    // Run in a temp dir where audit tools are unlikely to be configured
    // The function must not panic â€” it returns a graceful message
    let _guard = cwd_lock().lock().unwrap_or_else(|e| e.into_inner());
    let dir = TempDir::new().unwrap();
    let original = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();

    let result = run_audit("npm");

    std::env::set_current_dir(original).unwrap();
    // Either actual audit JSON or a "not found / no lockfile" message
    assert!(!result.is_empty());
}

#[test]
fn run_audit_rejects_unknown_tool() {
    let result = run_audit("unknown_tool_xyz");
    assert!(result.contains("Unknown audit tool"));
}

use zentra_cli::agent::orchestrator::OrchestratorAgent;
use zentra_cli::agent::{ScanEvent, ScannerType};

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn tool_registry_dispatches_read_file() {
    let _guard = cwd_lock().lock().unwrap_or_else(|e| e.into_inner());
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("hello.txt"), "hello world").unwrap();
    let original = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();

    let registry = zentra_cli::tools::ToolRegistry::new();
    let writer = StateWriter::new(dir.path()).unwrap();
    let (tx, _rx) = tokio::sync::mpsc::channel(16);

    let result = registry
        .dispatch(
            "read_file",
            &serde_json::json!({"path": "hello.txt"}),
            &writer,
            &tx,
            ScannerType::Sast,
        )
        .await;

    std::env::set_current_dir(original).unwrap();
    assert!(result.contains("hello world"), "got: {}", result);
}

#[tokio::test]
async fn tool_registry_dispatches_write_finding() {
    let dir = TempDir::new().unwrap();
    let registry = zentra_cli::tools::ToolRegistry::new();
    let writer = StateWriter::new(dir.path()).unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);

    let result = registry
        .dispatch(
            "write_finding",
            &serde_json::json!({
                "severity": "high",
                "title": "Test Finding",
                "description": "A test finding",
                "location": "src/main.rs:1",
                "recommendation": "Fix it"
            }),
            &writer,
            &tx,
            ScannerType::Sast,
        )
        .await;

    assert!(result.contains("recorded"), "got: {}", result);
    // Event should have been sent
    let event = rx.try_recv().unwrap();
    assert!(matches!(event, ScanEvent::FindingAdded(_)));
}

#[test]
fn tool_registry_definitions_contains_all_tools() {
    let registry = zentra_cli::tools::ToolRegistry::new();
    let defs = registry.definitions();
    let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();

    for expected in &[
        "read_file",
        "list_files",
        "grep_code",
        "write_finding",
        "write_report",
        "run_audit",
        "git_log",
        "git_diff",
        "git_blame",
        "git_status",
    ] {
        assert!(names.contains(expected), "missing tool: {}", expected);
    }
}

#[test]
fn all_scanner_prompts_are_non_empty() {
    use zentra_cli::agent::ScannerType;
    for scanner in &[
        ScannerType::ThreatModel,
        ScannerType::Sast,
        ScannerType::SupplyChain,
        ScannerType::ApiScan,
        ScannerType::IacScan,
        ScannerType::Report,
    ] {
        let prompt = scanners::system_prompt(*scanner);
        assert!(!prompt.is_empty(), "{:?} has empty system prompt", scanner);
        assert!(
            prompt.len() > 100,
            "{:?} prompt too short ({})",
            scanner,
            prompt.len()
        );
    }
}

#[test]
fn report_prompt_is_non_empty() {
    let prompt = scanners::system_prompt(zentra_cli::agent::ScannerType::Report);
    assert!(prompt.contains("report") || prompt.contains("Report") || prompt.contains("summary"));
}

/// Serialize tests that mutate the process-global current directory so they
/// don't race when cargo runs tests in parallel.
static CWD_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();

fn cwd_lock() -> &'static std::sync::Mutex<()> {
    CWD_LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

#[tokio::test]
async fn scanner_agent_runs_react_loop_and_completes_when_no_tool_calls() {
    let server = MockServer::start().await;

    // First call: agent returns no tool calls (done immediately)
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{"message": {"role": "assistant", "content": "No issues found."}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        })))
        .mount(&server)
        .await;

    let dir = TempDir::new().unwrap();
    let provider = Arc::new(OpenAICompatProvider::new(
        server.uri(),
        "gpt-4o".to_string(),
        "test-key".to_string(),
    ));
    let registry = Arc::new(zentra_cli::tools::ToolRegistry::new());
    let writer = Arc::new(StateWriter::new(dir.path()).unwrap());
    let (tx, _rx) = mpsc::channel(16);

    let agent = ScannerAgent::new(
        ScannerType::Sast,
        provider,
        registry,
        writer,
        tx,
        None,
        CancellationToken::new(),
    );
    let result = agent.run().await;

    assert!(
        result.is_ok(),
        "scanner should complete without error: {:?}",
        result
    );
}

#[tokio::test]
async fn scanner_agent_executes_tool_call_and_feeds_result_back() {
    let server = MockServer::start().await;
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();

    // First response: agent calls list_files â€” consumed once (up_to_n_times),
    // then falls through to the fallback mock below for all subsequent requests.
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "list_files",
                            "arguments": "{\"dir\": \".\"}"
                        }
                    }]
                }
            }],
            "usage": {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30}
        })))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;

    // Second response: agent is done after seeing file list (fallback for all subsequent calls)
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{"message": {"role": "assistant", "content": "Scan complete."}}],
            "usage": {"prompt_tokens": 30, "completion_tokens": 5, "total_tokens": 35}
        })))
        .mount(&server)
        .await;

    let provider = Arc::new(OpenAICompatProvider::new(
        server.uri(),
        "gpt-4o".to_string(),
        "test-key".to_string(),
    ));
    let registry = Arc::new(zentra_cli::tools::ToolRegistry::new());
    let writer = Arc::new(StateWriter::new(dir.path()).unwrap());
    let (tx, mut rx) = mpsc::channel(16);

    let agent = ScannerAgent::new(
        ScannerType::Sast,
        provider,
        registry,
        writer,
        tx,
        None,
        CancellationToken::new(),
    );
    agent.run().await.unwrap();

    // Should have sent ToolCall event
    let mut found_tool_call = false;
    while let Ok(event) = rx.try_recv() {
        if matches!(event, ScanEvent::ToolCall { .. }) {
            found_tool_call = true;
        }
    }
    assert!(found_tool_call, "should have sent ToolCall event");
}

#[test]
fn git_log_returns_string_outside_git_repo() {
    // Run from a temp dir with no .git â€” should not panic, just return graceful message
    let _guard = cwd_lock().lock().unwrap_or_else(|e| e.into_inner());
    let dir = TempDir::new().unwrap();
    let original = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();

    let result = git_log(5);

    std::env::set_current_dir(&original).unwrap();
    // Either returns commits or a graceful "not a git repo" message â€” must not panic
    assert!(!result.is_empty());
}

#[test]
fn git_status_returns_string_outside_git_repo() {
    let _guard = cwd_lock().lock().unwrap_or_else(|e| e.into_inner());
    let dir = TempDir::new().unwrap();
    let original = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();

    let result = git_status();

    std::env::set_current_dir(&original).unwrap();
    assert!(!result.is_empty());
}

#[tokio::test]
async fn orchestrator_runs_selected_scanners_in_order() {
    let server = MockServer::start().await;

    // All calls return immediately with no tool calls
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{"message": {"role": "assistant", "content": "done"}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}
        })))
        .mount(&server)
        .await;

    let dir = TempDir::new().unwrap();
    let provider: Arc<dyn zentra_cli::provider::LLMProvider> = Arc::new(OpenAICompatProvider::new(
        server.uri(),
        "gpt-4o".to_string(),
        "key".to_string(),
    ));
    let registry = Arc::new(zentra_cli::tools::ToolRegistry::new());
    let writer = Arc::new(zentra_cli::state::StateWriter::new(dir.path()).unwrap());
    let (tx, mut rx) = mpsc::channel(32);

    let orchestrator =
        OrchestratorAgent::new(provider, registry, writer, tx, CancellationToken::new());

    orchestrator
        .run(&[
            ScannerType::ThreatModel,
            ScannerType::Sast,
            ScannerType::Report,
        ])
        .await
        .unwrap();

    // Collect all events
    let mut started = vec![];
    let mut completed = vec![];
    while let Ok(event) = rx.try_recv() {
        match event {
            ScanEvent::ScannerStarted(s) => started.push(s),
            ScanEvent::ScannerCompleted(s) => completed.push(s),
            _ => {}
        }
    }

    assert!(started.contains(&ScannerType::ThreatModel));
    assert!(started.contains(&ScannerType::Sast));
    assert!(started.contains(&ScannerType::Report));
    assert_eq!(completed.len(), 3);
}

#[tokio::test]
async fn orchestrator_continues_to_report_after_parallel_scanner_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{"message": {"role": "assistant", "content": "done"}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}
        })))
        .up_to_n_times(2)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(400).set_body_string("bad request"))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{"message": {"role": "assistant", "content": "done"}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}
        })))
        .mount(&server)
        .await;

    let dir = TempDir::new().unwrap();
    let provider: Arc<dyn zentra_cli::provider::LLMProvider> = Arc::new(OpenAICompatProvider::new(
        server.uri(),
        "gpt-4o".to_string(),
        "key".to_string(),
    ));
    let registry = Arc::new(zentra_cli::tools::ToolRegistry::new());
    let writer = Arc::new(zentra_cli::state::StateWriter::new(dir.path()).unwrap());
    let (tx, mut rx) = mpsc::channel(32);

    let orchestrator =
        OrchestratorAgent::new(provider, registry, writer, tx, CancellationToken::new());

    let _failed = orchestrator
        .run(&[
            ScannerType::ThreatModel,
            ScannerType::Sast,
            ScannerType::IacScan,
            ScannerType::Report,
        ])
        .await
        .unwrap();

    let mut started = vec![];
    let mut completed = vec![];
    let mut saw_error = false;
    while let Ok(event) = rx.try_recv() {
        match event {
            ScanEvent::ScannerStarted(s) => started.push(s),
            ScanEvent::ScannerCompleted(s) => completed.push(s),
            ScanEvent::Error { .. } => saw_error = true,
            _ => {}
        }
    }

    assert!(saw_error, "should emit scanner error event");
    assert!(
        started.contains(&ScannerType::Report),
        "report should still start"
    );
    assert!(
        completed.contains(&ScannerType::Report),
        "report should still complete"
    );
}

#[tokio::test]
async fn orchestrator_returns_failed_scanners() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{"message": {"role": "assistant", "content": "done"}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}
        })))
        .up_to_n_times(2)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(400).set_body_string("bad request"))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{"message": {"role": "assistant", "content": "done"}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}
        })))
        .mount(&server)
        .await;

    let dir = TempDir::new().unwrap();
    let provider: Arc<dyn zentra_cli::provider::LLMProvider> = Arc::new(OpenAICompatProvider::new(
        server.uri(),
        "gpt-4o".to_string(),
        "key".to_string(),
    ));
    let registry = Arc::new(zentra_cli::tools::ToolRegistry::new());
    let writer = Arc::new(zentra_cli::state::StateWriter::new(dir.path()).unwrap());
    let (tx, _rx) = mpsc::channel(32);

    let orchestrator =
        OrchestratorAgent::new(provider, registry, writer, tx, CancellationToken::new());

    let failed = orchestrator
        .run(&[
            ScannerType::ThreatModel,
            ScannerType::Sast,
            ScannerType::IacScan,
            ScannerType::Report,
        ])
        .await
        .unwrap();

    assert!(!failed.is_empty(), "expected at least one failed scanner in the Vec");
    // ThreatModel is sequential (phase 1) and gets one of the two 200 responses.
    // Sast and IacScan run concurrently in phase 2; one gets the remaining 200,
    // the other receives the 400. Which one fails is non-deterministic, so we
    // assert membership in the set of parallel scanners that can plausibly fail.
    assert!(
        failed.iter().any(|s| matches!(s, ScannerType::Sast | ScannerType::IacScan)),
        "expected a parallel scanner (Sast or IacScan) in the failed list, got: {:?}",
        failed
    );
}

#[tokio::test]
async fn scanner_agent_emits_tokens_used_event() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{"message": {"role": "assistant", "content": "Done."}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150}
        })))
        .mount(&server)
        .await;

    let dir = TempDir::new().unwrap();
    let provider = Arc::new(OpenAICompatProvider::new(
        server.uri(),
        "gpt-4o".to_string(),
        "key".to_string(),
    ));
    let registry = Arc::new(zentra_cli::tools::ToolRegistry::new());
    let writer = Arc::new(StateWriter::new(dir.path()).unwrap());
    let (tx, mut rx) = mpsc::channel(16);

    ScannerAgent::new(
        ScannerType::Sast,
        provider,
        registry,
        writer,
        tx,
        None,
        CancellationToken::new(),
    )
    .run()
    .await
    .unwrap();

    let mut found_tokens = false;
    while let Ok(event) = rx.try_recv() {
        if matches!(event, ScanEvent::TokensUsed { .. }) {
            found_tokens = true;
        }
    }
    assert!(found_tokens, "should have emitted TokensUsed event");
}

#[cfg(unix)]
#[test]
fn read_file_rejects_symlink_escaping_cwd() {
    use std::os::unix::fs::symlink;
    let _guard = cwd_lock().lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::TempDir::new().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(outside.path(), b"SECRET").unwrap();
    symlink(outside.path(), dir.path().join("link")).unwrap();
    let prev = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();
    let out = read_file("link");
    std::env::set_current_dir(prev).unwrap();
    assert!(out.contains("escapes the scan root"), "got: {out}");
}

#[cfg(unix)]
#[test]
fn list_files_rejects_symlinked_root_escaping_cwd() {
    use std::os::unix::fs::symlink;
    let _guard = cwd_lock().lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::TempDir::new().unwrap();
    let outside = tempfile::TempDir::new().unwrap();
    std::fs::write(outside.path().join("secret.txt"), b"SECRET").unwrap();
    symlink(outside.path(), dir.path().join("out")).unwrap();
    let prev = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();
    let out = list_files("out", None);
    std::env::set_current_dir(prev).unwrap();
    assert!(out.contains("escapes the scan root"), "got: {out}");
}

// ---- Finding correlation / corroboration ----

#[test]
fn finding_block_roundtrips_corroboration() {
    let dir = TempDir::new().unwrap();
    let writer = StateWriter::new(dir.path()).unwrap();
    writer
        .write_finding(&Finding {
            scanner: "sast".to_string(),
            severity: Severity::High,
            title: "Missing auth on admin route".to_string(),
            description: "No authorization guard.".to_string(),
            location: Some("src/admin.rs:5".to_string()),
            recommendation: "Add an auth middleware.".to_string(),
            corroborated_by: vec!["threat_model".to_string(), "api_scan".to_string()],
        })
        .unwrap();

    let raw = writer.read_findings_raw().unwrap();
    assert!(raw.contains("**Corroborated by:** threat_model, api_scan"));

    let parsed = zentra_cli::state::parse_findings(&raw);
    assert_eq!(parsed.len(), 1);
    assert_eq!(
        parsed[0].corroborated_by,
        vec!["threat_model".to_string(), "api_scan".to_string()]
    );
}

#[test]
fn legacy_markdown_without_corroboration_parses() {
    // Block in the pre-feature format — no "Corroborated by" line.
    let legacy = "## [HIGH] Old finding\n\
**Scanner:** sast\n\
**Location:** src/x.rs:1\n\
**Description:** something\n\
**Recommendation:** fix it\n\n---\n";
    let parsed = zentra_cli::state::parse_findings(legacy);
    assert_eq!(parsed.len(), 1);
    assert!(parsed[0].corroborated_by.is_empty());
}

#[test]
fn singleton_finding_markdown_has_no_corroboration_line() {
    let dir = TempDir::new().unwrap();
    let writer = StateWriter::new(dir.path()).unwrap();
    writer
        .write_finding(&Finding {
            scanner: "sast".to_string(),
            severity: Severity::Low,
            title: "Lone finding".to_string(),
            description: "desc".to_string(),
            location: None,
            recommendation: "fix".to_string(),
            corroborated_by: vec![],
        })
        .unwrap();
    let raw = writer.read_findings_raw().unwrap();
    assert!(
        !raw.contains("Corroborated by"),
        "singleton output must be unchanged, got:\n{raw}"
    );
}

#[tokio::test]
async fn correlate_merges_semantic_duplicates_via_llm() {
    let server = MockServer::start().await;
    // One LLM call returns a cluster joining the two findings.
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "report_clusters",
                            "arguments": "{\"clusters\": [[0, 1]]}"
                        }
                    }]
                }
            }],
            "usage": {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30}
        })))
        .mount(&server)
        .await;

    let provider: Arc<dyn zentra_cli::provider::LLMProvider> = Arc::new(OpenAICompatProvider::new(
        server.uri(),
        "gpt-4o".to_string(),
        "key".to_string(),
    ));

    // Distinct wording + locations so the deterministic pre-pass does NOT merge them;
    // only the LLM clustering can.
    let findings = vec![
        Finding {
            scanner: "threat_model".to_string(),
            severity: Severity::Critical,
            title: "Broken access control on admin surface".to_string(),
            description: "Privileged routes lack authorization.".to_string(),
            location: None,
            recommendation: "Enforce RBAC.".to_string(),
            corroborated_by: vec![],
        },
        Finding {
            scanner: "sast".to_string(),
            severity: Severity::Medium,
            title: "Missing authorization guard".to_string(),
            description: "Handler does not check the caller's role.".to_string(),
            location: Some("src/admin.rs:5".to_string()),
            recommendation: "Add a role check.".to_string(),
            corroborated_by: vec![],
        },
    ];

    let out = zentra_cli::agent::correlation::correlate(&provider, findings).await;
    assert_eq!(out.len(), 1, "the two findings should collapse into one");
    // Primary prefers the member with a concrete location (sast).
    assert_eq!(out[0].scanner, "sast");
    assert_eq!(out[0].location.as_deref(), Some("src/admin.rs:5"));
    // Highest severity is preserved.
    assert!(matches!(out[0].severity, Severity::Critical));
    // The other scanner is recorded as corroborating.
    assert_eq!(out[0].corroborated_by, vec!["threat_model".to_string()]);
}

#[tokio::test]
async fn scanner_aborts_when_context_budget_irreducible() {
    let server = MockServer::start().await;
    // Expect ZERO calls: the guard must abort before any request.
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{ "message": { "content": "should not be called" } }]
        })))
        .expect(0)
        .mount(&server)
        .await;

    let provider = Arc::new(
        OpenAICompatProvider::new(
            server.uri(),
            "tiny-model".to_string(),
            "key".to_string(),
        )
        .with_context_window(Some(1)),
    );

    let (tx, mut rx) = mpsc::channel(128);
    let tmp = tempfile::TempDir::new().unwrap();
    let state_writer = Arc::new(
        zentra_cli::state::StateWriter::new(tmp.path()).unwrap(),
    );
    let registry = Arc::new(zentra_cli::tools::ToolRegistry::new());

    let agent = ScannerAgent::new(
        ScannerType::Sast,
        provider,
        registry,
        state_writer,
        tx,
        None,
        CancellationToken::new(),
    );
    let result = agent.run().await;
    assert!(result.is_err(), "irreducible budget must return Err");

    let mut saw_error = false;
    while let Ok(ev) = rx.try_recv() {
        if let ScanEvent::Error { message, .. } = ev {
            assert!(message.contains("context budget exceeded"));
            saw_error = true;
        }
    }
    assert!(saw_error, "must emit a context-budget Error event");
    // .expect(0) on the mock verifies the provider was never called on drop.
}

#[tokio::test]
async fn correlate_preserves_findings_on_llm_failure() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(400).set_body_string("bad request"))
        .mount(&server)
        .await;

    let provider: Arc<dyn zentra_cli::provider::LLMProvider> = Arc::new(OpenAICompatProvider::new(
        server.uri(),
        "gpt-4o".to_string(),
        "key".to_string(),
    ));

    let findings = vec![
        Finding {
            scanner: "threat_model".to_string(),
            severity: Severity::High,
            title: "Issue one".to_string(),
            description: "d1".to_string(),
            location: None,
            recommendation: "r1".to_string(),
            corroborated_by: vec![],
        },
        Finding {
            scanner: "sast".to_string(),
            severity: Severity::Low,
            title: "Completely different issue two".to_string(),
            description: "d2".to_string(),
            location: Some("src/two.rs:9".to_string()),
            recommendation: "r2".to_string(),
            corroborated_by: vec![],
        },
    ];

    let out = zentra_cli::agent::correlation::correlate(&provider, findings).await;
    assert_eq!(out.len(), 2, "no findings may be dropped when correlation fails");
}
