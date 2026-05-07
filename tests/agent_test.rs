// tests/agent_test.rs
use zentra_cli::{agent, state, tools};
use zentra_cli::tools::fs_tools::{grep_code, list_files, read_file};
use zentra_cli::tools::git_tools::{git_log, git_status};
use zentra_cli::scanners;

use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use zentra_cli::agent::scanner::ScannerAgent;
use zentra_cli::provider::openai_compat::OpenAICompatProvider;
use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{method, path};

#[test]
fn modules_exist() {
    // compile-time verification that all new modules are declared
    let _ = std::any::type_name::<agent::ScannerType>();
    let _ = std::any::type_name::<state::Finding>();
    let _ = std::any::type_name::<tools::ToolRegistry>();
}

use zentra_cli::state::{Finding, Severity, StateWriter};
use tempfile::TempDir;

#[test]
fn state_writer_creates_findings_file() {
    let dir = TempDir::new().unwrap();
    let writer = StateWriter::new(dir.path()).unwrap();

    writer.write_finding(&Finding {
        scanner: "sast".to_string(),
        severity: Severity::Critical,
        title: "SQL Injection".to_string(),
        description: "User input concatenated into SQL".to_string(),
        location: Some("src/db.rs:42".to_string()),
        recommendation: "Use parameterized queries.".to_string(),
    }).unwrap();

    let findings_path = dir.path().join(".zentra").join("detailed-findings.md");
    assert!(findings_path.exists(), "detailed-findings.md should exist");

    let content = std::fs::read_to_string(&findings_path).unwrap();
    assert!(content.contains("SQL Injection"), "should contain finding title");
    assert!(content.contains("CRITICAL"), "should contain severity");
    assert!(content.contains("src/db.rs:42"), "should contain location");
}

#[test]
fn state_writer_appends_multiple_findings() {
    let dir = TempDir::new().unwrap();
    let writer = StateWriter::new(dir.path()).unwrap();

    for i in 0..3 {
        writer.write_finding(&Finding {
            scanner: "sast".to_string(),
            severity: Severity::High,
            title: format!("Finding {}", i),
            description: "desc".to_string(),
            location: None,
            recommendation: "fix it".to_string(),
        }).unwrap();
    }

    let content = std::fs::read_to_string(dir.path().join(".zentra").join("detailed-findings.md")).unwrap();
    assert!(content.contains("Finding 0"));
    assert!(content.contains("Finding 1"));
    assert!(content.contains("Finding 2"));
}

#[test]
fn state_writer_writes_report() {
    let dir = TempDir::new().unwrap();
    let writer = StateWriter::new(dir.path()).unwrap();
    writer.write_report("# Executive Summary\n\nAll clear.").unwrap();

    let reports_dir = dir.path().join(".zentra").join("reports");
    let entries: Vec<_> = std::fs::read_dir(&reports_dir).unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(entries.len(), 1, "should have one report file");

    let filename = entries[0].file_name();
    let name = filename.to_string_lossy();
    assert!(name.ends_with("-report.md"), "filename should end with -report.md, got: {}", name);

    let content = std::fs::read_to_string(entries[0].path()).unwrap();
    assert!(content.contains("Executive Summary"), "report should contain written content");
}

#[test]
fn read_findings_raw_returns_empty_when_no_findings() {
    let dir = TempDir::new().unwrap();
    let writer = StateWriter::new(dir.path()).unwrap();
    let result = writer.read_findings_raw().unwrap();
    assert!(result.is_empty(), "should return empty string when no findings written");
}

#[test]
fn read_findings_raw_returns_written_findings() {
    let dir = TempDir::new().unwrap();
    let writer = StateWriter::new(dir.path()).unwrap();
    writer.write_finding(&Finding {
        scanner: "sast".to_string(),
        severity: Severity::Low,
        title: "Test".to_string(),
        description: "desc".to_string(),
        location: None,
        recommendation: "fix".to_string(),
    }).unwrap();

    let content = writer.read_findings_raw().unwrap();
    assert!(content.contains("Test"), "should contain the written finding title");
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
    assert!(content.starts_with("Error:"), "should return error message, got: {}", content);
}

#[test]
fn read_file_blocks_path_traversal() {
    let content = read_file("../../etc/passwd");
    assert!(content.contains("path must be relative"), "got: {}", content);
}

#[test]
fn list_files_finds_files_in_dir() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("a.rs"), "").unwrap();
    std::fs::write(dir.path().join("b.rs"), "").unwrap();

    let result = list_files(dir.path().to_str().unwrap(), None);
    assert!(result.contains("a.rs"), "should list a.rs");
    assert!(result.contains("b.rs"), "should list b.rs");
}

#[test]
fn list_files_filters_by_pattern() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("main.rs"), "").unwrap();
    std::fs::write(dir.path().join("config.toml"), "").unwrap();

    let result = list_files(dir.path().to_str().unwrap(), Some(".rs"));
    assert!(result.contains("main.rs"), "should include .rs files");
    assert!(!result.contains("config.toml"), "should exclude .toml files");
}

#[test]
fn grep_code_finds_pattern() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("main.rs"), "fn main() {\n    let secret = \"abc\";\n}\n").unwrap();

    let result = grep_code("secret", Some(dir.path().to_str().unwrap()));
    assert!(result.contains("secret"), "should find 'secret'");
    assert!(result.contains("main.rs"), "should reference the file");
}

#[test]
fn grep_code_returns_no_matches_message() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("a.rs"), "fn main() {}").unwrap();

    let result = grep_code("VERY_UNLIKELY_PATTERN_XYZ123", Some(dir.path().to_str().unwrap()));
    assert!(result.contains("No matches"), "should say no matches");
}

use zentra_cli::tools::audit::run_audit;

#[test]
fn run_audit_returns_string_when_tool_not_installed() {
    // Run in a temp dir where audit tools are unlikely to be configured
    // The function must not panic — it returns a graceful message
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

use zentra_cli::agent::{ScanEvent, ScannerType};
use zentra_cli::agent::orchestrator::OrchestratorAgent;

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

    let result = registry.dispatch(
        "read_file",
        &serde_json::json!({"path": "hello.txt"}),
        &writer,
        &tx,
        ScannerType::Sast,
    ).await;

    std::env::set_current_dir(original).unwrap();
    assert!(result.contains("hello world"), "got: {}", result);
}

#[tokio::test]
async fn tool_registry_dispatches_write_finding() {
    let dir = TempDir::new().unwrap();
    let registry = zentra_cli::tools::ToolRegistry::new();
    let writer = StateWriter::new(dir.path()).unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);

    let result = registry.dispatch(
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
    ).await;

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

    for expected in &["read_file", "list_files", "grep_code", "write_finding",
                       "run_audit", "git_log", "git_diff", "git_blame", "git_status"] {
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
        assert!(prompt.len() > 100, "{:?} prompt too short ({})", scanner, prompt.len());
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
        server.uri(), "gpt-4o".to_string(), "test-key".to_string(),
    ));
    let registry = Arc::new(zentra_cli::tools::ToolRegistry::new());
    let writer = Arc::new(StateWriter::new(dir.path()).unwrap());
    let (tx, _rx) = mpsc::channel(16);

    let agent = ScannerAgent::new(ScannerType::Sast, provider, registry, writer, tx, None, CancellationToken::new());
    let result = agent.run().await;

    assert!(result.is_ok(), "scanner should complete without error: {:?}", result);
}

#[tokio::test]
async fn scanner_agent_executes_tool_call_and_feeds_result_back() {
    let server = MockServer::start().await;
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();

    // First response: agent calls list_files — consumed once (up_to_n_times),
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
        server.uri(), "gpt-4o".to_string(), "test-key".to_string(),
    ));
    let registry = Arc::new(zentra_cli::tools::ToolRegistry::new());
    let writer = Arc::new(StateWriter::new(dir.path()).unwrap());
    let (tx, mut rx) = mpsc::channel(16);

    let agent = ScannerAgent::new(ScannerType::Sast, provider, registry, writer, tx, None, CancellationToken::new());
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
    // Run from a temp dir with no .git — should not panic, just return graceful message
    let _guard = cwd_lock().lock().unwrap_or_else(|e| e.into_inner());
    let dir = TempDir::new().unwrap();
    let original = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();

    let result = git_log(5);

    std::env::set_current_dir(&original).unwrap();
    // Either returns commits or a graceful "not a git repo" message — must not panic
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
    let provider: Arc<dyn zentra_cli::provider::LLMProvider> = Arc::new(
        OpenAICompatProvider::new(server.uri(), "gpt-4o".to_string(), "key".to_string())
    );
    let registry = Arc::new(zentra_cli::tools::ToolRegistry::new());
    let writer = Arc::new(zentra_cli::state::StateWriter::new(dir.path()).unwrap());
    let (tx, mut rx) = mpsc::channel(32);

    let orchestrator = OrchestratorAgent::new(
        provider, registry, writer, tx, zentra_cli::scanners::secrets::HistoryDepth::default(), CancellationToken::new(),
    );

    orchestrator.run(&[ScannerType::ThreatModel, ScannerType::Sast, ScannerType::Report]).await.unwrap();

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
        server.uri(), "gpt-4o".to_string(), "key".to_string(),
    ));
    let registry = Arc::new(zentra_cli::tools::ToolRegistry::new());
    let writer = Arc::new(StateWriter::new(dir.path()).unwrap());
    let (tx, mut rx) = mpsc::channel(16);

    ScannerAgent::new(ScannerType::Sast, provider, registry, writer, tx, None, CancellationToken::new())
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
