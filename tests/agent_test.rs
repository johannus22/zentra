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
            cwe: None,
            secondary_cwe: vec![],
            cvss_vector: None,
            cvss_score: None,
            owasp: None,
            confidence: None,
            screening: None,
            evidence: None,
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
fn state_writer_writes_html_findings_report() {
    let dir = TempDir::new().unwrap();
    let writer = StateWriter::new(dir.path()).unwrap();

    writer
        .write_finding(&Finding {
            scanner: "sast".to_string(),
            severity: Severity::High,
            title: "SQL Injection".to_string(),
            description: "User input concatenated into SQL".to_string(),
            location: Some("src/db.rs:42".to_string()),
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
        })
        .unwrap();

    let raw =
        std::fs::read_to_string(dir.path().join(".zentra").join("detailed-findings.md")).unwrap();
    let findings = zentra_cli::state::parse_findings(&raw);

    let path = dir
        .path()
        .join(".zentra")
        .join("reports")
        .join("findings.html");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        &path,
        zentra_cli::state::html::render_report_html(
            &findings,
            "Zentra SAST Report",
            &[("Project", "my-project"), ("Branch", "main")],
        ),
    )
    .unwrap();
    assert!(path.exists(), "findings.html should exist");

    let html = std::fs::read_to_string(path).unwrap();
    assert!(html.starts_with("<!DOCTYPE html>"));
    assert!(html.contains("Zentra SAST Report"));
    assert!(html.contains("my-project"));
    assert!(html.contains("main"));
    assert!(html.contains("SQL Injection"));
    assert!(html.contains("src/db.rs:42"));
    assert!(html.contains("Use parameterized queries"));
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
                cwe: None,
                secondary_cwe: vec![],
                cvss_vector: None,
                cvss_score: None,
                owasp: None,
                confidence: None,
                screening: None,
                evidence: None,
            })
            .unwrap();
    }

    let content =
        std::fs::read_to_string(dir.path().join(".zentra").join("detailed-findings.md")).unwrap();
    assert!(content.contains("Finding 0"));
    assert!(content.contains("Finding 1"));
    assert!(content.contains("Finding 2"));
}

// H1 (chaos re-test): the 4 Phase-2 scanners run on separate runtime threads and
// share one `Arc<StateWriter>`. `write_finding` is append + read-whole + sort +
// write-whole with no lock, so concurrent calls lose updates — a dropped finding
// can be a Critical, and the scan still reports success. Hammer it from many
// threads and assert every finding survives.
#[test]
fn concurrent_write_finding_never_drops_a_finding() {
    use std::sync::{Arc, Barrier};

    let dir = TempDir::new().unwrap();
    let writer = Arc::new(StateWriter::new(dir.path()).unwrap());

    const N: usize = 32;
    // Release every thread into write_finding at the same instant to maximize the
    // append/read-sort-write overlap that the missing lock exposes.
    let barrier = Arc::new(Barrier::new(N));
    let handles: Vec<_> = (0..N)
        .map(|i| {
            let w = Arc::clone(&writer);
            let b = Arc::clone(&barrier);
            std::thread::spawn(move || {
                b.wait();
                // A few writes each further widens the racing window.
                for r in 0..4 {
                    w.write_finding(&Finding {
                        scanner: "sast".to_string(),
                        severity: Severity::High,
                        title: format!("RaceFinding-{i}-{r}"),
                        description: "desc".to_string(),
                        location: None,
                        recommendation: "fix it".to_string(),
                        corroborated_by: vec![],
                        cwe: None,
                        secondary_cwe: vec![],
                        cvss_vector: None,
                        cvss_score: None,
                        owasp: None,
                        confidence: None,
                        screening: None,
                        evidence: None,
                    })
                    .unwrap();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }

    const N_TOTAL: usize = N * 4;

    let content = writer.read_findings_raw().unwrap();
    let present = (0..N)
        .flat_map(|i| (0..4).map(move |r| format!("RaceFinding-{i}-{r}")))
        .filter(|t| content.contains(t))
        .count();
    assert_eq!(
        present, N_TOTAL,
        "concurrent write_finding dropped {} of {N_TOTAL} findings",
        N_TOTAL - present
    );
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
            cwe: None,
            secondary_cwe: vec![],
            cvss_vector: None,
            cvss_score: None,
            owasp: None,
            confidence: None,
            screening: None,
            evidence: None,
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
            cwe: None,
            secondary_cwe: vec![],
            cvss_vector: None,
            cvss_score: None,
            owasp: None,
            confidence: None,
            screening: None,
            evidence: None,
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
            cwe: None,
            secondary_cwe: vec![],
            cvss_vector: None,
            cvss_score: None,
            owasp: None,
            confidence: None,
            screening: None,
            evidence: None,
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

#[tokio::test]
async fn write_finding_captures_cwe_cvss_owasp() {
    let dir = TempDir::new().unwrap();
    let writer = Arc::new(StateWriter::new(dir.path()).unwrap());
    let registry = zentra_cli::tools::ToolRegistry::new();
    let (tx, mut rx) = mpsc::channel(16);

    let args = serde_json::json!({
        "severity": "high",
        "title": "SQL Injection",
        "description": "Concatenated SQL",
        "location": "src/db.rs:10",
        "recommendation": "Use parameterized queries",
        "cwe": "CWE-89",
        "secondary_cwe": ["CWE-20", "garbage"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "owasp": "A03:2021-Injection"
    });

    registry
        .dispatch("write_finding", &args, &writer, &tx, ScannerType::Sast)
        .await;

    let f = match rx.recv().await.expect("event emitted") {
        ScanEvent::FindingAdded(f) => f,
        other => panic!("expected FindingAdded, got {other:?}"),
    };
    assert_eq!(f.cwe.as_deref(), Some("CWE-89"));
    assert_eq!(f.secondary_cwe, vec!["CWE-20".to_string()]); // "garbage" dropped
    assert_eq!(
        f.cvss_vector.as_deref(),
        Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    );
    assert!((f.cvss_score.unwrap() - 9.8).abs() < 0.001);
    assert_eq!(f.owasp.as_deref(), Some("A03:2021-Injection"));
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

#[tokio::test]
async fn scanner_cancel_emits_completed_and_returns() {
    // A pre-cancelled token must cause the scanner to return promptly and
    // still emit ScannerCompleted (the clean exit path, not an error path).
    let server = MockServer::start().await;

    // Provide a response with a tool call — but cancel token fires before
    // the LLM call is even attempted, so the server should see zero requests.
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
    let (tx, mut rx) = mpsc::channel(32);

    let cancel = CancellationToken::new();
    cancel.cancel(); // pre-cancelled: scanner must exit fast

    let agent = ScannerAgent::new(
        ScannerType::Sast,
        provider,
        registry,
        writer,
        tx,
        None,
        cancel,
    );

    let handle = tokio::spawn(async move { agent.run().await });
    let res = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
    assert!(res.is_ok(), "scanner did not return promptly after cancel");

    // Drain the channel and assert ScannerCompleted was emitted
    let mut found_completed = false;
    while let Ok(event) = rx.try_recv() {
        if matches!(event, zentra_cli::agent::ScanEvent::ScannerCompleted(_)) {
            found_completed = true;
        }
    }
    assert!(
        found_completed,
        "scanner must emit ScannerCompleted even when cancelled"
    );
}

#[test]
fn scanner_agent_blocks_out_of_scope_tool_calls_under_incremental_scope() {
    // Sync plus block_on: a std MutexGuard must not cross an await point, or the
    // task can resume on another runtime thread while holding the CWD lock.
    let _guard = cwd_lock().lock().unwrap_or_else(|e| e.into_inner());
    let original_cwd = std::env::current_dir().unwrap();
    let dir = TempDir::new().unwrap();
    // A file that would show up in a real list_files/read_file call if scope
    // enforcement did NOT kick in — proves the real filesystem tools never ran.
    std::fs::write(dir.path().join("secret.rs"), "fn leaked() {}").unwrap();
    std::fs::write(dir.path().join("keep.rs"), "fn keep() {}").unwrap();
    std::env::set_current_dir(dir.path()).unwrap();

    let server = block_on(MockServer::start());

    // First response: agent calls list_files, which is always out of scope.
    let first_response = Mock::given(method("POST"))
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
        .expect(1);
    block_on(first_response.mount(&server));

    // Fallback for all subsequent requests: agent is done.
    let fallback = Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{"message": {"role": "assistant", "content": "Scan complete."}}],
            "usage": {"prompt_tokens": 30, "completion_tokens": 5, "total_tokens": 35}
        })));
    block_on(fallback.mount(&server));

    let provider = Arc::new(OpenAICompatProvider::new(
        server.uri(),
        "gpt-4o".to_string(),
        "test-key".to_string(),
    ));
    let registry = Arc::new(zentra_cli::tools::ToolRegistry::new());
    let writer = Arc::new(StateWriter::new(dir.path()).unwrap());
    let (tx, _rx) = mpsc::channel(16);

    let agent = ScannerAgent::new_with_contexts(
        ScannerType::Sast,
        provider,
        registry,
        writer,
        tx,
        None,
        None,
        CancellationToken::new(),
    )
    .with_incremental_scope(Some(vec!["keep.rs".to_string()]));
    let result = block_on(agent.run());

    std::env::set_current_dir(&original_cwd).unwrap();
    result.unwrap();

    // The second request carries the tool result for the blocked list_files
    // call. It must show the block message and must NOT show a real
    // directory listing (which would include "secret.rs").
    let requests = block_on(server.received_requests()).unwrap();
    assert!(
        requests.len() >= 2,
        "expected at least 2 requests, got {}",
        requests.len()
    );
    let second_body: serde_json::Value = serde_json::from_slice(&requests[1].body).unwrap();
    let messages = second_body["messages"].as_array().unwrap();
    let tool_result = messages
        .iter()
        .find(|m| m["role"] == "tool")
        .expect("expected a tool-result message in the second request");
    let content = tool_result["content"].as_str().unwrap_or("");
    assert!(
        content.contains("[INCREMENTAL SCOPE]"),
        "expected block message, got: {content}"
    );
    assert!(
        !content.contains("secret.rs"),
        "list_files must never actually run under incremental scope, got: {content}"
    );
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

    let summary = orchestrator
        .run(&[
            ScannerType::ThreatModel,
            ScannerType::Sast,
            ScannerType::IacScan,
            ScannerType::Report,
        ])
        .await
        .unwrap();
    let failed = summary.failed;

    assert!(
        !failed.is_empty(),
        "expected at least one failed scanner in the Vec"
    );
    // ThreatModel is sequential (phase 1) and gets one of the two 200 responses.
    // Sast and IacScan run concurrently in phase 2; one gets the remaining 200,
    // the other receives the 400. Which one fails is non-deterministic, so we
    // assert membership in the set of parallel scanners that can plausibly fail.
    assert!(
        failed
            .iter()
            .any(|s| matches!(s, ScannerType::Sast | ScannerType::IacScan)),
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
            cwe: None,
            secondary_cwe: vec![],
            cvss_vector: None,
            cvss_score: None,
            owasp: None,
            confidence: None,
            screening: None,
            evidence: None,
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
            cwe: None,
            secondary_cwe: vec![],
            cvss_vector: None,
            cvss_score: None,
            owasp: None,
            confidence: None,
            screening: None,
            evidence: None,
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
            cwe: None,
            secondary_cwe: vec![],
            cvss_vector: None,
            cvss_score: None,
            owasp: None,
            confidence: None,
            screening: None,
            evidence: None,
        },
        Finding {
            scanner: "sast".to_string(),
            severity: Severity::Medium,
            title: "Missing authorization guard".to_string(),
            description: "Handler does not check the caller's role.".to_string(),
            location: Some("src/admin.rs:5".to_string()),
            recommendation: "Add a role check.".to_string(),
            corroborated_by: vec![],
            cwe: None,
            secondary_cwe: vec![],
            cvss_vector: None,
            cvss_score: None,
            owasp: None,
            confidence: None,
            screening: None,
            evidence: None,
        },
    ];

    let out = zentra_cli::agent::correlation::correlate(&provider, findings, None).await;
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
        OpenAICompatProvider::new(server.uri(), "tiny-model".to_string(), "key".to_string())
            .with_context_window(Some(1)),
    );

    let (tx, mut rx) = mpsc::channel(128);
    let tmp = tempfile::TempDir::new().unwrap();
    let state_writer = Arc::new(zentra_cli::state::StateWriter::new(tmp.path()).unwrap());
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
            cwe: None,
            secondary_cwe: vec![],
            cvss_vector: None,
            cvss_score: None,
            owasp: None,
            confidence: None,
            screening: None,
            evidence: None,
        },
        Finding {
            scanner: "sast".to_string(),
            severity: Severity::Low,
            title: "Completely different issue two".to_string(),
            description: "d2".to_string(),
            location: Some("src/two.rs:9".to_string()),
            recommendation: "r2".to_string(),
            corroborated_by: vec![],
            cwe: None,
            secondary_cwe: vec![],
            cvss_vector: None,
            cvss_score: None,
            owasp: None,
            confidence: None,
            screening: None,
            evidence: None,
        },
    ];

    let out = zentra_cli::agent::correlation::correlate(&provider, findings, None).await;
    assert_eq!(
        out.len(),
        2,
        "no findings may be dropped when correlation fails"
    );
}

/// Minimal test-only provider that errors if actually called. Used by tests
/// that run the orchestrator with an empty scanner list so no LLM call occurs.
mod test_support {
    use anyhow::anyhow;
    use async_trait::async_trait;
    use tokio_util::sync::CancellationToken;
    use zentra_cli::provider::{
        AgentMessage, CompletionRequest, CompletionResponse, LLMProvider, ToolDefinition,
    };

    #[derive(Default)]
    pub struct NoopProvider;

    #[async_trait]
    impl LLMProvider for NoopProvider {
        async fn complete(&self, _req: CompletionRequest) -> anyhow::Result<CompletionResponse> {
            Err(anyhow!("NoopProvider: should not be called"))
        }

        async fn complete_with_tools(
            &self,
            _system: &str,
            _messages: &[AgentMessage],
            _tools: &[ToolDefinition],
            _max_tokens: u32,
            _cancel_token: Option<&CancellationToken>,
        ) -> anyhow::Result<CompletionResponse> {
            Err(anyhow!("NoopProvider: should not be called"))
        }

        fn context_window(&self) -> u32 {
            200_000
        }

        fn model_name(&self) -> &str {
            "noop"
        }
    }
}

#[tokio::test]
async fn orchestrator_incremental_carries_and_reconciles() {
    use zentra_cli::agent::orchestrator::OrchestratorAgent;
    use zentra_cli::incremental::ChangeSet;
    use zentra_cli::state::{Finding, Severity, StateWriter};

    let dir = tempfile::TempDir::new().unwrap();
    let writer = Arc::new(StateWriter::open(dir.path(), false).unwrap());
    // Seed a "fresh" finding on disk as if a focused scanner wrote it.
    writer
        .write_finding(&Finding {
            scanner: "sast".into(),
            severity: Severity::High,
            title: "Fresh in changed file".into(),
            description: "d".into(),
            location: Some("src/changed.rs:1".into()),
            recommendation: "r".into(),
            corroborated_by: vec![],
            cwe: None,
            secondary_cwe: vec![],
            cvss_vector: None,
            cvss_score: None,
            owasp: None,
            confidence: None,
            screening: None,
            evidence: None,
        })
        .unwrap();

    let prior = vec![Finding {
        scanner: "sast".into(),
        severity: Severity::Medium,
        title: "Old in untouched file".into(),
        description: "d".into(),
        location: Some("src/untouched.rs:9".into()),
        recommendation: "r".into(),
        corroborated_by: vec![],
        cwe: None,
        secondary_cwe: vec![],
        cvss_vector: None,
        cvss_score: None,
        owasp: None,
        confidence: None,
        screening: None,
        evidence: None,
    }];
    let change_set = ChangeSet {
        changed: vec!["src/changed.rs".into()],
        impact: vec!["src/changed.rs".into()],
    };

    // Provider unused: run with an empty scanner list so no LLM call happens;
    // reconciliation still runs because `incremental` is set and Report is absent.
    let provider = Arc::new(test_support::NoopProvider);
    let (tx, _rx) = mpsc::channel(128);
    let registry = Arc::new(zentra_cli::tools::ToolRegistry::new());
    let summary = OrchestratorAgent::new(
        provider,
        registry,
        writer.clone(),
        tx,
        CancellationToken::new(),
    )
    .with_incremental(prior, change_set)
    .run(&[])
    .await
    .unwrap();

    let delta = summary.delta.expect("incremental delta present");
    assert_eq!(delta.carried, 1, "untouched finding carried");
    assert_eq!(delta.new, 1, "changed-file finding is new");
    let merged = zentra_cli::state::parse_findings(&writer.read_findings_raw().unwrap());
    assert_eq!(merged.len(), 2);
}

#[tokio::test]
async fn orchestrator_replays_retained_findings_for_skipped_scanner() {
    use zentra_cli::agent::checkpoint::Checkpoint;
    use zentra_cli::state::{Finding, Severity, StateWriter};

    let dir = tempfile::TempDir::new().unwrap();
    let writer = Arc::new(StateWriter::open(dir.path(), true).unwrap());
    let finding = Finding {
        scanner: "sast".into(),
        severity: Severity::High,
        title: "Retained finding".into(),
        description: "d".into(),
        location: Some("src/main.rs:1".into()),
        recommendation: "r".into(),
        corroborated_by: vec![],
        cwe: None,
        secondary_cwe: vec![],
        cvss_vector: None,
        cvss_score: None,
        owasp: None,
        confidence: None,
        screening: None,
        evidence: None,
    };
    writer.write_finding(&finding).unwrap();

    let mut checkpoint = Checkpoint::default();
    checkpoint.completed.insert("sast".into());
    let provider = Arc::new(test_support::NoopProvider);
    let registry = Arc::new(zentra_cli::tools::ToolRegistry::new());
    let (tx, mut rx) = mpsc::channel(32);

    OrchestratorAgent::new(
        provider,
        registry,
        writer,
        tx,
        CancellationToken::new(),
    )
    .with_resume(Some(checkpoint))
    .run(&[ScannerType::Sast])
    .await
    .unwrap();

    let mut events = Vec::new();
    while let Ok(event) = rx.try_recv() {
        events.push(event);
    }
    assert!(matches!(events.first(), Some(ScanEvent::ScannerStarted(ScannerType::Sast))));
    assert!(events.iter().any(|event| matches!(
        event,
        ScanEvent::FindingAdded(f) if f.title == "Retained finding"
    )));
    assert!(matches!(events.last(), Some(ScanEvent::ScannerCompleted(ScannerType::Sast))));
}

#[tokio::test]
async fn orchestrator_reruns_report_when_a_prior_scanner_reruns_on_resume() {
    use zentra_cli::agent::checkpoint::Checkpoint;

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(400).set_body_string("scan failure"))
        .mount(&server)
        .await;

    let dir = tempfile::TempDir::new().unwrap();
    let writer = Arc::new(StateWriter::open(dir.path(), true).unwrap());
    writer
        .write_finding(&Finding {
            scanner: "report".into(),
            severity: Severity::Info,
            title: "Stale report finding".into(),
            description: "stale".into(),
            location: None,
            recommendation: "refresh".into(),
            corroborated_by: vec![],
            cwe: None,
            secondary_cwe: vec![],
            cvss_vector: None,
            cvss_score: None,
            owasp: None,
            confidence: None,
            screening: None,
            evidence: None,
        })
        .unwrap();

    let mut checkpoint = Checkpoint::default();
    checkpoint.completed.insert("report".into());
    let provider: Arc<dyn zentra_cli::provider::LLMProvider> = Arc::new(
        OpenAICompatProvider::new(server.uri(), "gpt-4o".into(), "key".into()),
    );
    let registry = Arc::new(zentra_cli::tools::ToolRegistry::new());
    let (tx, _rx) = mpsc::channel(32);

    let summary = OrchestratorAgent::new(
        provider,
        registry,
        writer.clone(),
        tx,
        CancellationToken::new(),
    )
    .with_resume(Some(checkpoint))
    .run(&[ScannerType::Sast, ScannerType::Report])
    .await
    .unwrap();

    assert!(summary.failed.contains(&ScannerType::Sast));
    assert!(summary.failed.contains(&ScannerType::Report));
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
    assert!(!writer.read_findings_raw().unwrap().contains("Stale report finding"));

    let persisted = Checkpoint::load(&dir.path().join(".zentra"));
    assert!(!persisted.completed.contains("report"));
}

#[tokio::test]
async fn orchestrator_scopes_sast_but_not_supply_chain_on_incremental_run() {
    use zentra_cli::incremental::ChangeSet;

    let server = MockServer::start().await;
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
    let writer = Arc::new(StateWriter::open(dir.path(), false).unwrap());
    let (tx, _rx) = mpsc::channel(32);

    let change_set = ChangeSet {
        changed: vec!["src/keep.rs".to_string()],
        impact: vec!["src/keep.rs".to_string()],
    };

    OrchestratorAgent::new(provider, registry, writer, tx, CancellationToken::new())
        .with_incremental(vec![], change_set)
        .run(&[ScannerType::Sast, ScannerType::SupplyChain])
        .await
        .unwrap();

    let sast_sys = scanners::system_prompt(ScannerType::Sast);
    let supply_sys = scanners::system_prompt(ScannerType::SupplyChain);

    let requests = server.received_requests().await.unwrap();
    let mut checked_sast = false;
    let mut checked_supply_chain = false;
    for r in &requests {
        let body: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        let messages = body["messages"].as_array().unwrap();
        let system_content = messages[0]["content"].as_str().unwrap_or("");
        let user_content = messages[1]["content"].as_str().unwrap_or("");
        if system_content == sast_sys {
            assert!(
                user_content.contains("Incremental rescan") && user_content.contains("src/keep.rs"),
                "SAST must receive the incremental-scope prompt, got: {user_content}"
            );
            checked_sast = true;
        } else if system_content == supply_sys {
            assert!(
                !user_content.contains("Incremental rescan"),
                "SupplyChain must NOT be scoped, got: {user_content}"
            );
            checked_supply_chain = true;
        }
    }
    assert!(checked_sast, "expected a request with SAST's system prompt");
    assert!(
        checked_supply_chain,
        "expected a request with SupplyChain's system prompt"
    );
}

#[test]
fn scanner_prompts_request_classification() {
    use zentra_cli::scanners;
    use zentra_cli::agent::ScannerType;
    for st in [
        ScannerType::Sast,
        ScannerType::ApiScan,
        ScannerType::SupplyChain,
        ScannerType::IacScan,
        ScannerType::ThreatModel,
    ] {
        let p = scanners::system_prompt(st);
        assert!(p.contains("CWE"), "{st:?} prompt should mention CWE");
        assert!(p.contains("CVSS"), "{st:?} prompt should mention CVSS");
    }
}

// --- Findings file ordering (determinism) ---
//
// The sort key used to be severity alone, and `sort_by_key` is stable. Phase 2
// writes from four parallel scanners, so thread interleaving decided the order
// of equal-severity findings and the same findings produced a different file on
// every run. The key is now (severity, location, title, scanner).

fn ordering_finding(sev: Severity, title: &str, loc: &str, scanner: &str) -> Finding {
    Finding {
        scanner: scanner.to_string(),
        severity: sev,
        title: title.to_string(),
        description: "d".to_string(),
        location: Some(loc.to_string()),
        recommendation: "r".to_string(),
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
fn findings_file_bytes_do_not_depend_on_write_order() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let a = StateWriter::new(dir_a.path()).unwrap();
    let b = StateWriter::new(dir_b.path()).unwrap();

    let f1 = ordering_finding(Severity::High, "Zebra issue", "src/z.rs:1", "sast");
    let f2 = ordering_finding(Severity::High, "Alpha issue", "src/a.rs:1", "api_scan");
    let f3 = ordering_finding(Severity::High, "Middle issue", "src/m.rs:1", "iac_scan");

    for f in [&f1, &f2, &f3] {
        a.write_finding(f).unwrap();
    }
    for f in [&f3, &f1, &f2] {
        b.write_finding(f).unwrap();
    }

    assert_eq!(
        a.read_findings_raw().unwrap(),
        b.read_findings_raw().unwrap(),
        "equal-severity findings must not depend on write order"
    );
}

#[test]
fn equal_severity_findings_sort_by_location_then_title() {
    let dir = TempDir::new().unwrap();
    let w = StateWriter::new(dir.path()).unwrap();

    w.write_finding(&ordering_finding(
        Severity::High,
        "B",
        "src/z.rs:1",
        "sast",
    ))
    .unwrap();
    w.write_finding(&ordering_finding(
        Severity::High,
        "A",
        "src/a.rs:1",
        "sast",
    ))
    .unwrap();

    let raw = w.read_findings_raw().unwrap();
    let a_at = raw.find("src/a.rs:1").unwrap();
    let z_at = raw.find("src/z.rs:1").unwrap();
    assert!(a_at < z_at, "src/a.rs must precede src/z.rs:\n{raw}");
}

#[test]
fn same_location_findings_sort_by_title() {
    let dir = TempDir::new().unwrap();
    let w = StateWriter::new(dir.path()).unwrap();

    w.write_finding(&ordering_finding(
        Severity::High,
        "Zeta problem",
        "src/a.rs:1",
        "sast",
    ))
    .unwrap();
    w.write_finding(&ordering_finding(
        Severity::High,
        "Alpha problem",
        "src/a.rs:1",
        "sast",
    ))
    .unwrap();

    let raw = w.read_findings_raw().unwrap();
    assert!(
        raw.find("Alpha problem").unwrap() < raw.find("Zeta problem").unwrap(),
        "titles must break a location tie:\n{raw}"
    );
}

#[test]
fn severity_still_dominates_the_order() {
    let dir = TempDir::new().unwrap();
    let w = StateWriter::new(dir.path()).unwrap();

    w.write_finding(&ordering_finding(
        Severity::Low,
        "aaa",
        "src/a.rs:1",
        "sast",
    ))
    .unwrap();
    w.write_finding(&ordering_finding(
        Severity::Critical,
        "zzz",
        "src/z.rs:1",
        "sast",
    ))
    .unwrap();

    let raw = w.read_findings_raw().unwrap();
    assert!(
        raw.find("[CRITICAL]").unwrap() < raw.find("[LOW]").unwrap(),
        "critical must sort before low:\n{raw}"
    );
}

/// Drive one async block to completion on this thread.
///
/// The CWD-dependent coverage tests hold `cwd_lock()` while they run, and a
/// `std::sync::MutexGuard` must not be held across an `.await` in an async fn —
/// on a multi-threaded runtime the task can resume on another thread. A
/// current-thread runtime inside a sync test removes the await point entirely.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

// --- Coverage ledger wiring ---
//
// The ledger lives in ToolRegistry so `dispatch` can record without a signature
// change, and so all four parallel Phase 2 scanners share one tally.

#[test]
fn dispatch_records_read_coverage() {
    let _guard = cwd_lock().lock().unwrap_or_else(|e| e.into_inner());
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("a.rs"), "fn a() {}").unwrap();
    let original = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();

    let registry = zentra_cli::tools::ToolRegistry::new();
    let writer = StateWriter::new(dir.path()).unwrap();
    let (tx, _rx) = tokio::sync::mpsc::channel(16);

    block_on(registry.dispatch(
        "read_file",
        &serde_json::json!({"path": "a.rs"}),
        &writer,
        &tx,
        ScannerType::Sast,
    ));

    std::env::set_current_dir(original).unwrap();

    let summary = registry.coverage_snapshot(1);
    assert_eq!(summary.distinct_read, 1);
    assert_eq!(summary.candidate_count, 1);
    assert_eq!(summary.percent(), 100);
    assert_eq!(summary.per_scanner.len(), 1);
    assert_eq!(summary.per_scanner[0].scanner, "sast");
    assert_eq!(summary.per_scanner[0].files_read, 1);
}

#[tokio::test]
async fn dispatch_records_a_rejected_read_as_a_hole_not_coverage() {
    let dir = TempDir::new().unwrap();
    let registry = zentra_cli::tools::ToolRegistry::new();
    let writer = StateWriter::new(dir.path()).unwrap();
    let (tx, _rx) = tokio::sync::mpsc::channel(16);

    registry
        .dispatch(
            "read_file",
            &serde_json::json!({"path": "missing.rs"}),
            &writer,
            &tx,
            ScannerType::Sast,
        )
        .await;

    let summary = registry.coverage_snapshot(1);
    assert_eq!(summary.distinct_read, 0, "a failed read is not coverage");
    assert_eq!(summary.per_scanner[0].failed, 1);
    assert_eq!(summary.percent(), 0);
}

#[test]
fn dispatch_records_listings_and_searches() {
    let _guard = cwd_lock().lock().unwrap_or_else(|e| e.into_inner());
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("a.rs"), "fn a() {}").unwrap();
    let original = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();

    let registry = zentra_cli::tools::ToolRegistry::new();
    let writer = StateWriter::new(dir.path()).unwrap();
    let (tx, _rx) = tokio::sync::mpsc::channel(16);

    block_on(registry.dispatch(
        "list_files",
        &serde_json::json!({"dir": "."}),
        &writer,
        &tx,
        ScannerType::Sast,
    ));
    block_on(registry.dispatch(
        "grep_code",
        &serde_json::json!({"pattern": "fn"}),
        &writer,
        &tx,
        ScannerType::Sast,
    ));

    std::env::set_current_dir(original).unwrap();

    let summary = registry.coverage_snapshot(1);
    assert_eq!(summary.per_scanner[0].listings, 1);
    assert_eq!(summary.per_scanner[0].searches, 1);
    assert_eq!(
        summary.distinct_read, 0,
        "navigation is not reading — this is the monorepo failure mode"
    );
}

#[test]
fn last_outcome_for_is_visible_through_the_registry() {
    let _guard = cwd_lock().lock().unwrap_or_else(|e| e.into_inner());
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("a.rs"), "fn a() {}").unwrap();
    let original = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();

    let registry = zentra_cli::tools::ToolRegistry::new();
    let writer = StateWriter::new(dir.path()).unwrap();
    let (tx, _rx) = tokio::sync::mpsc::channel(16);

    block_on(registry.dispatch(
        "read_file",
        &serde_json::json!({"path": "a.rs"}),
        &writer,
        &tx,
        ScannerType::Sast,
    ));

    std::env::set_current_dir(original).unwrap();

    assert_eq!(
        registry.last_outcome_for(ScannerType::Sast, "a.rs"),
        Some(zentra_cli::tools::fs_tools::ReadOutcome::Read { bytes: 9 })
    );
    assert_eq!(registry.last_outcome_for(ScannerType::ApiScan, "a.rs"), None);
}

#[tokio::test]
async fn never_read_snapshot_names_untouched_candidates() {
    let dir = TempDir::new().unwrap();
    let registry = zentra_cli::tools::ToolRegistry::new();
    let candidates = vec!["src/a.rs".to_string(), "src/b.rs".to_string()];
    let _ = &dir;

    assert_eq!(registry.never_read_snapshot(&candidates), candidates);
}

#[test]
fn state_writer_writes_the_coverage_artifact() {
    let dir = TempDir::new().unwrap();
    let w = StateWriter::new(dir.path()).unwrap();
    w.write_coverage("# Scan Coverage\n").unwrap();
    let body = std::fs::read_to_string(dir.path().join(".zentra").join("coverage.md")).unwrap();
    assert!(body.contains("# Scan Coverage"));
}

// End-to-end: a real orchestrator run against a mock provider must leave a
// coverage artifact on disk. This is the closest check to the operator's
// experience that does not need a live API key.
#[tokio::test]
async fn orchestrator_writes_the_coverage_artifact_end_to_end() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{"message": {"role": "assistant", "content": "done"}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}
        })))
        .mount(&server)
        .await;

    let dir = TempDir::new().unwrap();
    // Two candidate source files the agent never opens: the mock provider makes
    // no tool calls, so this is exactly the "read nothing, report success" case.
    std::fs::write(dir.path().join("a.rs"), "fn a() {}").unwrap();
    std::fs::write(dir.path().join("b.rs"), "fn b() {}").unwrap();

    let provider: Arc<dyn zentra_cli::provider::LLMProvider> = Arc::new(
        OpenAICompatProvider::new(server.uri(), "gpt-4o".to_string(), "key".to_string()),
    );
    let registry = Arc::new(zentra_cli::tools::ToolRegistry::new());
    let writer = Arc::new(zentra_cli::state::StateWriter::new(dir.path()).unwrap());
    let (tx, mut rx) = mpsc::channel(64);

    let summary = OrchestratorAgent::new(provider, registry, writer, tx, CancellationToken::new())
        .run(&[ScannerType::Sast])
        .await
        .unwrap();

    while rx.try_recv().is_ok() {}

    assert_eq!(summary.coverage.candidate_count, 2);
    assert_eq!(summary.coverage.distinct_read, 0);
    assert_eq!(summary.coverage.percent(), 0);

    let body = std::fs::read_to_string(dir.path().join(".zentra").join("coverage.md")).unwrap();
    assert!(body.contains("# Scan Coverage"), "got:\n{body}");
    assert!(body.contains("0 of 2 (0%)"), "got:\n{body}");
    assert!(body.contains("Never opened (2 files)"), "got:\n{body}");
    assert!(body.contains("- a.rs"), "got:\n{body}");
    assert!(body.contains("- b.rs"), "got:\n{body}");
}

// --- Screening (the precision pass) ---

fn screening_finding(title: &str, location: Option<&str>) -> Finding {
    Finding {
        scanner: "sast".to_string(),
        severity: Severity::High,
        title: title.to_string(),
        description: "user input reaches a query".to_string(),
        location: location.map(str::to_string),
        recommendation: "parameterize".to_string(),
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
fn screening_verdict_survives_the_markdown_round_trip() {
    let dir = TempDir::new().unwrap();
    let writer = StateWriter::new(dir.path()).unwrap();

    let mut finding = screening_finding("SQL injection", Some("src/db.rs:42"));
    finding.screening = Some(zentra_cli::state::finding::Screening::Confirmed);
    finding.confidence = Some(87);
    writer.write_finding(&finding).unwrap();

    let raw = writer.read_findings_raw().unwrap();
    assert!(
        raw.contains("**Screening:** confirmed (87% confidence)"),
        "got:\n{raw}"
    );

    let parsed = zentra_cli::state::parse_findings(&raw);
    assert_eq!(parsed.len(), 1);
    assert_eq!(
        parsed[0].screening,
        Some(zentra_cli::state::finding::Screening::Confirmed)
    );
    assert_eq!(parsed[0].confidence, Some(87));
}

#[test]
fn every_screening_verdict_round_trips() {
    use zentra_cli::state::finding::Screening;

    for verdict in [Screening::Confirmed, Screening::Disputed, Screening::Unclear] {
        let dir = TempDir::new().unwrap();
        let writer = StateWriter::new(dir.path()).unwrap();

        let mut finding = screening_finding("Issue", Some("src/a.rs:1"));
        finding.screening = Some(verdict);
        finding.confidence = Some(50);
        writer.write_finding(&finding).unwrap();

        let parsed = zentra_cli::state::parse_findings(&writer.read_findings_raw().unwrap());
        assert_eq!(parsed[0].screening, Some(verdict), "verdict {verdict} lost");
    }
}

#[test]
fn an_unscreened_finding_emits_no_screening_line() {
    let dir = TempDir::new().unwrap();
    let writer = StateWriter::new(dir.path()).unwrap();

    writer
        .write_finding(&screening_finding("Unscreened", Some("src/a.rs:1")))
        .unwrap();

    let raw = writer.read_findings_raw().unwrap();
    assert!(
        !raw.contains("Screening"),
        "an unscreened finding must look as it did before the field existed:\n{raw}"
    );

    let parsed = zentra_cli::state::parse_findings(&raw);
    assert_eq!(parsed[0].screening, None);
    assert_eq!(parsed[0].confidence, None);
}

#[test]
fn a_legacy_findings_file_parses_without_a_screening_line() {
    // Files written before this field existed must still load.
    let legacy = "## [HIGH] Old finding\n**Scanner:** sast\n**Location:** src/a.rs:1\n\
**Description:** d\n**Recommendation:** r\n\n---\n";
    let parsed = zentra_cli::state::parse_findings(legacy);
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].screening, None);
    assert_eq!(parsed[0].confidence, None);
}

#[tokio::test]
async fn screening_pass_annotates_findings_from_the_provider_verdict() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{"message": {"role": "assistant", "tool_calls": [{
                "id": "c1",
                "type": "function",
                "function": {
                    "name": "report_screening",
                    "arguments": "{\"verdicts\":[{\"index\":0,\"verdict\":\"confirmed\",\"confidence\":91,\"reason\":\"reachable from the HTTP handler\"},{\"index\":1,\"verdict\":\"disputed\",\"confidence\":80,\"reason\":\"test fixture only\"}]}"
                }
            }]}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        })))
        .mount(&server)
        .await;

    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("db.rs"), "fn query() {}").unwrap();

    let provider: Arc<dyn zentra_cli::provider::LLMProvider> = Arc::new(
        OpenAICompatProvider::new(server.uri(), "gpt-4o".to_string(), "key".to_string()),
    );
    let findings = vec![
        screening_finding("Real SQLi", Some("db.rs:1")),
        screening_finding("Fixture SQLi", Some("db.rs:1")),
    ];

    let out = zentra_cli::agent::screening::screen(&provider, dir.path(), findings, None).await;

    assert_eq!(out.len(), 2);
    assert_eq!(
        out[0].screening,
        Some(zentra_cli::state::finding::Screening::Confirmed)
    );
    assert_eq!(out[0].confidence, Some(91));
    assert_eq!(
        out[1].screening,
        Some(zentra_cli::state::finding::Screening::Disputed)
    );
    assert_eq!(out[1].confidence, Some(80));
}

#[tokio::test]
async fn screening_pass_returns_findings_unchanged_when_the_provider_fails() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(429).set_body_string("Too Many Requests"))
        .mount(&server)
        .await;

    let dir = TempDir::new().unwrap();
    let provider: Arc<dyn zentra_cli::provider::LLMProvider> = Arc::new(
        OpenAICompatProvider::new(server.uri(), "gpt-4o".to_string(), "key".to_string()),
    );
    let findings = vec![screening_finding("Critical thing", Some("db.rs:1"))];

    let out = zentra_cli::agent::screening::screen(&provider, dir.path(), findings, None).await;

    assert_eq!(out.len(), 1, "a rate limit must never drop a finding");
    assert_eq!(out[0].screening, None, "unscreened, not silently confirmed");
    assert_eq!(out[0].confidence, None);
}

#[tokio::test]
async fn screening_pass_survives_a_response_with_no_tool_call() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{"message": {"role": "assistant", "content": "I cannot decide"}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
        })))
        .mount(&server)
        .await;

    let dir = TempDir::new().unwrap();
    let provider: Arc<dyn zentra_cli::provider::LLMProvider> = Arc::new(
        OpenAICompatProvider::new(server.uri(), "gpt-4o".to_string(), "key".to_string()),
    );
    let findings = vec![screening_finding("Thing", None)];

    let out = zentra_cli::agent::screening::screen(&provider, dir.path(), findings, None).await;

    assert_eq!(out.len(), 1);
    assert_eq!(out[0].screening, None);
}

#[tokio::test]
async fn screening_pass_handles_more_findings_than_one_batch() {
    let server = MockServer::start().await;
    // Every batch gets the same single verdict for local index 0.
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{"message": {"role": "assistant", "tool_calls": [{
                "id": "c1",
                "type": "function",
                "function": {
                    "name": "report_screening",
                    "arguments": "{\"verdicts\":[{\"index\":0,\"verdict\":\"unclear\",\"confidence\":10}]}"
                }
            }]}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
        })))
        .mount(&server)
        .await;

    let dir = TempDir::new().unwrap();
    let provider: Arc<dyn zentra_cli::provider::LLMProvider> = Arc::new(
        OpenAICompatProvider::new(server.uri(), "gpt-4o".to_string(), "key".to_string()),
    );
    // 10 findings = one batch of 8 plus one of 2.
    let findings: Vec<Finding> = (0..10)
        .map(|i| screening_finding(&format!("Finding {i}"), None))
        .collect();

    let out = zentra_cli::agent::screening::screen(&provider, dir.path(), findings, None).await;

    assert_eq!(out.len(), 10, "batching must not lose a finding");
    // Local index 0 of each batch maps to global 0 and 8.
    assert_eq!(
        out[0].screening,
        Some(zentra_cli::state::finding::Screening::Unclear)
    );
    assert_eq!(
        out[8].screening,
        Some(zentra_cli::state::finding::Screening::Unclear),
        "local index 0 of the second batch must map to global index 8"
    );
    assert_eq!(out[1].screening, None);
}

// --- Pack mode (whole-repository compaction) ---
//
// Pack mode replaces the navigation prompt with the whole filtered repository.
// The guarantee it buys is coverage: if a file is in the pack, the model saw it.

fn pack_repo(files: &[(&str, &str)]) -> TempDir {
    let dir = TempDir::new().unwrap();
    std::fs::create_dir_all(dir.path().join(".git")).unwrap();
    for (path, body) in files {
        let full = dir.path().join(path);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, body).unwrap();
    }
    dir
}

#[tokio::test]
async fn pack_mode_sends_the_repository_and_never_lists_files() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{"message": {"role": "assistant", "content": "reviewed"}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}
        })))
        .mount(&server)
        .await;

    let dir = pack_repo(&[
        ("src/handler.rs", "fn handle(input: &str) {}"),
        ("src/db.rs", "fn query(sql: &str) {}"),
        ("tests/it.rs", "fn excluded_from_pack() {}"),
    ]);

    let provider: Arc<dyn zentra_cli::provider::LLMProvider> = Arc::new(
        OpenAICompatProvider::new(server.uri(), "gpt-4o".to_string(), "key".to_string()),
    );
    let registry = Arc::new(zentra_cli::tools::ToolRegistry::new());
    let writer = Arc::new(zentra_cli::state::StateWriter::new(dir.path()).unwrap());
    let (tx, mut rx) = mpsc::channel(64);

    let built = zentra_cli::agent::pack::build_pack(dir.path());
    let rendered = Arc::new(built.render());

    OrchestratorAgent::new(provider, registry, writer, tx, CancellationToken::new())
        .with_pack(Some(Arc::clone(&rendered)))
        .run(&[ScannerType::Sast])
        .await
        .unwrap();

    while rx.try_recv().is_ok() {}

    // The provider saw the pack as the opening user message.
    let requests = server.received_requests().await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    let sent = body["messages"].as_array().unwrap();
    let first_user = sent
        .iter()
        .find(|m| m["role"] == "user")
        .unwrap()
        .get("content")
        .unwrap()
        .as_str()
        .unwrap();

    assert!(
        first_user.contains("=== FILE: src/handler.rs ==="),
        "the pack must be the opening message, got:\n{first_user}"
    );
    assert!(first_user.contains("fn query(sql: &str)"), "got:\n{first_user}");
    assert!(
        !first_user.contains("excluded_from_pack"),
        "tests are filtered out of the pack, got:\n{first_user}"
    );
    assert!(
        first_user.contains("Do not call list_files"),
        "got:\n{first_user}"
    );
    assert!(
        !first_user.contains("Start by listing the project files"),
        "pack mode must replace the navigation opener, got:\n{first_user}"
    );
}

#[tokio::test]
async fn without_pack_the_opener_is_unchanged() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{"message": {"role": "assistant", "content": "done"}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}
        })))
        .mount(&server)
        .await;

    let dir = pack_repo(&[("src/a.rs", "fn a() {}")]);
    let provider: Arc<dyn zentra_cli::provider::LLMProvider> = Arc::new(
        OpenAICompatProvider::new(server.uri(), "gpt-4o".to_string(), "key".to_string()),
    );
    let registry = Arc::new(zentra_cli::tools::ToolRegistry::new());
    let writer = Arc::new(zentra_cli::state::StateWriter::new(dir.path()).unwrap());
    let (tx, mut rx) = mpsc::channel(64);

    OrchestratorAgent::new(provider, registry, writer, tx, CancellationToken::new())
        .run(&[ScannerType::Sast])
        .await
        .unwrap();

    while rx.try_recv().is_ok() {}

    let requests = server.received_requests().await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    let first_user = body["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["role"] == "user")
        .unwrap()
        .get("content")
        .unwrap()
        .as_str()
        .unwrap();

    assert_eq!(first_user, "Begin your security scan. Start by listing the project files.");
}

#[tokio::test]
async fn every_parallel_scanner_receives_the_pack() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{"message": {"role": "assistant", "content": "done"}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}
        })))
        .mount(&server)
        .await;

    let dir = pack_repo(&[("src/a.rs", "fn marker_in_pack() {}")]);
    let provider: Arc<dyn zentra_cli::provider::LLMProvider> = Arc::new(
        OpenAICompatProvider::new(server.uri(), "gpt-4o".to_string(), "key".to_string()),
    );
    let registry = Arc::new(zentra_cli::tools::ToolRegistry::new());
    let writer = Arc::new(zentra_cli::state::StateWriter::new(dir.path()).unwrap());
    let (tx, mut rx) = mpsc::channel(128);

    let rendered = Arc::new(zentra_cli::agent::pack::build_pack(dir.path()).render());

    // Sast, SupplyChain, ApiScan and IacScan all run through the parallel spawn
    // path, which builds ScannerAgent directly rather than via run_llm_scanner.
    OrchestratorAgent::new(provider, registry, writer, tx, CancellationToken::new())
        .with_pack(Some(rendered))
        .run(&[
            ScannerType::Sast,
            ScannerType::SupplyChain,
            ScannerType::ApiScan,
            ScannerType::IacScan,
        ])
        .await
        .unwrap();

    while rx.try_recv().is_ok() {}

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 4, "one opening call per parallel scanner");
    for request in &requests {
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        let has_pack = body["messages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| {
                m["content"]
                    .as_str()
                    .map(|c| c.contains("marker_in_pack"))
                    .unwrap_or(false)
            });
        assert!(has_pack, "every parallel scanner must open with the pack");
    }
}
