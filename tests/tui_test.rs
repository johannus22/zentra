use zentra_cli::agent::{ScanEvent, ScannerType};
use zentra_cli::state::{Finding, Severity};
use zentra_cli::tui::{ScanStatus, UiScanner, UiState};

#[test]
fn ui_state_scanner_starts_as_queued() {
    let state = UiState::new(
        vec![ScannerType::Sast, ScannerType::Report],
        "gpt-4o · openai".to_string(),
        200_000,
    );
    assert_eq!(state.scanners[0].status, ScanStatus::Queued);
    assert_eq!(state.scanners[1].status, ScanStatus::Waiting);
}

#[test]
fn ui_state_apply_scanner_started() {
    let mut state = UiState::new(
        vec![ScannerType::Sast],
        "gpt-4o".to_string(),
        200_000,
    );
    state.apply_event(ScanEvent::ScannerStarted(ScannerType::Sast));
    assert_eq!(state.scanners[0].status, ScanStatus::Running);
}

#[test]
fn ui_state_apply_scanner_completed() {
    let mut state = UiState::new(
        vec![ScannerType::Sast],
        "gpt-4o".to_string(),
        200_000,
    );
    state.apply_event(ScanEvent::ScannerStarted(ScannerType::Sast));
    state.apply_event(ScanEvent::ScannerCompleted(ScannerType::Sast));
    assert_eq!(state.scanners[0].status, ScanStatus::Done);
}

#[test]
fn ui_state_apply_finding_added() {
    let mut state = UiState::new(vec![ScannerType::Sast], "m".to_string(), 200_000);
    let f = Finding {
        scanner: "sast".to_string(),
        severity: Severity::High,
        title: "Test finding".to_string(),
        description: "desc".to_string(),
        location: Some("src/main.rs:1".to_string()),
        recommendation: "fix it".to_string(),
    };
    state.apply_event(ScanEvent::FindingAdded(f));
    assert_eq!(state.findings.len(), 1);
    assert_eq!(state.scanners[0].high_count, 1);
}

#[test]
fn ui_state_apply_tool_call_updates_activity() {
    let mut state = UiState::new(vec![ScannerType::Sast], "m".to_string(), 200_000);
    state.apply_event(ScanEvent::ToolCall {
        scanner: ScannerType::Sast,
        tool: "read_file".to_string(),
        arg: "src/main.rs".to_string(),
    });
    assert!(state.activity.contains("read_file"));
    assert!(state.activity.contains("src/main.rs"));
}

#[test]
fn ui_state_apply_tokens_used_accumulates() {
    let mut state = UiState::new(vec![ScannerType::Sast], "m".to_string(), 200_000);
    state.apply_event(ScanEvent::TokensUsed { input: 1000, output: 200 });
    state.apply_event(ScanEvent::TokensUsed { input: 500, output: 100 });
    assert_eq!(state.total_tokens, 1800);
}

#[test]
fn ui_state_all_done_when_all_scanners_completed_or_failed() {
    let mut state = UiState::new(
        vec![ScannerType::Sast, ScannerType::Report],
        "m".to_string(),
        200_000,
    );
    assert!(!state.all_done());
    state.apply_event(ScanEvent::ScannerStarted(ScannerType::Sast));
    state.apply_event(ScanEvent::ScannerCompleted(ScannerType::Sast));
    state.apply_event(ScanEvent::ScannerStarted(ScannerType::Report));
    state.apply_event(ScanEvent::ScannerCompleted(ScannerType::Report));
    assert!(state.all_done());
}

#[test]
fn ui_state_select_next_wraps() {
    let mut state = UiState::new(vec![ScannerType::Sast], "m".to_string(), 200_000);
    let f = Finding {
        scanner: "sast".to_string(),
        severity: Severity::High,
        title: "A".to_string(),
        description: "d".to_string(),
        location: None,
        recommendation: "r".to_string(),
    };
    state.apply_event(ScanEvent::FindingAdded(f.clone()));
    state.apply_event(ScanEvent::FindingAdded(f));
    state.select_next();
    assert_eq!(state.selected_idx, 1);
    state.select_next();
    assert_eq!(state.selected_idx, 1); // clamped at end
}
