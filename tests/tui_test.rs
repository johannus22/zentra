use zentra_cli::agent::{ScanEvent, ScannerType};
use zentra_cli::state::{Finding, Severity};
use zentra_cli::tui::{ScanStatus, UiScanner, UiState};
use zentra_cli::tui::menu::{MenuAction, MenuState, MenuScreen};

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

#[test]
fn ui_state_token_pct_is_correct() {
    let mut state = UiState::new(vec![ScannerType::Sast], "m".to_string(), 200_000);
    state.apply_event(ScanEvent::TokensUsed { input: 10_000, output: 5_000 });
    // 15_000 / 200_000 = 7.5% → 7
    assert_eq!(state.token_pct(), 7);
}

#[test]
fn ui_state_token_pct_caps_at_100() {
    let mut state = UiState::new(vec![ScannerType::Sast], "m".to_string(), 1_000);
    state.apply_event(ScanEvent::TokensUsed { input: 2_000, output: 0 });
    assert_eq!(state.token_pct(), 100);
}

#[test]
fn menu_state_starts_at_first_item() {
    let state = MenuState::new(true, true);
    assert_eq!(state.selected_idx, 0);
    assert_eq!(state.screen, MenuScreen::Main);
}

#[test]
fn menu_state_navigate_wraps() {
    let mut state = MenuState::new(true, true);
    // 5 items: RunFull(0), SelectScanners(1), ViewResults(2), Config(3), Exit(4)
    state.next();
    assert_eq!(state.selected_idx, 1);
    state.next(); state.next(); state.next();
    assert_eq!(state.selected_idx, 4);
    state.next(); // should clamp at last
    assert_eq!(state.selected_idx, 4);
    state.prev();
    assert_eq!(state.selected_idx, 3);
}

#[test]
fn menu_state_disabled_items_when_unconfigured() {
    let state = MenuState::new(false, false); // no provider, no project
    assert!(!state.is_item_enabled(0)); // RunFull
    assert!(!state.is_item_enabled(1)); // SelectScanners
    assert!(state.is_item_enabled(2));  // ViewResults
    assert!(state.is_item_enabled(3));  // Config
    assert!(state.is_item_enabled(4));  // Exit
}

#[test]
fn menu_state_scanner_selector_toggle() {
    let mut state = MenuState::new(true, true);
    state.screen = MenuScreen::ScannerSelector;
    assert!(state.scanner_selected[0]);
    state.toggle_scanner(); // toggle ThreatModel off
    assert!(!state.scanner_selected[0]);
    state.toggle_scanner(); // toggle back on
    assert!(state.scanner_selected[0]);
}

#[test]
fn menu_state_scanner_selector_selected_types() {
    let mut state = MenuState::new(true, true);
    state.screen = MenuScreen::ScannerSelector;
    state.scanner_idx = 1; // SAST
    state.toggle_scanner(); // disable SAST
    let types = state.selected_scanner_types();
    assert!(!types.contains(&ScannerType::Sast));
    assert!(types.contains(&ScannerType::ThreatModel));
    assert!(types.contains(&ScannerType::Report)); // always included
}

use zentra_cli::tui::results::parse_findings;

#[test]
fn parse_findings_extracts_critical_finding() {
    let raw = "## [CRITICAL] Hardcoded JWT secret\n\
               **Scanner:** sast\n\
               **Location:** src/config.rs:18\n\
               **Description:** Static secret in config.\n\
               **Recommendation:** Use env var.\n\
               \n\
               ---\n";
    let findings = parse_findings(raw);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].title, "Hardcoded JWT secret");
    assert!(matches!(findings[0].severity, zentra_cli::state::Severity::Critical));
    assert_eq!(findings[0].scanner, "sast");
    assert_eq!(findings[0].location.as_deref(), Some("src/config.rs:18"));
}

#[test]
fn parse_findings_handles_missing_location() {
    let raw = "## [HIGH] Missing rate limit\n\
               **Scanner:** api_scan\n\
               **Description:** No rate limit on /login.\n\
               **Recommendation:** Add rate limiting.\n\
               \n\
               ---\n";
    let findings = parse_findings(raw);
    assert_eq!(findings.len(), 1);
    assert!(findings[0].location.is_none());
}

#[test]
fn parse_findings_parses_multiple_findings() {
    let raw = "## [HIGH] Finding A\n\
               **Scanner:** sast\n\
               **Description:** desc a.\n\
               **Recommendation:** fix a.\n\
               \n\
               ---\n\
               ## [LOW] Finding B\n\
               **Scanner:** threat_model\n\
               **Description:** desc b.\n\
               **Recommendation:** fix b.\n\
               \n\
               ---\n";
    let findings = parse_findings(raw);
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].title, "Finding A");
    assert_eq!(findings[1].title, "Finding B");
}

#[test]
fn parse_findings_returns_empty_on_empty_input() {
    let findings = parse_findings("");
    assert!(findings.is_empty());
}
