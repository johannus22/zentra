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
        vec![],
        String::new(),
        String::new(),
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
        vec![],
        String::new(),
        String::new(),
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
        vec![],
        String::new(),
        String::new(),
    );
    state.apply_event(ScanEvent::ScannerStarted(ScannerType::Sast));
    state.apply_event(ScanEvent::ScannerCompleted(ScannerType::Sast));
    assert_eq!(state.scanners[0].status, ScanStatus::Done);
}

#[test]
fn ui_state_apply_finding_added() {
    let mut state = UiState::new(vec![ScannerType::Sast], "m".to_string(), 200_000, vec![], String::new(), String::new());
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
    let mut state = UiState::new(vec![ScannerType::Sast], "m".to_string(), 200_000, vec![], String::new(), String::new());
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
    let mut state = UiState::new(vec![ScannerType::Sast], "m".to_string(), 200_000, vec![], String::new(), String::new());
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
        vec![],
        String::new(),
        String::new(),
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
    let mut state = UiState::new(vec![ScannerType::Sast], "m".to_string(), 200_000, vec![], String::new(), String::new());
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
    let mut state = UiState::new(vec![ScannerType::Sast], "m".to_string(), 200_000, vec![], String::new(), String::new());
    state.apply_event(ScanEvent::TokensUsed { input: 10_000, output: 5_000 });
    // peak_input = 10_000 / 200_000 = 5%
    assert_eq!(state.token_pct(), 5);
}

#[test]
fn ui_state_token_pct_caps_at_100() {
    let mut state = UiState::new(vec![ScannerType::Sast], "m".to_string(), 1_000, vec![], String::new(), String::new());
    state.apply_event(ScanEvent::TokensUsed { input: 2_000, output: 0 });
    assert_eq!(state.token_pct(), 100);
}

#[test]
fn menu_state_starts_at_first_item() {
    let state = MenuState::new(true, true, vec![], String::new(), String::new());
    assert_eq!(state.selected_idx, 0);
    assert_eq!(state.screen, MenuScreen::Main);
}

#[test]
fn menu_state_navigate_wraps() {
    let mut state = MenuState::new(true, true, vec![], String::new(), String::new());
    // 6 items: RunFull(0), SelectScanners(1), ViewResults(2), ChangeProvider(3), AddProvider(4), Exit(5)
    state.next();
    assert_eq!(state.selected_idx, 1);
    state.next(); state.next(); state.next(); state.next();
    assert_eq!(state.selected_idx, 5);
    state.next(); // clamp
    assert_eq!(state.selected_idx, 5);
    state.prev();
    assert_eq!(state.selected_idx, 4);
}

#[test]
fn menu_state_disabled_items_when_unconfigured() {
    let state = MenuState::new(false, false, vec![], String::new(), String::new()); // no provider, no project
    assert!(!state.is_item_enabled(0)); // RunFull
    assert!(!state.is_item_enabled(1)); // SelectScanners
    assert!(state.is_item_enabled(2));  // ViewResults
    assert!(!state.is_item_enabled(3)); // ChangeProvider
    assert!(state.is_item_enabled(4));  // AddProvider
    assert!(state.is_item_enabled(5));  // Exit
}

#[test]
fn menu_state_scanner_selector_toggle() {
    let mut state = MenuState::new(true, true, vec![], String::new(), String::new());
    state.screen = MenuScreen::ScannerSelector;
    assert!(state.scanner_selected[0]);
    state.toggle_scanner(); // toggle ThreatModel off
    assert!(!state.scanner_selected[0]);
    state.toggle_scanner(); // toggle back on
    assert!(state.scanner_selected[0]);
}

#[test]
fn menu_state_scanner_selector_selected_types() {
    let mut state = MenuState::new(true, true, vec![], String::new(), String::new());
    state.screen = MenuScreen::ScannerSelector;
    state.scanner_idx = 1; // SAST
    state.toggle_scanner(); // disable SAST
    let types = state.selected_scanner_types();
    assert!(!types.contains(&ScannerType::Sast));
    assert!(types.contains(&ScannerType::ThreatModel));
    assert!(types.contains(&ScannerType::Report)); // always included
}

use zentra_cli::tui::{PopupState, ScanOutcome};
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

#[test]
fn popup_state_starts_at_zero() {
    let p = PopupState::new();
    assert_eq!(p.selected, 0);
}

#[test]
fn popup_state_next_clamps_at_max() {
    let mut p = PopupState::new();
    // popup_items(scan_done=false) → 4 items: 0=Change Provider and Restart Scan, 1=Add Provider, 2=Abort Scan, 3=Exit App
    // popup_items(scan_done=true)  → 3 items: 0=Change Provider and Restart Scan, 1=Add Provider, 2=Exit App
    p.next(3);
    assert_eq!(p.selected, 1);
    p.next(3);
    assert_eq!(p.selected, 2);
    p.next(3); // should clamp
    assert_eq!(p.selected, 2);
}

#[test]
fn popup_state_prev_clamps_at_zero() {
    let mut p = PopupState::new();
    p.prev();
    assert_eq!(p.selected, 0);
}

#[test]
fn ui_state_popup_starts_closed() {
    let state = UiState::new(vec![ScannerType::Sast], "m".to_string(), 200_000, vec![], String::new(), String::new());
    assert!(!state.popup_open);
}

#[test]
fn ui_state_toggle_popup() {
    let mut state = UiState::new(vec![ScannerType::Sast], "m".to_string(), 200_000, vec![], String::new(), String::new());
    state.toggle_popup();
    assert!(state.popup_open);
    state.toggle_popup();
    assert!(!state.popup_open);
}

// ── Results Parser ─────────────────────────────────────────────────────────

#[test]
fn ui_state_scan_end_is_none_initially() {
    let state = UiState::new(
        vec![ScannerType::Sast],
        "m".to_string(),
        200_000,
        vec![],
        String::new(),
        String::new(),
    );
    assert!(state.scan_end.is_none());
}

#[test]
fn ui_state_mark_complete_sets_scan_end() {
    let mut state = UiState::new(
        vec![ScannerType::Sast],
        "m".to_string(),
        200_000,
        vec![],
        String::new(),
        String::new(),
    );
    assert!(!state.scan_done);
    state.mark_complete();
    assert!(state.scan_done);
    assert!(state.scan_end.is_some());
}

#[test]
fn ui_state_elapsed_duration_freezes_after_complete() {
    let mut state = UiState::new(
        vec![ScannerType::Sast],
        "m".to_string(),
        200_000,
        vec![],
        String::new(),
        String::new(),
    );
    state.mark_complete();
    let d1 = state.elapsed_duration();
    std::thread::sleep(std::time::Duration::from_millis(10));
    let d2 = state.elapsed_duration();
    // Timer is frozen: both calls return the same value even after sleeping
    assert_eq!(d1, d2);
}

#[test]
fn parse_findings_returns_all_findings() {
    use zentra_cli::tui::results::parse_findings;
    // Matches the exact on-disk format written by StateWriter::write_finding:
    // writeln! appends one extra \n after the \n\n---\n in the format string.
    let raw = "\
## [HIGH] SQL Injection\n\
**Scanner:** Sast\n\
**Description:** Unsanitised input in login handler\n\
**Recommendation:** Use parameterised queries\n\
\n\
---\n\
\n\
## [MEDIUM] Hardcoded API key\n\
**Scanner:** Sast\n\
**Location:** src/config/auth.rs:42\n\
**Description:** API key embedded in source\n\
**Recommendation:** Use environment variables\n\
\n\
---\n\
\n";
    let findings = parse_findings(raw);
    assert_eq!(findings.len(), 2, "expected 2 findings, got {}", findings.len());
    assert_eq!(findings[0].title, "SQL Injection");
    assert_eq!(findings[1].title, "Hardcoded API key");
    assert_eq!(findings[1].location.as_deref(), Some("src/config/auth.rs:42"));
}

#[test]
fn menu_state_new_stores_active_profile() {
    let state = MenuState::new(
        true,
        true,
        vec![("anthropic".to_string(), "claude-opus-4-7".to_string())],
        "claude-opus-4-7".to_string(),
        "anthropic".to_string(),
    );
    assert_eq!(state.active_profile, "anthropic");
    assert_eq!(state.active_model, "claude-opus-4-7");
    assert_eq!(state.profiles.len(), 1);
}

#[test]
fn menu_state_navigate_new_max_is_5() {
    let mut state = MenuState::new(true, true, vec![], String::new(), String::new());
    // 6 items: 0-5
    for _ in 0..5 { state.next(); }
    assert_eq!(state.selected_idx, 5);
    state.next(); // clamp
    assert_eq!(state.selected_idx, 5);
}

#[test]
fn menu_state_change_provider_requires_provider() {
    let state = MenuState::new(false, false, vec![], String::new(), String::new());
    assert!(!state.is_item_enabled(3)); // Change Provider = index 3
}

use zentra_cli::tui::scan_ui::popup_items;

#[test]
fn popup_items_includes_abort_when_not_done() {
    let items = popup_items(false);
    assert!(items.contains(&"Abort Scan"));
}

#[test]
fn popup_items_excludes_abort_when_scan_done() {
    let items = popup_items(true);
    assert!(!items.contains(&"Abort Scan"));
}

#[test]
fn ui_state_abort_scan_marks_running_as_failed() {
    let mut state = UiState::new(
        vec![ScannerType::Sast, ScannerType::ThreatModel],
        "m".to_string(),
        200_000,
        vec![],
        String::new(),
        String::new(),
    );
    state.apply_event(ScanEvent::ScannerStarted(ScannerType::Sast));
    // ThreatModel stays Queued
    state.abort_scan();
    assert_eq!(state.scanners[0].status, ScanStatus::Failed); // was Running
    assert_eq!(state.scanners[1].status, ScanStatus::Queued); // untouched
    assert!(state.scan_aborted);
    assert!(state.scan_done);
    assert!(state.scan_end.is_some());
}
