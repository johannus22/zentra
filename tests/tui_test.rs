use ratatui::layout::{Constraint, Layout, Rect};
use tempfile::TempDir;
use zentra_cli::agent::{ScanEvent, ScannerType};
use zentra_cli::config::{AuthMethod, GlobalConfig};
use zentra_cli::pentest::{PentestEvent, PentestEvidence, PentestFinding, PentestSeverity};
use zentra_cli::state::{Finding, Severity};
use zentra_cli::tui::menu::{
    centered_middle_column, main_menu_actions, provider_selector_footer_hint,
    scanner_selector_footer_hint, MenuScreen, MenuState, OAuthModalPhase,
};
use zentra_cli::tui::pentest_setup::build_pentest_config_from_setup_input;
use zentra_cli::tui::pentest_ui::PentestUiState;
use zentra_cli::tui::{ScanStatus, UiState};

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
    let mut state = UiState::new(
        vec![ScannerType::Sast],
        "m".to_string(),
        200_000,
        vec![],
        String::new(),
        String::new(),
    );
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
    let mut state = UiState::new(
        vec![ScannerType::Sast],
        "m".to_string(),
        200_000,
        vec![],
        String::new(),
        String::new(),
    );
    state.apply_event(ScanEvent::ToolCall {
        scanner: ScannerType::Sast,
        tool: "read_file".to_string(),
        arg: "src/main.rs".to_string(),
    });
    assert!(state.activity.contains("read_file"));
    assert!(state.activity.contains("src/main.rs"));
}

#[test]
fn pentest_setup_requires_authorization_confirmation() {
    let config = build_pentest_config_from_setup_input("https://app.example.test", "no").unwrap();
    assert!(config.is_none());
}

#[test]
fn pentest_setup_accepts_yes_authorization_confirmation() {
    let config = build_pentest_config_from_setup_input(" https://app.example.test ", " YES ")
        .unwrap()
        .expect("valid confirmation should build config");

    assert_eq!(config.target_url, "https://app.example.test");
    assert!(config.authorized);
    assert_eq!(config.scope.allowed_hosts, vec!["app.example.test"]);
    assert_eq!(config.scope.allowed_paths, vec!["/"]);
    assert!(config.scope.excluded_paths.is_empty());
    assert_eq!(config.auth.label(), "none");
}

#[test]
fn pentest_setup_empty_url_returns_none() {
    let config = build_pentest_config_from_setup_input("   ", "yes").unwrap();
    assert!(config.is_none());
}

#[test]
fn pentest_ui_state_agent_lifecycle_events_are_no_ops() {
    let mut state = PentestUiState::new(
        "https://app.example.test".to_string(),
        "gpt-4o".to_string(),
        "none".to_string(),
    );
    // These events are no-ops in the stage-based pipeline UI
    state.apply_event(PentestEvent::AgentPlanned {
        role: "Crawler".to_string(),
        objective: "Map app".to_string(),
    });
    state.apply_event(PentestEvent::AgentStarted {
        id: 1,
        role: "Crawler".to_string(),
    });
    state.apply_event(PentestEvent::AgentCompleted { id: 1 });

    // No side effects — activity log stays empty, no stage changes
    assert_eq!(state.activity.len(), 0);
    assert_eq!(state.current_stage, 0);
}

#[test]
fn pentest_ui_state_tracks_findings_and_activity() {
    let mut state = PentestUiState::new(
        "https://app.example.test".to_string(),
        "gpt-4o".to_string(),
        "header".to_string(),
    );
    state.apply_event(PentestEvent::BrowserAction {
        id: 1,
        action: "navigate".to_string(),
        target: "https://app.example.test/app".to_string(),
    });
    state.apply_event(PentestEvent::FindingAdded(PentestFinding {
        severity: PentestSeverity::High,
        title: "IDOR".to_string(),
        impact: "Data exposure".to_string(),
        reproduction_steps: vec!["Open invoice".to_string()],
        evidence_paths: vec!["evidence/invoice.json".to_string()],
        remediation: "Check ownership".to_string(),
    }));

    assert_eq!(state.findings.len(), 1);
    assert_eq!(state.activity.len(), 1);
    assert!(state.activity[0].contains("navigate"));
}

#[test]
fn pentest_ui_state_redacts_sensitive_activity_values() {
    let mut state = PentestUiState::new(
        "https://app.example.test".to_string(),
        "gpt-4o".to_string(),
        "header".to_string(),
    );

    state.apply_event(PentestEvent::BrowserAction {
        id: 1,
        action: "navigate".to_string(),
        target: "https://app.example.test/app?token=secret-token&api_key=secret-key&safe=ok"
            .to_string(),
    });
    state.apply_event(PentestEvent::CliCall {
        id: 1,
        command: "open https://app.example.test --header Authorization: Bearer secret-bearer --cookie session=secret-session --header=Cookie: secret-cookie".to_string(),
    });
    state.apply_event(PentestEvent::EvidenceCaptured(PentestEvidence {
        kind: "response".to_string(),
        path: "evidence/login.json?signature=secret-signature&key=secret-key".to_string(),
        description: "Login response".to_string(),
    }));
    state.apply_event(PentestEvent::Error {
        id: None,
        message: "failed with Cookie: secret-cookie and Authorization: Bearer secret-bearer"
            .to_string(),
    });

    let activity = state.activity.join("\n");
    assert!(activity.contains("token=<redacted>"));
    assert!(activity.contains("api_key=<redacted>"));
    assert!(activity.contains("signature=<redacted>"));
    assert!(activity.contains("key=<redacted>"));
    assert!(activity.contains("Authorization: Bearer <redacted>"));
    assert!(activity.contains("Cookie: <redacted>"));
    assert!(activity.contains("--header <redacted>"));
    assert!(activity.contains("--cookie <redacted>"));
    assert!(activity.contains("--header=<redacted>"));
    assert!(!activity.contains("secret-token"));
    assert!(!activity.contains("secret-key"));
    assert!(!activity.contains("secret-bearer"));
    assert!(!activity.contains("secret-session"));
    assert!(!activity.contains("secret-cookie"));
    assert!(!activity.contains("secret-signature"));
}

#[test]
fn pentest_ui_state_handles_error_and_completed_events() {
    let mut state = PentestUiState::new(
        "https://app.example.test".to_string(),
        "gpt-4o".to_string(),
        "header".to_string(),
    );
    state.apply_event(PentestEvent::AgentStarted {
        id: 7,
        role: "Exploiter".to_string(),
    });
    state.apply_event(PentestEvent::Error {
        id: Some(7),
        message: "request failed with Authorization: Bearer secret-token".to_string(),
    });
    state.apply_event(PentestEvent::Completed);

    assert_eq!(state.completed, true);
    assert!(state.error_stages.contains(&7));
    assert!(state.activity[0].contains("Authorization: Bearer <redacted>"));
    assert!(!state.activity[0].contains("secret-token"));
}

#[test]
fn pentest_ui_state_caps_activity_log() {
    let mut state = PentestUiState::new(
        "https://app.example.test".to_string(),
        "gpt-4o".to_string(),
        "none".to_string(),
    );

    for idx in 0..105 {
        state.apply_event(PentestEvent::AgentActivity {
            id: 1,
            message: format!("activity {idx}"),
        });
    }

    assert_eq!(state.activity.len(), 100);
    assert_eq!(state.activity[0], "activity 5");
    assert_eq!(state.activity[99], "activity 104");
}

#[test]
fn pentest_focus_defaults_to_findings() {
    use zentra_cli::tui::pentest_ui::PentestFocus;
    let state = PentestUiState::new(
        "https://t.test".to_string(),
        "model".to_string(),
        "none".to_string(),
    );
    assert_eq!(state.focus, PentestFocus::Findings);
    assert_eq!(state.activity_scroll, 0);
}

#[test]
fn pentest_tab_toggles_focus() {
    use zentra_cli::tui::pentest_ui::PentestFocus;
    let mut state = PentestUiState::new(
        "https://t.test".to_string(),
        "model".to_string(),
        "none".to_string(),
    );
    assert_eq!(state.focus, PentestFocus::Findings);
    state.handle_tab();
    assert_eq!(state.focus, PentestFocus::Activity);
    state.handle_tab();
    assert_eq!(state.focus, PentestFocus::Findings);
}

#[test]
fn pentest_up_down_routes_to_findings_when_findings_focused() {
    use zentra_cli::tui::pentest_ui::PentestFocus;
    let mut state = PentestUiState::new(
        "https://t.test".to_string(),
        "model".to_string(),
        "none".to_string(),
    );
    // Add two findings via apply_event
    let finding = PentestFinding {
        severity: PentestSeverity::High,
        title: "A".to_string(),
        impact: "".to_string(),
        reproduction_steps: vec![],
        evidence_paths: vec![],
        remediation: "".to_string(),
    };
    state.apply_event(PentestEvent::FindingAdded(finding.clone()));
    state.apply_event(PentestEvent::FindingAdded(PentestFinding {
        title: "B".to_string(),
        ..finding
    }));
    assert_eq!(state.focus, PentestFocus::Findings);
    state.handle_down();
    assert_eq!(state.selected_idx, 1);
    state.handle_up();
    assert_eq!(state.selected_idx, 0);
    // activity_scroll unchanged
    assert_eq!(state.activity_scroll, 0);
}

#[test]
fn pentest_activity_scroll_increments_on_up_when_activity_focused() {
    use zentra_cli::tui::pentest_ui::PentestFocus;
    let mut state = PentestUiState::new(
        "https://t.test".to_string(),
        "model".to_string(),
        "none".to_string(),
    );
    // Add 5 activity entries
    for i in 0..5 {
        state.apply_event(PentestEvent::AgentActivity {
            id: 1,
            message: format!("event {i}"),
        });
    }
    state.handle_tab(); // switch to Activity
    assert_eq!(state.focus, PentestFocus::Activity);
    state.handle_up();
    assert_eq!(state.activity_scroll, 1);
    state.handle_up();
    assert_eq!(state.activity_scroll, 2);
    // selected_idx unchanged
    assert_eq!(state.selected_idx, 0);
}

#[test]
fn pentest_activity_scroll_clamps_to_history_length() {
    let mut state = PentestUiState::new(
        "https://t.test".to_string(),
        "model".to_string(),
        "none".to_string(),
    );
    for i in 0..3 {
        state.apply_event(PentestEvent::AgentActivity {
            id: 1,
            message: format!("event {i}"),
        });
    }
    state.handle_tab(); // Activity focus
                        // Press Up 100 times — must not exceed activity.len() - 1 (keeps at least 1 item visible)
    for _ in 0..100 {
        state.handle_up();
    }
    assert_eq!(state.activity_scroll, 2);
}

#[test]
fn pentest_activity_scroll_resets_to_zero_floor_on_down() {
    let mut state = PentestUiState::new(
        "https://t.test".to_string(),
        "model".to_string(),
        "none".to_string(),
    );
    for i in 0..3 {
        state.apply_event(PentestEvent::AgentActivity {
            id: 1,
            message: format!("event {i}"),
        });
    }
    state.handle_tab();
    state.handle_up();
    state.handle_up();
    assert_eq!(state.activity_scroll, 2);
    state.handle_down();
    assert_eq!(state.activity_scroll, 1);
    state.handle_down();
    assert_eq!(state.activity_scroll, 0);
    state.handle_down(); // floor at 0
    assert_eq!(state.activity_scroll, 0);
}

#[test]
fn pentest_ui_state_evidence_and_findings_tracked_at_state_level() {
    let mut state = PentestUiState::new(
        "https://app.example.test".to_string(),
        "gpt-4o".to_string(),
        "none".to_string(),
    );
    state.apply_event(PentestEvent::EvidenceCaptured(PentestEvidence {
        kind: "screenshot".to_string(),
        path: "evidence/page.png".to_string(),
        description: "Page".to_string(),
    }));
    state.apply_event(PentestEvent::FindingAdded(PentestFinding {
        severity: PentestSeverity::Low,
        title: "Low".to_string(),
        impact: "Minor".to_string(),
        reproduction_steps: vec!["Open page".to_string()],
        evidence_paths: vec!["evidence/page.png".to_string()],
        remediation: "Fix".to_string(),
    }));

    assert_eq!(state.findings.len(), 1);
    assert!(state
        .activity
        .iter()
        .any(|a| a.contains("evidence/page.png")));

    // Findings are sorted by severity (highest first)
    let mut multi = PentestUiState::new(
        "https://app.example.test".to_string(),
        "gpt-4o".to_string(),
        "none".to_string(),
    );
    multi.selected_idx = 10;
    multi.apply_event(PentestEvent::FindingAdded(PentestFinding {
        severity: PentestSeverity::Low,
        title: "Low".to_string(),
        impact: "Minor".to_string(),
        reproduction_steps: vec!["Open page".to_string()],
        evidence_paths: vec!["evidence/page.png".to_string()],
        remediation: "Fix".to_string(),
    }));
    multi.apply_event(PentestEvent::FindingAdded(PentestFinding {
        severity: PentestSeverity::Critical,
        title: "Critical".to_string(),
        impact: "Major".to_string(),
        reproduction_steps: vec!["Exploit".to_string()],
        evidence_paths: vec!["evidence/exploit.json".to_string()],
        remediation: "Fix now".to_string(),
    }));

    assert_eq!(multi.findings.len(), 2);
    assert_eq!(multi.findings[0].severity, PentestSeverity::Critical);
    assert!(multi.selected_idx < multi.findings.len());
}

#[test]
fn ui_state_apply_tokens_used_accumulates() {
    let mut state = UiState::new(
        vec![ScannerType::Sast],
        "m".to_string(),
        200_000,
        vec![],
        String::new(),
        String::new(),
    );
    state.apply_event(ScanEvent::TokensUsed {
        input: 1000,
        output: 200,
    });
    state.apply_event(ScanEvent::TokensUsed {
        input: 500,
        output: 100,
    });
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
    let mut state = UiState::new(
        vec![ScannerType::Sast],
        "m".to_string(),
        200_000,
        vec![],
        String::new(),
        String::new(),
    );
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
    let mut state = UiState::new(
        vec![ScannerType::Sast],
        "m".to_string(),
        200_000,
        vec![],
        String::new(),
        String::new(),
    );
    state.apply_event(ScanEvent::TokensUsed {
        input: 10_000,
        output: 5_000,
    });
    // peak_input = 10_000 / 200_000 = 5%
    assert_eq!(state.token_pct(), 5);
}

#[test]
fn ui_state_token_pct_caps_at_100() {
    let mut state = UiState::new(
        vec![ScannerType::Sast],
        "m".to_string(),
        1_000,
        vec![],
        String::new(),
        String::new(),
    );
    state.apply_event(ScanEvent::TokensUsed {
        input: 2_000,
        output: 0,
    });
    assert_eq!(state.token_pct(), 100);
}

#[test]
fn menu_state_starts_at_first_item() {
    let state = MenuState::new(
        true,
        true,
        vec![],
        String::new(),
        String::new(),
        String::new(),
        String::new(),
    );
    assert_eq!(state.selected_idx, 0);
    assert_eq!(state.screen, MenuScreen::Main);
}

#[test]
fn menu_state_navigate_wraps() {
    let mut state = MenuState::new(
        true,
        true,
        vec![],
        String::new(),
        String::new(),
        String::new(),
        String::new(),
    );
    // 7 items: RunFull(0), RunPentest(1), SelectScanners(2), ViewResults(3), ChangeProvider(4), AddProvider(5), Exit(6)
    state.next();
    assert_eq!(state.selected_idx, 1);
    state.next();
    state.next();
    state.next();
    state.next();
    assert_eq!(state.selected_idx, 5);
    state.next();
    assert_eq!(state.selected_idx, 6);
    state.prev();
    assert_eq!(state.selected_idx, 5);
}

#[test]
fn menu_state_disabled_items_when_unconfigured() {
    let state = MenuState::new(
        false,
        false,
        vec![],
        String::new(),
        String::new(),
        String::new(),
        String::new(),
    ); // no provider, no project
    assert!(!state.is_item_enabled(0)); // RunFull
    assert!(state.is_item_enabled(1)); // RunPentest
    assert!(!state.is_item_enabled(2)); // SelectScanners
    assert!(state.is_item_enabled(3)); // ViewResults
    assert!(!state.is_item_enabled(4)); // ChangeProvider
    assert!(state.is_item_enabled(5)); // AddProvider
    assert!(state.is_item_enabled(6)); // Exit
}

#[test]
fn menu_state_scanner_selector_toggle() {
    let mut state = MenuState::new(
        true,
        true,
        vec![],
        String::new(),
        String::new(),
        String::new(),
        String::new(),
    );
    state.screen = MenuScreen::ScannerSelector;
    assert!(state.scanner_selected[0]);
    state.toggle_scanner(); // toggle ThreatModel off
    assert!(!state.scanner_selected[0]);
    state.toggle_scanner(); // toggle back on
    assert!(state.scanner_selected[0]);
}

#[test]
fn menu_state_scanner_selector_selected_types() {
    let mut state = MenuState::new(
        true,
        true,
        vec![],
        String::new(),
        String::new(),
        String::new(),
        String::new(),
    );
    state.screen = MenuScreen::ScannerSelector;
    state.scanner_idx = 1; // SAST
    state.toggle_scanner(); // disable SAST
    let types = state.selected_scanner_types();
    assert!(!types.contains(&ScannerType::Sast));
    assert!(types.contains(&ScannerType::ThreatModel));
    assert!(types.contains(&ScannerType::Report)); // always included
}

use zentra_cli::tui::results::parse_findings;
use zentra_cli::tui::PopupState;

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
    assert!(matches!(
        findings[0].severity,
        zentra_cli::state::Severity::Critical
    ));
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
    let state = UiState::new(
        vec![ScannerType::Sast],
        "m".to_string(),
        200_000,
        vec![],
        String::new(),
        String::new(),
    );
    assert!(!state.popup_open);
}

#[test]
fn ui_state_toggle_popup() {
    let mut state = UiState::new(
        vec![ScannerType::Sast],
        "m".to_string(),
        200_000,
        vec![],
        String::new(),
        String::new(),
    );
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
    assert_eq!(
        findings.len(),
        2,
        "expected 2 findings, got {}",
        findings.len()
    );
    assert_eq!(findings[0].title, "SQL Injection");
    assert_eq!(findings[1].title, "Hardcoded API key");
    assert_eq!(
        findings[1].location.as_deref(),
        Some("src/config/auth.rs:42")
    );
}

#[test]
fn menu_state_new_stores_active_profile() {
    let state = MenuState::new(
        true,
        true,
        vec![("anthropic".to_string(), "claude-opus-4-7".to_string())],
        "claude-opus-4-7".to_string(),
        "anthropic".to_string(),
        String::new(),
        String::new(),
    );
    assert_eq!(state.active_profile, "anthropic");
    assert_eq!(state.active_model, "claude-opus-4-7");
    assert_eq!(state.profiles.len(), 1);
}

#[test]
fn menu_state_navigate_new_max_is_6() {
    let mut state = MenuState::new(
        true,
        true,
        vec![],
        String::new(),
        String::new(),
        String::new(),
        String::new(),
    );
    for _ in 0..6 {
        state.next();
    }
    assert_eq!(state.selected_idx, 6);
    state.next(); // clamp
    assert_eq!(state.selected_idx, 6);
}

#[test]
fn menu_state_main_menu_has_run_pentest_action() {
    let actions = main_menu_actions();
    assert_eq!(actions[0], "Run Full Scan");
    assert_eq!(actions[1], "Run Pentest");
    assert!(actions.contains(&"Select Scanners"));
}

#[test]
fn menu_state_main_menu_has_seven_actions() {
    assert_eq!(main_menu_actions().len(), 7);
    assert_eq!(
        main_menu_actions(),
        &[
            "Run Full Scan",
            "Run Pentest",
            "Select Scanners",
            "View Last Results",
            "Change Provider",
            "Add Provider",
            "Exit",
        ]
    );
}

#[test]
fn scanner_selector_hint_is_centered_like_the_list() {
    let area = Rect::new(0, 0, 120, 40);
    let chunks = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(7),
        Constraint::Min(10),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .split(area);

    let list_area = centered_middle_column(chunks[2]);
    let hint_area = centered_middle_column(chunks[3]);

    assert_eq!(hint_area.x, list_area.x);
    assert_eq!(hint_area.width, list_area.width);
    assert_eq!(
        scanner_selector_footer_hint(),
        " Space toggle · Enter run · Esc back"
    );
}

#[test]
fn menu_state_change_provider_requires_provider() {
    let state = MenuState::new(
        false,
        false,
        vec![],
        String::new(),
        String::new(),
        String::new(),
        String::new(),
    );
    assert!(!state.is_item_enabled(4)); // Change Provider = index 4
}

use zentra_cli::tui::menu::{clip_with_ellipsis, ProviderFormState};
use zentra_cli::tui::scan_ui::{
    clip_failed_error_preview, failed_error_preview_width, popup_items, scan_body_chunks,
};

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
fn scan_ui_scanner_panel_width_is_wider_than_before() {
    let [scanner_area, findings_area] = scan_body_chunks(Rect::new(0, 0, 80, 12));

    assert!(scanner_area.width > 26);
    assert!(findings_area.width >= 20);
}

#[test]
fn scan_ui_failed_error_preview_clips_long_messages() {
    let preview_width = failed_error_preview_width(34);
    let preview = clip_failed_error_preview("abcdefghijklmnopqrstuvwxyz0123456789", preview_width);

    assert!(preview_width > 20);
    assert_eq!(preview.chars().count(), preview_width);
    assert_eq!(preview, "abcdefghijklmnopqrstuvwxyz0…");
}

#[test]
fn scan_ui_failed_error_preview_normalizes_multiline_and_control_chars() {
    let preview = clip_failed_error_preview("panic\r\n\u{1b}[31mboom\u{1b}[0m\tpath", 64);

    assert_eq!(preview, "panic boom path");
    assert!(!preview.contains(['\n', '\r', '\u{1b}']));
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

#[test]
fn provider_form_default_uses_first_known_provider() {
    let form = ProviderFormState::default();
    assert_eq!(form.provider_idx, 0);
    assert!(!form.model.is_empty());
    assert_eq!(form.auth_method, AuthMethod::ApiKey);
    assert_eq!(form.focused_field, 0);
    assert!(form.error.is_none());
}

#[test]
fn provider_form_append_char_to_api_key() {
    let mut form = ProviderFormState {
        focused_field: 3,
        ..Default::default()
    }; // api_key field
    form.append_char('s');
    form.append_char('k');
    assert_eq!(form.api_key, "sk");
}

#[test]
fn provider_form_backspace_removes_last_char() {
    let mut form = ProviderFormState {
        focused_field: 4,
        profile_name: "test".to_string(),
        ..Default::default()
    }; // profile_name field
    form.backspace();
    assert_eq!(form.profile_name, "tes");
}

#[test]
fn provider_form_cycle_provider_updates_defaults() {
    let mut form = ProviderFormState::default();
    form.cycle_provider(1); // next provider
    assert_eq!(form.provider_idx, 1);
}

#[test]
fn provider_form_masked_key_shows_prefix_only() {
    let form = ProviderFormState {
        api_key: "sk-ant-abc123xyz".to_string(),
        ..Default::default()
    };
    let masked = form.masked_key();
    assert!(masked.starts_with("sk-ant"));
    assert!(masked.contains('*'));
}

#[test]
fn provider_form_validate_fails_on_empty_key() {
    let form = ProviderFormState::default();
    // api_key is empty by default
    assert!(form.validate().is_err());
}

#[test]
fn provider_form_validate_rejects_forced_openai_oauth_state_without_key() {
    let mut form = ProviderFormState::default();
    form.cycle_provider(1);
    form.auth_method = AuthMethod::OAuth;
    form.profile_name = "openai_legacy".to_string();

    let err = form.validate().unwrap_err().to_string();
    assert!(err.contains("API key cannot be empty"));
}

#[test]
fn provider_form_cycle_auth_method_noops_for_openai() {
    let mut form = ProviderFormState::default();
    form.cycle_provider(1);

    assert_eq!(form.auth_method, AuthMethod::ApiKey);
    form.cycle_auth_method(1);
    assert_eq!(form.auth_method, AuthMethod::ApiKey);
    form.cycle_auth_method(-1);
    assert_eq!(form.auth_method, AuthMethod::ApiKey);
}

#[test]
fn provider_form_validate_still_requires_api_key_for_non_openai_providers() {
    let form = ProviderFormState {
        auth_method: AuthMethod::OAuth,
        profile_name: "anthropic_oauth".to_string(),
        ..Default::default()
    };

    let err = form.validate().unwrap_err().to_string();
    assert!(err.contains("API key cannot be empty"));
}

#[test]
fn provider_form_validate_rejects_invalid_base_url() {
    let form = ProviderFormState {
        api_key: "sk-test-key-12345".to_string(),
        profile_name: "anthropic_validated".to_string(),
        base_url: "not-a-url".to_string(),
        ..Default::default()
    };

    let err = form.validate().unwrap_err().to_string();
    assert!(err.contains("relative URL without a base") || err.contains("base URL"));
}

#[test]
fn provider_form_validate_allows_localhost_http_base_url() {
    let form = ProviderFormState {
        api_key: "sk-test-key-12345".to_string(),
        profile_name: "local_ollama".to_string(),
        base_url: "http://localhost:11434/v1".to_string(),
        ..Default::default()
    };

    assert!(form.validate().is_ok());
}

#[test]
fn oauth_modal_state_tracks_progress_and_launch_error() {
    let mut state = MenuState::new(
        true,
        true,
        vec![],
        "gpt-4.1".to_string(),
        "openai".to_string(),
        String::new(),
        String::new(),
    );
    state.screen = MenuScreen::ProviderForm;

    state.open_oauth_modal("https://example.test/oauth/start".to_string());
    let modal = state.oauth_modal.as_ref().unwrap();
    assert_eq!(modal.phase, OAuthModalPhase::LaunchingBrowser);
    assert_eq!(modal.auth_url, "https://example.test/oauth/start");
    assert!(modal.error.is_none());

    state.set_oauth_modal_error(Some("Failed to launch browser".to_string()));
    state.set_oauth_modal_phase(OAuthModalPhase::WaitingForCallback);
    let modal = state.oauth_modal.as_ref().unwrap();
    assert_eq!(modal.phase, OAuthModalPhase::WaitingForCallback);
    assert_eq!(modal.error.as_deref(), Some("Failed to launch browser"));

    state.set_oauth_modal_phase(OAuthModalPhase::ExchangingCode);
    assert_eq!(
        state.oauth_modal.as_ref().unwrap().phase,
        OAuthModalPhase::ExchangingCode
    );

    state.set_oauth_modal_phase(OAuthModalPhase::Success);
    assert_eq!(
        state.oauth_modal.as_ref().unwrap().phase,
        OAuthModalPhase::Success
    );
}

#[test]
fn provider_form_save_persists_openai_as_api_key_auth_even_if_legacy_oauth_state_is_forced() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");
    let stored_keys = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

    let mut form = ProviderFormState::default();
    form.cycle_provider(1);
    form.auth_method = AuthMethod::OAuth;
    form.profile_name = "openai_api_key".to_string();
    form.api_key = "sk-test-key-12345".to_string();

    let saved_name = form
        .save_with_oauth_to_path_using(
            &config_path,
            || unreachable!(),
            |_, _| Ok(()),
            |_| Ok(()),
            {
                let stored_keys = stored_keys.clone();
                move |profile_name, api_key| {
                    stored_keys
                        .lock()
                        .unwrap()
                        .push((profile_name.to_string(), api_key.to_string()));
                    Ok(())
                }
            },
            |_| Ok(()),
        )
        .unwrap();

    assert_eq!(saved_name, "openai_api_key");

    let cfg = GlobalConfig::load_from(&config_path).unwrap();
    let profile = cfg.profiles.get("openai_api_key").unwrap();
    assert_eq!(profile.auth_method, AuthMethod::ApiKey);
    assert_eq!(cfg.default_profile.as_deref(), Some("openai_api_key"));
    assert_eq!(
        stored_keys.lock().unwrap().as_slice(),
        [(
            "openai_api_key".to_string(),
            "sk-test-key-12345".to_string()
        )]
    );
}

#[test]
fn provider_form_validate_rejects_unsafe_profile_name() {
    let form = ProviderFormState {
        api_key: "sk-test-key-12345".to_string(),
        profile_name: "../evil".to_string(),
        ..Default::default()
    };
    assert!(form.validate().is_err());
    let err = form.validate().unwrap_err().to_string();
    assert!(err.contains("letters") || err.contains("alphanumeric") || err.contains("only"));
}

#[test]
fn pentest_auth_form_all_blank_produces_default_auth() {
    use zentra_cli::pentest::auth::PentestAuth;
    let auth = PentestAuth::default();
    assert!(auth.login_url.is_none());
    assert!(auth.password.is_none());
    assert_eq!(auth.label(), "none");
}

#[test]
fn pentest_auth_form_bearer_only_label() {
    use zentra_cli::pentest::auth::PentestAuth;
    let auth = PentestAuth {
        bearer_token: Some("tok".into()),
        ..Default::default()
    };
    assert_eq!(auth.label(), "bearer-token");
}

#[test]
fn ui_state_error_event_captures_message() {
    let mut state = UiState::new(
        vec![ScannerType::Sast],
        "m".to_string(),
        200_000,
        vec![],
        String::new(),
        String::new(),
    );
    state.apply_event(ScanEvent::ScannerStarted(ScannerType::Sast));
    state.apply_event(ScanEvent::Error {
        scanner: ScannerType::Sast,
        message: "rate limit exceeded".to_string(),
    });
    assert_eq!(state.scanners[0].status, ScanStatus::Failed);
    assert_eq!(
        state.scanners[0].error.as_deref(),
        Some("rate limit exceeded")
    );
}

#[test]
fn clip_with_ellipsis_leaves_short_string_unchanged() {
    assert_eq!(clip_with_ellipsis("short", 10), "short");
}

#[test]
fn clip_with_ellipsis_truncates_long_string_with_ellipsis() {
    let s = "https://api.openai.com/v1";
    // 25 chars, max 20 → take 19 + "…" = 20
    let result = clip_with_ellipsis(s, 20);
    assert_eq!(result, "https://api.openai.…");
    assert!(result.ends_with('…'));
}

#[test]
fn clip_with_ellipsis_handles_very_long_url() {
    let s = "https://very-long-custom-endpoint.example.com/v1/chat/completions";
    let result = clip_with_ellipsis(s, 10);
    assert_eq!(result.chars().count(), 10); // Unicode char count
    assert_eq!(result, "https://v…");
    assert!(result.ends_with('…'));
}

#[test]
fn provider_form_handles_long_url() {
    let form = ProviderFormState {
        base_url: "https://very-long-custom-endpoint.example.com/v1/chat/completions".to_string(),
        ..Default::default()
    };
    assert!(form.base_url.len() > 40);
}

#[test]
fn provider_selector_arms_delete_for_non_active_profile() {
    let mut state = MenuState::new(
        true,
        true,
        vec![
            ("anthropic".to_string(), "claude-opus-4-1".to_string()),
            ("openai".to_string(), "gpt-4.1".to_string()),
        ],
        "claude-opus-4-1".to_string(),
        "anthropic".to_string(),
        String::new(),
        String::new(),
    );
    state.screen = MenuScreen::ProviderSelector;
    state.provider_idx = 1;

    assert_eq!(
        provider_selector_footer_hint(&state),
        " ↑↓ navigate · Enter select · d delete · Esc back"
    );

    let deleted = state.handle_provider_delete_key().unwrap();

    assert!(!deleted);
    assert_eq!(state.pending_delete_profile.as_deref(), Some("openai"));
    assert!(state.provider_error.is_none());
    assert_eq!(
        provider_selector_footer_hint(&state),
        " d again confirm delete · ↑↓ move cancel · Esc back"
    );
}

#[test]
fn provider_selector_blocks_delete_for_active_profile() {
    let mut state = MenuState::new(
        true,
        true,
        vec![
            ("anthropic".to_string(), "claude-opus-4-1".to_string()),
            ("openai".to_string(), "gpt-4.1".to_string()),
        ],
        "claude-opus-4-1".to_string(),
        "anthropic".to_string(),
        String::new(),
        String::new(),
    );
    state.screen = MenuScreen::ProviderSelector;
    state.provider_idx = 0;

    let deleted = state.handle_provider_delete_key().unwrap();

    assert!(!deleted);
    assert_eq!(
        state.provider_error.as_deref(),
        Some("Cannot delete active provider")
    );
    assert!(state.pending_delete_profile.is_none());
    assert_eq!(state.profiles.len(), 2);
    assert_eq!(
        provider_selector_footer_hint(&state),
        " ↑↓ navigate · Enter select · d delete · Esc back"
    );
}

#[test]
fn provider_selector_blocks_delete_for_default_non_active_profile() {
    let mut state = MenuState::new(
        true,
        true,
        vec![
            ("anthropic".to_string(), "claude-opus-4-1".to_string()),
            ("openai".to_string(), "gpt-4.1".to_string()),
        ],
        "claude-opus-4-1".to_string(),
        "anthropic".to_string(),
        String::new(),
        String::new(),
    );
    state.screen = MenuScreen::ProviderSelector;
    state.default_profile = "openai".to_string();
    state.provider_idx = 1;

    let deleted = state.handle_provider_delete_key().unwrap();

    assert!(!deleted);
    assert_eq!(
        state.provider_error.as_deref(),
        Some("Cannot delete active provider")
    );
    assert!(state.pending_delete_profile.is_none());
    assert_eq!(state.profiles.len(), 2);
}

#[test]
fn provider_selector_navigation_clears_pending_delete() {
    let mut state = MenuState::new(
        true,
        true,
        vec![
            ("anthropic".to_string(), "claude-opus-4-1".to_string()),
            ("openai".to_string(), "gpt-4.1".to_string()),
        ],
        "anthropic-model".to_string(),
        "anthropic".to_string(),
        String::new(),
        String::new(),
    );
    state.screen = MenuScreen::ProviderSelector;
    state.provider_idx = 1;
    state.handle_provider_delete_key().unwrap();
    state.provider_error = Some("temporary".to_string());

    state.provider_selector_move_up();
    assert!(state.pending_delete_profile.is_none());
    assert!(state.provider_error.is_none());

    state.provider_idx = 1;
    state.handle_provider_delete_key().unwrap();
    state.provider_selector_move_down();
    assert!(state.pending_delete_profile.is_none());

    state.provider_idx = 1;
    state.handle_provider_delete_key().unwrap();
    state.provider_selector_escape();
    assert!(state.pending_delete_profile.is_none());
    assert_eq!(state.screen, MenuScreen::Main);
    assert_eq!(state.selected_idx, 4);
}
