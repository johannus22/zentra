use ratatui::layout::{Constraint, Layout, Rect};
use tempfile::TempDir;
use zentra_cli::agent::{ScanEvent, ScannerType};
use zentra_cli::config::{AuthMethod, GlobalConfig};
use zentra_cli::pentest::{PentestEvent, PentestEvidence, PentestFinding, PentestSeverity};
use zentra_cli::state::{Finding, Severity};
use zentra_cli::tui::menu::{
    centered_middle_column, main_menu_actions, provider_selector_footer_hint,
    scanner_selector_footer_hint, DetailMode, MenuScreen, MenuState, OAuthModalPhase,
    SettingsCategory, SettingsFocus, SettingsFormState,
};
use zentra_cli::tui::pentest_setup::build_pentest_config_from_setup_input;
use zentra_cli::tui::pentest_ui::PentestUiState;
use zentra_cli::tools::fs_tools::ReadOutcome;
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
        String::new(),
    );
    let f = Finding {
        scanner: "sast".to_string(),
        severity: Severity::High,
        title: "Test finding".to_string(),
        description: "desc".to_string(),
        location: Some("src/main.rs:1".to_string()),
        recommendation: "fix it".to_string(),
        corroborated_by: vec![],
        cwe: None,
        secondary_cwe: vec![],
        cvss_vector: None,
        cvss_score: None,
        owasp: None,
        confidence: None,
        screening: None,
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
        None,
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
        None,
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
        None,
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
        None,
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
        None,
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
        None,
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
        None,
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
        None,
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
        None,
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
        None,
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
        None,
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
        None,
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
        None,
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
        String::new(),
    );
    let f = Finding {
        scanner: "sast".to_string(),
        severity: Severity::High,
        title: "A".to_string(),
        description: "d".to_string(),
        location: None,
        recommendation: "r".to_string(),
        corroborated_by: vec![],
        cwe: None,
        secondary_cwe: vec![],
        cvss_vector: None,
        cvss_score: None,
        owasp: None,
        confidence: None,
        screening: None,
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
    // 7 items: RunFull(0), Clone(1), RunPentest(2), SelectScanners(3),
    // ViewResults(4), Settings(5), Exit(6)
    state.next();
    assert_eq!(state.selected_idx, 1);
    state.next(); // 2
    state.next(); // 3
    state.next(); // 4
    state.next(); // 5
    assert_eq!(state.selected_idx, 5);
    state.next(); // 6
    assert_eq!(state.selected_idx, 6);
    state.next(); // clamp at max
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
    assert!(!state.is_item_enabled(0)); // Run Full Scan
    assert!(!state.is_item_enabled(1)); // Clone Repo & Scan
    assert!(state.is_item_enabled(2)); // Run Pentest
    assert!(!state.is_item_enabled(3)); // Select Scanners
    assert!(state.is_item_enabled(4)); // View Last Results
    assert!(state.is_item_enabled(5)); // Settings
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
fn menu_state_navigate_new_max_is_9() {
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
fn menu_state_main_menu_has_clone_action() {
    let actions = main_menu_actions();
    assert_eq!(actions[0], "Run Full Scan (this directory)");
    assert_eq!(actions[1], "Clone Repo & Scan");
    assert_eq!(actions[2], "Run Pentest");
}

#[test]
fn settings_form_save_persists_and_clears_output_dir() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("config.toml");

    // Saving a (whitespace-padded) directory trims and persists it.
    let mut s = SettingsFormState {
        output_dir: "  /mnt/c/Users/me/Documents/Zentra  ".to_string(),
        ..Default::default()
    };
    s.save_to(&path).unwrap();
    assert!(s.saved);
    let loaded = GlobalConfig::load_from(&path).unwrap();
    assert_eq!(
        loaded.output_dir.as_deref(),
        Some("/mnt/c/Users/me/Documents/Zentra")
    );

    // Saving a blank directory clears the override (back to default).
    let mut blank = SettingsFormState::default();
    blank.save_to(&path).unwrap();
    let reloaded = GlobalConfig::load_from(&path).unwrap();
    assert_eq!(reloaded.output_dir, None);
}

#[test]
fn menu_state_main_menu_has_seven_actions() {
    assert_eq!(main_menu_actions().len(), 7);
    assert_eq!(
        main_menu_actions(),
        &[
            "Run Full Scan (this directory)",
            "Clone Repo & Scan",
            "Run Pentest",
            "Select Scanners",
            "View Last Results",
            "Settings",
            "Exit",
        ]
    );
}

fn new_menu_state() -> MenuState {
    MenuState::new(
        true,
        true,
        vec![],
        String::new(),
        String::new(),
        String::new(),
        String::new(),
    )
}

#[test]
fn theme_picker_cycles_and_previews() {
    let mut state = new_menu_state();
    state.theme = state.theme_options[0].clone();
    state.open_theme_picker();
    let first = state.theme.id.clone();
    state.theme_picker_next();
    assert_ne!(
        state.theme.id, first,
        "next() should live-apply a different theme"
    );
}

#[test]
fn theme_picker_esc_restores_previous() {
    let mut state = new_menu_state();
    state.theme = state.theme_options[0].clone();
    let original = state.theme.id.clone();
    state.open_theme_picker();
    state.theme_picker_next();
    state.cancel_theme();
    assert_eq!(state.theme.id, original);
}

#[test]
fn theme_picker_enter_persists() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let mut state = new_menu_state();
    state.theme = state.theme_options[0].clone();
    state.open_theme_picker();
    state.theme_picker_next();
    let chosen = state.theme.id.clone();
    state.confirm_theme_to(&path).unwrap();
    let saved = zentra_cli::config::GlobalConfig::load_from(&path).unwrap();
    assert_eq!(saved.theme.as_deref(), Some(chosen.as_str()));
}

#[test]
fn settings_hub_opens_on_providers_nav() {
    let mut state = new_menu_state();
    state.open_settings();
    assert!(state.settings_open);
    assert_eq!(state.settings_category(), SettingsCategory::Providers);
    assert_eq!(state.settings_focus, SettingsFocus::Nav);
}

#[test]
fn settings_hub_nav_cycles_categories_and_resets_detail() {
    let mut state = new_menu_state();
    state.open_settings();
    state.settings_nav_down(); // Theme
    assert_eq!(state.settings_category(), SettingsCategory::Theme);
    assert_eq!(state.settings_detail, DetailMode::ThemeList);
    state.settings_nav_down(); // Output dir
    state.settings_nav_down(); // CWE reference
    assert_eq!(state.settings_category(), SettingsCategory::CweReference);
    state.settings_nav_down(); // About
    assert_eq!(state.settings_category(), SettingsCategory::About);
    state.settings_nav_down(); // clamp
    assert_eq!(state.settings_category(), SettingsCategory::About);
    state.settings_nav_up(); // CWE reference
    assert_eq!(state.settings_category(), SettingsCategory::CweReference);
}

#[test]
fn settings_hub_enter_and_leave_detail_focus() {
    let mut state = new_menu_state();
    state.open_settings();
    state.settings_enter_detail();
    assert_eq!(state.settings_focus, SettingsFocus::Detail);
    assert_eq!(state.settings_detail, DetailMode::ProviderList);
    state.settings_leave_detail();
    assert_eq!(state.settings_focus, SettingsFocus::Nav);
}

#[test]
fn settings_hub_theme_detail_restores_on_leave() {
    let mut state = new_menu_state();
    state.theme = state.theme_options[0].clone();
    let original = state.theme.id.clone();
    state.open_settings();
    state.settings_nav_down(); // Theme
    state.settings_enter_detail();
    state.theme_picker_next(); // live preview a different theme
    assert_ne!(state.theme.id, original);
    state.settings_leave_detail();
    assert_eq!(state.theme.id, original);
}

#[test]
fn settings_open_provider_form_switches_detail() {
    let mut state = new_menu_state();
    state.open_settings();
    state.settings_enter_detail(); // Providers detail
    state.open_provider_form();
    assert_eq!(state.settings_detail, DetailMode::ProviderForm);
}

#[test]
fn settings_cancel_provider_form_returns_to_list() {
    let mut state = new_menu_state();
    state.open_settings();
    state.settings_enter_detail();
    state.open_provider_form();
    state.form.model = "xyz".to_string();
    state.cancel_provider_form();
    assert_eq!(state.settings_detail, DetailMode::ProviderList);
    assert_eq!(state.form.model, ProviderFormState::default().model);
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
fn settings_provider_change_persists_via_hub() {
    // Provider switching now happens inside the Settings hub, not a menu item.
    // apply_provider_change_to refreshes state in place AND keeps the hub open
    // (it no longer tears the TUI back down to the main menu).
    use std::collections::HashMap;
    use zentra_cli::config::ProviderProfile;

    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");

    let mut profiles = HashMap::new();
    profiles.insert(
        "anthropic".to_string(),
        ProviderProfile {
            kind: "anthropic".to_string(),
            base_url: "https://api.anthropic.com".to_string(),
            model: "claude-opus-4-1".to_string(),
            keyless: false,
            auth_method: AuthMethod::ApiKey,
            context_window: None,
            reasoning_effort: None,
            temperature: None,
        },
    );
    profiles.insert(
        "openai".to_string(),
        ProviderProfile {
            kind: "openai_compat".to_string(),
            base_url: "https://api.openai.com/v1".to_string(),
            model: "gpt-4o".to_string(),
            keyless: false,
            auth_method: AuthMethod::ApiKey,
            context_window: None,
            reasoning_effort: None,
            temperature: None,
        },
    );
    GlobalConfig {
        profiles,
        default_profile: Some("anthropic".to_string()),
        output_dir: None,
        theme: None,
        cwe_url_template: None,
    }
    .save_to(&config_path)
    .unwrap();

    let mut state = MenuState::new(
        true,
        true,
        vec![
            ("anthropic".to_string(), "claude-opus-4-1".to_string()),
            ("openai".to_string(), "gpt-4o".to_string()),
        ],
        "claude-opus-4-1".to_string(),
        "anthropic".to_string(),
        String::new(),
        String::new(),
    );
    state.open_settings();
    state.settings_enter_detail();
    state.provider_idx = 1;

    state.apply_provider_change_to("openai", &config_path).unwrap();

    // The hub stays open and the active provider is refreshed in place.
    assert!(state.settings_open);
    assert_eq!(state.active_profile, "openai");
    // The change is surfaced, not silent.
    assert!(matches!(state.settings_status, Some((true, _))));
}

#[test]
fn settings_status_set_on_theme_save_and_cleared_on_nav() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let mut state = new_menu_state();
    state.theme = state.theme_options[0].clone();
    state.open_settings();
    assert!(state.settings_status.is_none());

    state.settings_nav_down(); // Theme
    state.settings_enter_detail();
    state.theme_picker_next();
    state.confirm_theme_to(&path).unwrap();

    let (ok, msg) = state
        .settings_status
        .clone()
        .expect("a status message should be set after saving the theme");
    assert!(ok);
    assert!(msg.contains("Theme saved"), "unexpected message: {msg}");

    // Navigating to another category clears the stale message.
    state.settings_nav_up();
    assert!(state.settings_status.is_none());
}

use zentra_cli::tui::menu::{clip_with_ellipsis, ProviderEditContext, ProviderFormState};
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
fn provider_form_append_char_to_reasoning_field() {
    let mut form = ProviderFormState {
        focused_field: 3,
        ..Default::default()
    }; // reasoning field
    form.append_char('l');
    form.append_char('o');
    form.append_char('w');
    assert_eq!(form.reasoning_effort, "low");
}

#[test]
fn provider_form_append_char_to_api_key() {
    let mut form = ProviderFormState {
        focused_field: 4,
        ..Default::default()
    }; // api_key field
    form.append_char('s');
    form.append_char('k');
    assert_eq!(form.api_key, "sk");
}

#[test]
fn provider_form_backspace_removes_last_char() {
    let mut form = ProviderFormState {
        focused_field: 5,
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
fn provider_form_custom_has_empty_name_and_https_base_url() {
    use zentra_cli::wizard::KNOWN_PROVIDER_NAMES;
    let custom_idx = KNOWN_PROVIDER_NAMES
        .iter()
        .position(|p| *p == "custom")
        .expect("'custom' provider must exist");

    let mut form = ProviderFormState::default();
    // Cycle forward until we land on the custom provider.
    while form.provider_idx != custom_idx {
        form.cycle_provider(1);
    }

    assert_eq!(
        form.profile_name, "",
        "custom provider should start with an empty name"
    );
    assert_eq!(
        form.base_url, "https://",
        "custom provider base URL should be pre-filled with the https scheme"
    );
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
    state.open_settings();
    state.settings_detail = DetailMode::ProviderForm;

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
fn provider_form_save_with_reasoning_persists_effort() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");

    let mut form = ProviderFormState::default();
    form.cycle_provider(1);
    form.profile_name = "r1".to_string();
    form.api_key = "sk-test".to_string();
    form.reasoning_effort = "high".to_string();

    form.save_with_oauth_to_path_using(
        &config_path,
        || unreachable!(),
        |_, _| Ok(()),
        |_| Ok(()),
        |_, _| Ok(()),
        |_| Ok(()),
    )
    .unwrap();

    let cfg = GlobalConfig::load_from(&config_path).unwrap();
    assert_eq!(cfg.profiles["r1"].reasoning_effort.as_deref(), Some("high"));
}

/// Seed a temp config with one provider profile and return (config_path, TempDir).
fn seed_provider_config(name: &str) -> (std::path::PathBuf, TempDir) {
    use zentra_cli::config::ProviderProfile;
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");
    let mut global = GlobalConfig::default();
    global.profiles.insert(
        name.to_string(),
        ProviderProfile {
            kind: "openai_compat".to_string(),
            base_url: "https://api.example.com/v1".to_string(),
            model: "some-model".to_string(),
            keyless: false,
            auth_method: AuthMethod::ApiKey,
            context_window: Some(128_000),
            reasoning_effort: Some("high".to_string()),
            temperature: None,
        },
    );
    global.default_profile = Some(name.to_string());
    global.save_to(&config_path).unwrap();
    (config_path, dir)
}

#[test]
fn open_provider_edit_form_prefills_from_profile() {
    let (config_path, _dir) = seed_provider_config("prod");
    let mut state = MenuState::new(
        true,
        true,
        vec![("prod".to_string(), "some-model".to_string())],
        String::new(),
        String::new(),
        String::new(),
        String::new(),
    );
    state.provider_idx = 0;

    state.open_provider_edit_form_from(&config_path);

    assert_eq!(state.settings_detail, DetailMode::ProviderForm);
    let editing = state
        .form
        .editing
        .as_ref()
        .expect("form should be in edit mode");
    assert_eq!(editing.name, "prod");
    assert_eq!(editing.kind, "openai_compat");
    assert!(!editing.keyless);
    assert_eq!(state.form.model, "some-model");
    assert_eq!(state.form.base_url, "https://api.example.com/v1");
    assert_eq!(state.form.reasoning_effort, "high");
    assert_eq!(state.form.profile_name, "prod");
    assert_eq!(
        state.form.api_key, "",
        "key field starts blank (blank = keep current)"
    );
    // Cursor lands on the API-key field for quick rotation.
    assert_eq!(state.form.focused_field, 4);
}

#[test]
fn edit_save_with_blank_key_preserves_existing_key() {
    let (config_path, _dir) = seed_provider_config("prod");

    let form = ProviderFormState {
        provider_idx: 0,
        model: "new-model".to_string(),
        base_url: "https://api.example.com/v2".to_string(),
        auth_method: AuthMethod::ApiKey,
        api_key: String::new(), // blank → keep current key
        profile_name: "prod".to_string(),
        reasoning_effort: String::new(),
        focused_field: 4,
        error: None,
        editing: Some(ProviderEditContext {
            name: "prod".to_string(),
            kind: "openai_compat".to_string(),
            keyless: false,
        }),
    };

    let saved_name = form
        .save_with_oauth_to_path_using(
            &config_path,
            || unreachable!(),
            |_, _| Ok(()),
            |_| Ok(()),
            |_, _| panic!("store_key must NOT be called when the key field is blank"),
            |_| Ok(()),
        )
        .unwrap();

    assert_eq!(saved_name, "prod");
    let cfg = GlobalConfig::load_from(&config_path).unwrap();
    let profile = cfg.profiles.get("prod").unwrap();
    // Editable fields were updated, identity (kind) preserved, key untouched.
    assert_eq!(profile.model, "new-model");
    assert_eq!(profile.base_url, "https://api.example.com/v2");
    assert_eq!(profile.kind, "openai_compat");
}

#[test]
fn edit_save_with_new_key_rotates_under_original_name() {
    let (config_path, _dir) = seed_provider_config("prod");
    let stored_keys = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

    let form = ProviderFormState {
        provider_idx: 0,
        model: "some-model".to_string(),
        base_url: "https://api.example.com/v1".to_string(),
        auth_method: AuthMethod::ApiKey,
        api_key: "sk-rotated-999".to_string(),
        profile_name: "prod".to_string(),
        reasoning_effort: String::new(),
        focused_field: 4,
        error: None,
        editing: Some(ProviderEditContext {
            name: "prod".to_string(),
            kind: "openai_compat".to_string(),
            keyless: false,
        }),
    };

    form.save_with_oauth_to_path_using(
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

    assert_eq!(
        stored_keys.lock().unwrap().as_slice(),
        [("prod".to_string(), "sk-rotated-999".to_string())]
    );
}

#[test]
fn edit_mode_validate_allows_blank_key() {
    let form = ProviderFormState {
        provider_idx: 0,
        model: "m".to_string(),
        base_url: "https://api.example.com/v1".to_string(),
        auth_method: AuthMethod::ApiKey,
        api_key: String::new(),
        profile_name: "prod".to_string(),
        reasoning_effort: String::new(),
        focused_field: 4,
        error: None,
        editing: Some(ProviderEditContext {
            name: "prod".to_string(),
            kind: "openai_compat".to_string(),
            keyless: false,
        }),
    };
    assert!(
        form.validate().is_ok(),
        "blank key is valid while editing (means keep current)"
    );
}

#[test]
fn provider_form_save_with_blank_reasoning_omits_effort() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");

    let mut form = ProviderFormState::default();
    form.cycle_provider(1);
    form.profile_name = "r2".to_string();
    form.api_key = "sk-test".to_string();
    form.reasoning_effort = "   ".to_string(); // whitespace-only → None

    form.save_with_oauth_to_path_using(
        &config_path,
        || unreachable!(),
        |_, _| Ok(()),
        |_| Ok(()),
        |_, _| Ok(()),
        |_| Ok(()),
    )
    .unwrap();

    let cfg = GlobalConfig::load_from(&config_path).unwrap();
    assert!(cfg.profiles["r2"].reasoning_effort.is_none());
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
    state.open_settings();
    state.settings_enter_detail(); // Providers detail
    state.provider_idx = 1;

    assert_eq!(
        provider_selector_footer_hint(&state),
        " ↑↓ navigate · Enter use · a add · e edit · d delete · ← back"
    );

    let deleted = state.handle_provider_delete_key().unwrap();

    assert!(!deleted);
    assert_eq!(state.pending_delete_profile.as_deref(), Some("openai"));
    assert!(state.provider_error.is_none());
    assert_eq!(
        provider_selector_footer_hint(&state),
        " d again confirm delete · ↑↓ move cancel · ← back"
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
    state.open_settings();
    state.settings_enter_detail(); // Providers detail
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
        " ↑↓ navigate · Enter use · a add · e edit · d delete · ← back"
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
    state.open_settings();
    state.settings_enter_detail(); // Providers detail
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
    state.open_settings();
    state.settings_enter_detail(); // Providers detail
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
    state.settings_leave_detail();
    assert!(state.pending_delete_profile.is_none());
    assert_eq!(state.settings_focus, SettingsFocus::Nav);
}

#[test]
fn apply_provider_change_persists_default_and_refreshes_state_in_place() {
    use std::collections::HashMap;
    use zentra_cli::config::ProviderProfile;

    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");

    let mut profiles = HashMap::new();
    profiles.insert(
        "anthropic".to_string(),
        ProviderProfile {
            kind: "anthropic".to_string(),
            base_url: "https://api.anthropic.com".to_string(),
            model: "claude-opus-4-1".to_string(),
            keyless: false,
            auth_method: AuthMethod::ApiKey,
            context_window: None,
            reasoning_effort: None,
            temperature: None,
        },
    );
    profiles.insert(
        "openai".to_string(),
        ProviderProfile {
            kind: "openai_compat".to_string(),
            base_url: "https://api.openai.com/v1".to_string(),
            model: "gpt-4o".to_string(),
            keyless: false,
            auth_method: AuthMethod::ApiKey,
            context_window: None,
            reasoning_effort: None,
            temperature: None,
        },
    );
    GlobalConfig {
        profiles,
        default_profile: Some("anthropic".to_string()),
        output_dir: None,
        theme: None,
        cwe_url_template: None,
    }
    .save_to(&config_path)
    .unwrap();

    let mut state = MenuState::new(
        true,
        true,
        vec![
            ("anthropic".to_string(), "claude-opus-4-1".to_string()),
            ("openai".to_string(), "gpt-4o".to_string()),
        ],
        "claude-opus-4-1".to_string(),
        "anthropic".to_string(),
        String::new(),
        String::new(),
    );
    state.open_settings();
    state.settings_enter_detail(); // Providers detail
    state.provider_idx = 1;

    state
        .apply_provider_change_to("openai", &config_path)
        .unwrap();

    // In-memory state refreshed without leaving the TUI.
    assert_eq!(state.active_profile, "openai");
    assert_eq!(state.default_profile, "openai");
    assert_eq!(state.active_model, "gpt-4o");
    assert!(state.provider_configured);

    // And the new default is durably persisted to the config file.
    let saved = GlobalConfig::load_from(&config_path).unwrap();
    assert_eq!(saved.default_profile.as_deref(), Some("openai"));
}

#[test]
fn entering_clone_screen_sets_repo_input() {
    let mut state = MenuState::new(
        true,
        true,
        vec![],
        String::new(),
        String::new(),
        String::new(),
        String::new(),
    );
    state.open_repo_input();
    assert_eq!(state.screen, MenuScreen::RepoInput);
    assert_eq!(state.repo_url, "");
    assert!(state.repo_input_error.is_none());
}

#[test]
fn repo_input_edit_and_validate() {
    let mut state = MenuState::new(
        true, true, vec![], String::new(), String::new(), String::new(), String::new(),
    );
    state.open_repo_input();
    for c in "https://github.com/foo/bar.git".chars() {
        state.repo_url.push(c);
    }
    assert!(state.validate_repo_input().is_ok());

    state.repo_url.clear();
    state.repo_url.push_str("garbage");
    assert!(state.validate_repo_input().is_err());
}

#[test]
fn pentest_ui_renders_escalation_spawned_activity() {
    let mut state = PentestUiState::new(
        "https://app.example.test".into(),
        "model · profile".into(),
        "none".into(),
        None,
    );
    state.apply_event(zentra_cli::pentest::PentestEvent::EscalationSpawned {
        id: 100,
        parent_id: 6,
        finding_title: "IDOR on /api/user".into(),
        depth: 1,
    });
    assert!(state
        .activity
        .iter()
        .any(|a| a.contains("escalation") && a.contains("IDOR on /api/user")));
}

#[test]
fn pentest_ui_renders_escalation_cap_reached_activity() {
    let mut state = zentra_cli::tui::pentest_ui::PentestUiState::new(
        "https://app.example.test".into(),
        "model · profile".into(),
        "none".into(),
        None,
    );
    state.apply_event(zentra_cli::pentest::PentestEvent::EscalationCapReached {
        dropped_title: "XSS in search".into(),
    });
    assert!(state
        .activity
        .iter()
        .any(|a| a.contains("cap reached") && a.contains("XSS in search")));
}

#[test]
fn completed_footer_shows_output_dir() {
    let mut state = PentestUiState::new(
        "https://target.test".to_string(),
        "model · profile".to_string(),
        "none".to_string(),
        Some(std::path::PathBuf::from("/runs/pentest-123")),
    );
    state.completed = true;
    let footer = state.completion_footer_text();
    assert!(footer.contains("/runs/pentest-123"), "footer: {footer}");
    assert!(footer.contains("complete"));

    // No output dir → no "saved to" segment, falls back to the plain footer.
    let no_dir = PentestUiState::new(
        "https://t.test".to_string(),
        "m".to_string(),
        "n".to_string(),
        None,
    );
    assert!(!no_dir.completion_footer_text().contains("saved to"));
    assert!(no_dir.completion_footer_text().contains("complete"));
}

#[test]
fn provider_form_validate_skips_base_url_check_for_cli_providers() {
    use zentra_cli::wizard::KNOWN_PROVIDER_NAMES;

    // Find the index of "claude_cli" in KNOWN_PROVIDER_NAMES
    let claude_cli_idx = KNOWN_PROVIDER_NAMES
        .iter()
        .position(|&n| n == "claude_cli")
        .expect("claude_cli must be in KNOWN_PROVIDER_NAMES");

    let form = ProviderFormState {
        provider_idx: claude_cli_idx,
        profile_name: "my-claude-cli".to_string(),
        model: "claude-opus-4-8".to_string(),
        base_url: "claude".to_string(), // binary name — not a URL
        ..Default::default()
    };

    // validate() must succeed: CLI providers must not fail the base_url URL check
    assert!(
        form.validate().is_ok(),
        "CLI provider with binary-name base_url should pass validate(): {:?}",
        form.validate().unwrap_err()
    );
}

#[test]
fn uistate_mcp_status_updates_on_event() {
    use zentra_cli::agent::{McpStatus, ScanEvent};
    let mut state = UiState::new(
        vec![],
        "Codex CLI".to_string(),
        128_000,
        vec![],
        "main".to_string(),
        "myproject".to_string(),
        "codex_cli".to_string(),
    );
    state.apply_event(ScanEvent::McpChannelStatus(McpStatus::Disconnected));
    assert!(matches!(state.mcp_status, Some(McpStatus::Disconnected)));
}

#[test]
fn error_span_toggle_and_dismiss() {
    let mut state = MenuState::new(
        true, true, vec![], String::new(), String::new(), String::new(), String::new(),
    );
    assert!(state.last_error.is_none());

    state.last_error = Some("boom".to_string());
    assert!(!state.error_expanded);

    state.toggle_error_expanded();
    assert!(state.error_expanded);
    state.toggle_error_expanded();
    assert!(!state.error_expanded);

    state.error_expanded = true;
    state.dismiss_error();
    assert!(state.last_error.is_none());
    assert!(!state.error_expanded);
}

#[test]
fn toggle_error_is_noop_without_error() {
    let mut state = MenuState::new(
        true, true, vec![], String::new(), String::new(), String::new(), String::new(),
    );
    state.toggle_error_expanded();
    assert!(!state.error_expanded);
}

#[test]
fn incremental_banner_formats_counts() {
    let s = zentra_cli::tui::scan_ui::incremental_banner(3, 12, 14, "abc12345def");
    assert!(s.contains("Incremental rescan"));
    assert!(s.contains("baseline abc12345"));
    assert!(s.contains("3 changed"));
    assert!(s.contains("12 impacted"));
    assert!(s.contains("14 carried"));
}

// --- Live coverage counter ---
//
// The scanner panel shows how many distinct files each scanner has read. It
// counts only successful reads, so it matches .zentra/coverage.md exactly.

fn coverage_state() -> UiState {
    UiState::new(
        vec![ScannerType::Sast, ScannerType::ApiScan],
        "gpt-4o".to_string(),
        200_000,
        vec![],
        String::new(),
        String::new(),
        String::new(),
    )
}

#[test]
fn file_read_event_counts_distinct_successful_reads() {
    let mut state = coverage_state();

    for path in ["src/a.rs", "src/a.rs", "src/b.rs"] {
        state.apply_event(ScanEvent::FileRead {
            scanner: ScannerType::Sast,
            path: path.to_string(),
            outcome: ReadOutcome::Read { bytes: 10 },
        });
    }

    assert_eq!(state.scanners[0].files_read(), 2);
}

#[test]
fn file_read_event_ignores_holes() {
    let mut state = coverage_state();

    state.apply_event(ScanEvent::FileRead {
        scanner: ScannerType::Sast,
        path: "src/big.rs".to_string(),
        outcome: ReadOutcome::TooLarge { bytes: 200_000 },
    });
    state.apply_event(ScanEvent::FileRead {
        scanner: ScannerType::Sast,
        path: "src/gone.rs".to_string(),
        outcome: ReadOutcome::Failed,
    });

    assert_eq!(
        state.scanners[0].files_read(),
        0,
        "a file the agent could not read is not coverage"
    );
}

#[test]
fn file_read_event_counts_per_scanner() {
    let mut state = coverage_state();

    state.apply_event(ScanEvent::FileRead {
        scanner: ScannerType::Sast,
        path: "src/a.rs".to_string(),
        outcome: ReadOutcome::Read { bytes: 1 },
    });
    state.apply_event(ScanEvent::FileRead {
        scanner: ScannerType::ApiScan,
        path: "src/a.rs".to_string(),
        outcome: ReadOutcome::Read { bytes: 1 },
    });
    state.apply_event(ScanEvent::FileRead {
        scanner: ScannerType::ApiScan,
        path: "src/b.rs".to_string(),
        outcome: ReadOutcome::Read { bytes: 1 },
    });

    assert_eq!(state.scanners[0].files_read(), 1);
    assert_eq!(state.scanners[1].files_read(), 2);
}

#[test]
fn file_read_event_normalizes_separators() {
    let mut state = coverage_state();

    state.apply_event(ScanEvent::FileRead {
        scanner: ScannerType::Sast,
        path: r"src\a.rs".to_string(),
        outcome: ReadOutcome::Read { bytes: 1 },
    });
    state.apply_event(ScanEvent::FileRead {
        scanner: ScannerType::Sast,
        path: "src/a.rs".to_string(),
        outcome: ReadOutcome::Read { bytes: 1 },
    });

    assert_eq!(state.scanners[0].files_read(), 1);
}

#[test]
fn file_read_event_for_an_unknown_scanner_is_ignored() {
    let mut state = coverage_state();

    // IacScan is not in this run's scanner list.
    state.apply_event(ScanEvent::FileRead {
        scanner: ScannerType::IacScan,
        path: "src/a.rs".to_string(),
        outcome: ReadOutcome::Read { bytes: 1 },
    });

    assert_eq!(state.scanners[0].files_read(), 0);
    assert_eq!(state.scanners[1].files_read(), 0);
}
