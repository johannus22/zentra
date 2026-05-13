use ratatui::layout::{Constraint, Layout, Rect};
use tempfile::TempDir;
use zentra_cli::agent::{ScanEvent, ScannerType};
use zentra_cli::config::{AuthMethod, GlobalConfig};
use zentra_cli::state::{Finding, Severity};
use zentra_cli::tui::menu::{
    centered_middle_column, main_menu_actions, provider_selector_footer_hint,
    scanner_selector_footer_hint, MenuScreen, MenuState, OAuthModalPhase,
};
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
    // 6 items: RunFull(0), SelectScanners(1), ViewResults(2), ChangeProvider(3), AddProvider(4), Exit(5)
    state.next();
    assert_eq!(state.selected_idx, 1);
    state.next();
    state.next();
    state.next();
    state.next();
    assert_eq!(state.selected_idx, 5);
    state.next(); // clamp
    assert_eq!(state.selected_idx, 5);
    state.prev();
    assert_eq!(state.selected_idx, 4);
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
    assert!(!state.is_item_enabled(1)); // SelectScanners
    assert!(state.is_item_enabled(2)); // ViewResults
    assert!(!state.is_item_enabled(3)); // ChangeProvider
    assert!(state.is_item_enabled(4)); // AddProvider
    assert!(state.is_item_enabled(5)); // Exit
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
fn menu_state_navigate_new_max_is_5() {
    let mut state = MenuState::new(
        true,
        true,
        vec![],
        String::new(),
        String::new(),
        String::new(),
        String::new(),
    );
    for _ in 0..5 {
        state.next();
    }
    assert_eq!(state.selected_idx, 5);
    state.next(); // clamp
    assert_eq!(state.selected_idx, 5);
}

#[test]
fn menu_state_main_menu_still_has_six_actions() {
    assert_eq!(
        main_menu_actions(),
        &[
            "Run Full Scan",
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
    assert!(!state.is_item_enabled(3)); // Change Provider = index 3
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
fn provider_form_validate_allows_openai_oauth_without_api_key() {
    let mut form = ProviderFormState::default();
    form.cycle_provider(1);
    form.auth_method = AuthMethod::OAuth;
    form.profile_name = "openai_oauth".to_string();

    assert!(form.validate().is_ok());
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

    state.open_oauth_modal("https://auth.openai.com/example".to_string());
    let modal = state.oauth_modal.as_ref().unwrap();
    assert_eq!(modal.phase, OAuthModalPhase::LaunchingBrowser);
    assert_eq!(modal.auth_url, "https://auth.openai.com/example");
    assert!(modal.error.is_none());

    state.set_oauth_modal_error(Some("Failed to launch browser".to_string()));
    state.set_oauth_modal_phase(OAuthModalPhase::WaitingForCallback);
    let modal = state.oauth_modal.as_ref().unwrap();
    assert_eq!(modal.phase, OAuthModalPhase::WaitingForCallback);
    assert_eq!(
        modal.error.as_deref(),
        Some("Failed to launch browser")
    );

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
fn provider_form_save_persists_openai_oauth_auth_method_without_api_key() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");

    let mut form = ProviderFormState::default();
    form.cycle_provider(1);
    form.auth_method = AuthMethod::OAuth;
    form.profile_name = "openai_oauth".to_string();

    let saved_name = form
        .save_with_oauth_to_path(
            &config_path,
            || {
                Ok(zentra_cli::auth::OAuthTokens {
                    access_token: "access-token".to_string(),
                    refresh_token: "refresh-token".to_string(),
                    expires_at: 4_102_444_800,
                })
            },
            |_, _| Ok(()),
        )
        .unwrap();

    assert_eq!(saved_name, "openai_oauth");

    let cfg = GlobalConfig::load_from(&config_path).unwrap();
    let profile = cfg.profiles.get("openai_oauth").unwrap();
    assert_eq!(profile.auth_method, AuthMethod::OAuth);
    assert_eq!(cfg.default_profile.as_deref(), Some("openai_oauth"));

    let key_path = dir.path().join("keys").join("openai_oauth.key");
    assert!(
        !key_path.exists(),
        "OAuth save should not persist an API key file"
    );
}

#[test]
fn provider_form_oauth_save_store_failure_preserves_form_and_populates_error() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");

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
    state.form.cycle_provider(1);
    state.form.auth_method = AuthMethod::OAuth;
    state.form.profile_name = "openai_retry".to_string();
    state.form.model = "gpt-4.1".to_string();
    state.form.base_url = "https://api.openai.com/v1".to_string();

    let expected_model = state.form.model.clone();
    let expected_base_url = state.form.base_url.clone();
    let expected_profile_name = state.form.profile_name.clone();
    let expected_auth_method = state.form.auth_method.clone();

    state.open_oauth_modal("https://auth.openai.com/example".to_string());

    let err = state
        .form
        .save_with_oauth_to_path(
            &config_path,
            || {
                Ok(zentra_cli::auth::OAuthTokens {
                    access_token: "access-token".to_string(),
                    refresh_token: "refresh-token".to_string(),
                    expires_at: 4_102_444_800,
                })
            },
            |_, _| anyhow::bail!("simulated oauth token store failure"),
        )
        .unwrap_err();

    state.finish_oauth_modal_error(err.to_string());

    assert!(state.oauth_modal.is_none());
    assert_eq!(state.screen, MenuScreen::ProviderForm);
    assert_eq!(state.form.model, expected_model);
    assert_eq!(state.form.base_url, expected_base_url);
    assert_eq!(state.form.profile_name, expected_profile_name);
    assert_eq!(state.form.auth_method, expected_auth_method);
    assert_eq!(state.form.error.as_deref(), Some("simulated oauth token store failure"));
}

#[test]
fn provider_form_save_oauth_store_failure_leaves_existing_config_unchanged() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");

    let mut original = GlobalConfig::default();
    original.default_profile = Some("work".to_string());
    original.profiles.insert(
        "work".to_string(),
        zentra_cli::config::ProviderProfile {
            kind: "anthropic".to_string(),
            base_url: "https://api.anthropic.com".to_string(),
            model: "claude-opus-4-1".to_string(),
            keyless: false,
            auth_method: AuthMethod::ApiKey,
            context_window: Some(200_000),
        },
    );
    original.save_to(&config_path).unwrap();

    let mut form = ProviderFormState::default();
    form.cycle_provider(1);
    form.auth_method = AuthMethod::OAuth;
    form.profile_name = "work".to_string();

    let err = form
        .save_with_oauth_to_path(
            &config_path,
            || {
                Ok(zentra_cli::auth::OAuthTokens {
                    access_token: "access-token".to_string(),
                    refresh_token: "refresh-token".to_string(),
                    expires_at: 4_102_444_800,
                })
            },
            |_, _| anyhow::bail!("simulated oauth token store failure"),
        )
        .unwrap_err();

    assert!(err.to_string().contains("token store failure"));

    let cfg = GlobalConfig::load_from(&config_path).unwrap();
    let profile = cfg.profiles.get("work").unwrap();
    assert_eq!(cfg.default_profile.as_deref(), Some("work"));
    assert_eq!(profile.kind, "anthropic");
    assert_eq!(profile.base_url, "https://api.anthropic.com");
    assert_eq!(profile.model, "claude-opus-4-1");
    assert_eq!(profile.auth_method, AuthMethod::ApiKey);
}

#[test]
fn provider_form_oauth_save_config_failure_rolls_back_stored_tokens() {
    let dir = TempDir::new().unwrap();
    let blocked_parent = dir.path().join("blocked-parent");
    std::fs::write(&blocked_parent, "not a directory").unwrap();
    let config_path = blocked_parent.join("config.toml");

    let mut form = ProviderFormState::default();
    form.cycle_provider(1);
    form.auth_method = AuthMethod::OAuth;
    form.profile_name = "openai_oauth".to_string();

    let store_calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let delete_calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

    let err = form
        .save_with_oauth_to_path_using(
            &config_path,
            || {
                Ok(zentra_cli::auth::OAuthTokens {
                    access_token: "access-token".to_string(),
                    refresh_token: "refresh-token".to_string(),
                    expires_at: 4_102_444_800,
                })
            },
            {
                let store_calls = store_calls.clone();
                move |profile_name: &str, _: &zentra_cli::auth::OAuthTokens| {
                    store_calls.lock().unwrap().push(profile_name.to_string());
                    Ok(())
                }
            },
            {
                let delete_calls = delete_calls.clone();
                move |profile_name: &str| {
                    delete_calls.lock().unwrap().push(profile_name.to_string());
                    Ok(())
                }
            },
            |_, _| Ok(()),
            |_| Ok(()),
        )
        .unwrap_err();

    assert_eq!(store_calls.lock().unwrap().as_slice(), ["openai_oauth"]);
    assert_eq!(delete_calls.lock().unwrap().as_slice(), ["openai_oauth"]);
    assert!(!err.to_string().is_empty());
    assert!(!config_path.exists(), "config file should not be created on rollback");
}

#[test]
fn provider_form_oauth_save_delete_key_failure_rolls_back_stored_tokens_and_keeps_config() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");

    let mut original = GlobalConfig::default();
    original.default_profile = Some("work".to_string());
    original.profiles.insert(
        "work".to_string(),
        zentra_cli::config::ProviderProfile {
            kind: "anthropic".to_string(),
            base_url: "https://api.anthropic.com".to_string(),
            model: "claude-opus-4-1".to_string(),
            keyless: false,
            auth_method: AuthMethod::ApiKey,
            context_window: Some(200_000),
        },
    );
    original.save_to(&config_path).unwrap();

    let mut form = ProviderFormState::default();
    form.cycle_provider(1);
    form.auth_method = AuthMethod::OAuth;
    form.profile_name = "work".to_string();

    let stored_oauth = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let deleted_oauth = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

    let err = form
        .save_with_oauth_to_path_using(
            &config_path,
            || {
                Ok(zentra_cli::auth::OAuthTokens {
                    access_token: "access-token".to_string(),
                    refresh_token: "refresh-token".to_string(),
                    expires_at: 4_102_444_800,
                })
            },
            {
                let stored_oauth = stored_oauth.clone();
                move |profile_name: &str, _: &zentra_cli::auth::OAuthTokens| {
                    stored_oauth.lock().unwrap().push(profile_name.to_string());
                    Ok(())
                }
            },
            {
                let deleted_oauth = deleted_oauth.clone();
                move |profile_name: &str| {
                    deleted_oauth.lock().unwrap().push(profile_name.to_string());
                    Ok(())
                }
            },
            |_, _| Ok(()),
            |_| anyhow::bail!("simulated api key delete failure"),
        )
        .unwrap_err();

    assert!(err.to_string().contains("api key delete failure"));
    assert_eq!(stored_oauth.lock().unwrap().as_slice(), ["work"]);
    assert_eq!(deleted_oauth.lock().unwrap().as_slice(), ["work"]);

    let cfg = GlobalConfig::load_from(&config_path).unwrap();
    let profile = cfg.profiles.get("work").unwrap();
    assert_eq!(cfg.default_profile.as_deref(), Some("work"));
    assert_eq!(profile.kind, "anthropic");
    assert_eq!(profile.base_url, "https://api.anthropic.com");
    assert_eq!(profile.model, "claude-opus-4-1");
    assert_eq!(profile.auth_method, AuthMethod::ApiKey);
}

#[test]
fn provider_form_overwriting_profile_with_oauth_clears_stale_api_key() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");

    let mut original = GlobalConfig::default();
    original.default_profile = Some("work".to_string());
    original.profiles.insert(
        "work".to_string(),
        zentra_cli::config::ProviderProfile {
            kind: "openai".to_string(),
            base_url: "https://api.openai.com/v1".to_string(),
            model: "gpt-4.1".to_string(),
            keyless: false,
            auth_method: AuthMethod::ApiKey,
            context_window: Some(1_000_000),
        },
    );
    original.save_to(&config_path).unwrap();

    let mut form = ProviderFormState::default();
    form.cycle_provider(1);
    form.auth_method = AuthMethod::OAuth;
    form.profile_name = "work".to_string();

    let cleared_keys = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let stored_oauth = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

    let saved_name = form
        .save_with_oauth_to_path_using(
            &config_path,
            || {
                Ok(zentra_cli::auth::OAuthTokens {
                    access_token: "access-token".to_string(),
                    refresh_token: "refresh-token".to_string(),
                    expires_at: 4_102_444_800,
                })
            },
            {
                let stored_oauth = stored_oauth.clone();
                move |profile_name: &str, _: &zentra_cli::auth::OAuthTokens| {
                    stored_oauth.lock().unwrap().push(profile_name.to_string());
                    Ok(())
                }
            },
            |_| Ok(()),
            |_, _| Ok(()),
            {
                let cleared_keys = cleared_keys.clone();
                move |profile_name: &str| {
                    cleared_keys.lock().unwrap().push(profile_name.to_string());
                    Ok(())
                }
            },
        )
        .unwrap();

    assert_eq!(saved_name, "work");
    assert_eq!(stored_oauth.lock().unwrap().as_slice(), ["work"]);
    assert_eq!(cleared_keys.lock().unwrap().as_slice(), ["work"]);

    let cfg = GlobalConfig::load_from(&config_path).unwrap();
    let profile = cfg.profiles.get("work").unwrap();
    assert_eq!(profile.auth_method, AuthMethod::OAuth);
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
    assert_eq!(state.selected_idx, 3);
}
