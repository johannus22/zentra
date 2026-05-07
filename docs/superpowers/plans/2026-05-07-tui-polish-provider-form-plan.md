# TUI Polish & Provider Form — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Polish the zentra-cli TUI with a frozen scan timer, better abort behavior, project-name header, redesigned main menu (Option C), and a full in-TUI provider management flow (selector + add form).

**Architecture:** All changes are confined to `src/tui/` (state logic + rendering), `src/commands/scan.rs` (project_name derivation), and `src/main.rs` (menu loop). Pure logic (UiState, MenuState, ProviderFormState) is tested directly. Rendering functions are visual-only and not unit tested.

**Tech Stack:** Rust, ratatui 0.29, crossterm, tokio, anyhow, keyring (keychain)

---

## File Map

| File | What changes |
|------|-------------|
| `src/tui/mod.rs` | Add `scan_end`, `project_name` to `UiState`; add `ProviderFormState` struct; add `popup_items()` fn |
| `src/tui/scan_ui.rs` | Use `scan_end` in timer; use `popup_items()`; add `UiState::abort_scan()`; accept `project_name` param |
| `src/tui/menu.rs` | Full redesign: `MenuRow` enum, Option C layout, `ProviderSelector`/`ProviderForm` screens, new `MenuState` fields |
| `src/commands/scan.rs` | Add `current_project_name()`, pass to `run_scan_ui` |
| `src/wizard/mod.rs` | Export `pub const KNOWN_PROVIDER_NAMES` |
| `src/main.rs` | Reload `GlobalConfig` each loop iteration; pass new args to `run_menu`; handle new `MenuAction` variants |
| `tests/tui_test.rs` | Update call sites for new signatures; add tests for new logic |

---

## Task 1: Timer Freeze — `scan_end` field

**Files:**
- Modify: `src/tui/mod.rs`
- Modify: `src/tui/scan_ui.rs`
- Modify: `tests/tui_test.rs`

- [ ] **Step 1: Write failing tests**

Add to `tests/tui_test.rs`:

```rust
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
    let d2 = state.elapsed_duration();
    // Both calls return the same frozen value (same end instant)
    assert_eq!(d1, d2);
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cargo test ui_state_scan_end ui_state_mark_complete ui_state_elapsed 2>&1 | tail -20
```
Expected: compile error (field `scan_end` not found, method `mark_complete` not found, etc.)

- [ ] **Step 3: Add `scan_end` field and `mark_complete` / `elapsed_duration` methods to `UiState` in `src/tui/mod.rs`**

In `UiState` struct, add after `scan_start`:
```rust
pub scan_end: Option<std::time::Instant>,
pub project_name: String,
```

Update `UiState::new` signature — add `project_name: String` as the 6th parameter (after `branch`):
```rust
pub fn new(
    scanner_types: Vec<ScannerType>,
    model_info: String,
    context_window: u32,
    profiles: Vec<String>,
    branch: String,
    project_name: String,
) -> Self {
    // ...
    Self {
        // existing fields...
        scan_end: None,
        project_name,
    }
}
```

Add methods after `toggle_provider_popup`:
```rust
pub fn mark_complete(&mut self) {
    self.scan_done = true;
    self.scan_end = Some(std::time::Instant::now());
}

pub fn elapsed_duration(&self) -> std::time::Duration {
    self.scan_end
        .map(|end| end.duration_since(self.scan_start))
        .unwrap_or_else(|| self.scan_start.elapsed())
}
```

- [ ] **Step 4: Update `run_loop` in `src/tui/scan_ui.rs` to call `mark_complete`**

Replace the scan-completion detection block (around line 143):
```rust
// Before:
if state.all_done() && !state.scan_done {
    state.scan_done = true;
    state.activity = "✓ Scan complete — browse findings · q to exit".to_string();
}

// After:
if state.all_done() && !state.scan_done {
    state.mark_complete();
    state.activity = "✓ Scan complete — browse findings · q to exit".to_string();
}
```

- [ ] **Step 5: Update `render_activity` in `src/tui/scan_ui.rs` to use `elapsed_duration()`**

Replace the duration computation inside the `scan_done && !scan_aborted` branch:
```rust
// Before:
let elapsed = state.scan_start.elapsed();

// After:
let elapsed = state.elapsed_duration();
```

- [ ] **Step 6: Update `UiState::new` call in `src/tui/scan_ui.rs` (line ~63)**

```rust
// Before:
let mut state = UiState::new(scanners, model_info, context_window, profiles, branch);

// After:
let mut state = UiState::new(scanners, model_info, context_window, profiles, branch, project_name);
```

Also update `run_scan_ui` and `run_loop` signatures to accept `project_name: String`:
```rust
pub async fn run_scan_ui(
    mut rx: mpsc::Receiver<ScanEvent>,
    scanners: Vec<ScannerType>,
    model_info: String,
    context_window: u32,
    abort_handle: tokio::task::AbortHandle,
    profiles: Vec<String>,
    branch: String,
    project_name: String,
) -> Result<ScanOutcome> { ... }

async fn run_loop(
    terminal: &mut ratatui::DefaultTerminal,
    rx: &mut mpsc::Receiver<ScanEvent>,
    scanners: Vec<ScannerType>,
    model_info: String,
    context_window: u32,
    abort_handle: tokio::task::AbortHandle,
    profiles: Vec<String>,
    branch: String,
    project_name: String,
) -> Result<ScanOutcome> { ... }
```

- [ ] **Step 7: Update existing `UiState::new` calls in `tests/tui_test.rs`**

Every existing call to `UiState::new` needs a 6th `String::new()` argument for `project_name`. There are 12 call sites. Example pattern:
```rust
// Every occurrence of:
UiState::new(vec![...], "m".to_string(), 200_000, vec![], String::new())
// becomes:
UiState::new(vec![...], "m".to_string(), 200_000, vec![], String::new(), String::new())
```

- [ ] **Step 8: Run the new tests to confirm they pass**

```bash
cargo test ui_state_scan_end ui_state_mark_complete ui_state_elapsed 2>&1 | tail -20
```
Expected: all 3 tests PASS.

- [ ] **Step 9: Run all tests**

```bash
cargo test 2>&1 | tail -30
```
Expected: all existing tests pass (no regressions from signature change).

- [ ] **Step 10: Commit**

```bash
git add src/tui/mod.rs src/tui/scan_ui.rs tests/tui_test.rs
git commit -m "feat: freeze scan timer at completion using scan_end instant"
```

---

## Task 2: Abort Behavior — dynamic popup items + abort_scan method

**Files:**
- Modify: `src/tui/mod.rs`
- Modify: `src/tui/scan_ui.rs`
- Modify: `tests/tui_test.rs`

- [ ] **Step 1: Write failing tests**

Add to `tests/tui_test.rs`:
```rust
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
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cargo test popup_items ui_state_abort_scan 2>&1 | tail -20
```
Expected: compile errors (`popup_items` not found, `abort_scan` not found).

- [ ] **Step 3: Add `popup_items` function to `src/tui/scan_ui.rs`**

Remove the `pub const POPUP_ITEMS: &[&str]` constant. Replace with:
```rust
pub fn popup_items(scan_done: bool) -> Vec<&'static str> {
    let mut items = vec![
        "Change Provider and Restart Scan",
        "Add Provider",
        "Exit App",
    ];
    if !scan_done {
        items.insert(2, "Abort Scan");
    }
    items
}
```

- [ ] **Step 4: Add `abort_scan` method to `UiState` in `src/tui/mod.rs`**

After `mark_complete`:
```rust
pub fn abort_scan(&mut self) {
    for s in &mut self.scanners {
        if s.status == ScanStatus::Running {
            s.status = ScanStatus::Failed;
        }
    }
    self.scan_aborted = true;
    self.scan_done = true;
    self.scan_end = Some(std::time::Instant::now());
}
```

- [ ] **Step 5: Update popup rendering and navigation in `src/tui/scan_ui.rs` to use `popup_items()`**

Replace all `POPUP_ITEMS` references. In the key handler for `popup_open`, update:

```rust
// Navigation — replace:
KeyCode::Down => state.popup.next(POPUP_ITEMS.len()),
// With:
KeyCode::Down => state.popup.next(popup_items(state.scan_done).len()),
```

Replace the Enter handler's hardcoded match with string-based dispatch:
```rust
KeyCode::Enter => {
    let items = popup_items(state.scan_done);
    match items.get(state.popup.selected).copied().unwrap_or("") {
        "Change Provider and Restart Scan" => {
            state.toggle_popup();
            state.toggle_provider_popup();
        }
        "Add Provider" => {
            return Ok(ScanOutcome::Reconfigure);
        }
        "Abort Scan" => {
            abort_handle.abort();
            state.abort_scan();
            state.activity = "✗ Scan aborted — browse findings · q to exit".to_string();
            state.toggle_popup();
        }
        "Exit App" => return Ok(ScanOutcome::ExitApp),
        _ => {}
    }
}
```

- [ ] **Step 6: Update `render_popup` in `src/tui/scan_ui.rs` to use `popup_items()`**

```rust
fn render_popup(frame: &mut Frame, area: Rect, popup: &crate::tui::PopupState, scan_done: bool) {
    let items_list = popup_items(scan_done);
    let popup_width = 46u16;
    let popup_height = (items_list.len() as u16) + 4;
    let popup_area = centered_rect(popup_width, popup_height, area);

    frame.render_widget(Clear, popup_area);

    let items: Vec<ListItem> = items_list
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let prefix = if i == popup.selected { "▶ " } else { "  " };
            let style = if i == popup.selected {
                Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow)
            } else {
                Style::default()
            };
            ListItem::new(format!("{}{}", prefix, label)).style(style)
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("  MENU  ").title_style(Style::default().fg(Color::Cyan)));
    frame.render_widget(list, popup_area);
}
```

Update the call site in `render()`:
```rust
// Before:
render_popup(frame, area, &state.popup);
// After:
render_popup(frame, area, &state.popup, state.scan_done);
```

- [ ] **Step 7: Run the new tests**

```bash
cargo test popup_items ui_state_abort_scan 2>&1 | tail -20
```
Expected: all 3 tests PASS.

- [ ] **Step 8: Run all tests**

```bash
cargo test 2>&1 | tail -30
```
Expected: all tests pass.

- [ ] **Step 9: Commit**

```bash
git add src/tui/mod.rs src/tui/scan_ui.rs tests/tui_test.rs
git commit -m "feat: abort clears running scanners, dynamic popup hides abort when done"
```

---

## Task 3: Scan UI Header — project name in right panel

**Files:**
- Modify: `src/tui/scan_ui.rs`
- Modify: `src/commands/scan.rs`
- Modify: `tests/tui_test.rs`

- [ ] **Step 1: Add `current_project_name()` to `src/commands/scan.rs`**

After `current_branch()`:
```rust
fn current_project_name() -> String {
    std::env::current_dir()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "project".to_string())
}
```

- [ ] **Step 2: Pass `project_name` through `run_once` in `src/commands/scan.rs`**

In `run_once`, after `let branch = current_branch();` add:
```rust
let project_name = current_project_name();
```

Update `run_scan_ui` call to include it:
```rust
let outcome = run_scan_ui(
    rx, scanners_with_framework, model_info, context_window,
    abort_handle, profiles, branch, project_name,
).await?;
```

- [ ] **Step 3: Update `render_header` right column in `src/tui/scan_ui.rs`**

Replace the right column block. Also update `Layout::horizontal` to widen right column from `Length(18)` to `Length(22)`:

```rust
fn render_header(frame: &mut Frame, area: Rect, state: &UiState) {
    let cols = Layout::horizontal([
        Constraint::Min(40),
        Constraint::Length(22),
    ])
    .split(area);

    // Left panel (unchanged — banner + token info)
    let pct = state.token_pct();
    let bar_width = 10usize;
    let filled = (pct as usize * bar_width / 100).min(bar_width);
    let bar = format!(
        "[{}{}] {}%",
        "█".repeat(filled),
        "░".repeat(bar_width - filled),
        pct
    );
    let banner = if area.width >= 80 {
        " ____        _ \n|_  /___ _ _| |_ _ _ __ _\n / // -_) ' \\  _| '_/ _` |\n/___\\___|_||_\\__|_| \\__,_|"
    } else {
        "ZENTRA"
    };
    let left_text = format!(
        "{}\n{} · peak: {} / {} {}  total: {}",
        banner,
        state.model_info,
        state.peak_input_tokens,
        state.context_window,
        bar,
        state.total_tokens,
    );
    let left = Paragraph::new(left_text)
        .block(Block::default().borders(Borders::ALL))
        .style(Style::default().fg(Color::Cyan));
    frame.render_widget(left, cols[0]);

    // Right panel: project name (green bold), branch (dark gray), version (dim)
    let project_display = state.project_name.chars().take(16).collect::<String>();
    let branch_display = state.branch.chars().take(14).collect::<String>();
    let right_content = ratatui::text::Text::from(vec![
        ratatui::text::Line::from(vec![
            ratatui::text::Span::styled(
                project_display,
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            ),
        ]),
        ratatui::text::Line::from(vec![
            ratatui::text::Span::styled(
                format!("⎇ {}", branch_display),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        ratatui::text::Line::from(vec![
            ratatui::text::Span::styled(
                format!("v{}", env!("CARGO_PKG_VERSION")),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
    ]);
    let right = Paragraph::new(right_content)
        .block(Block::default().borders(Borders::ALL))
        .alignment(ratatui::layout::Alignment::Right);
    frame.render_widget(right, cols[1]);
}
```

- [ ] **Step 4: Run all tests**

```bash
cargo test 2>&1 | tail -30
```
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/tui/scan_ui.rs src/commands/scan.rs tests/tui_test.rs
git commit -m "feat: add project name to scan UI header right panel"
```

---

## Task 4: Main Menu Redesign — Option C layout, grouped sections

**Files:**
- Modify: `src/tui/menu.rs`
- Modify: `tests/tui_test.rs`

- [ ] **Step 1: Write failing tests**

Add to `tests/tui_test.rs`:
```rust
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
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cargo test menu_state_new_stores menu_state_navigate_new menu_state_change_provider 2>&1 | tail -20
```
Expected: compile errors.

- [ ] **Step 3: Add `MenuRow` enum and `MAIN_MENU_ROWS` to `src/tui/menu.rs`**

Add after the imports:
```rust
#[derive(Debug, Clone, Copy)]
enum MenuRow {
    Section(&'static str),
    Item { label: &'static str, action: usize },
}

const MAIN_MENU_ROWS: &[MenuRow] = &[
    MenuRow::Section("SCAN"),
    MenuRow::Item { label: "Run Full Scan",      action: 0 },
    MenuRow::Item { label: "Select Scanners",    action: 1 },
    MenuRow::Item { label: "View Last Results",  action: 2 },
    MenuRow::Section("PROVIDER"),
    MenuRow::Item { label: "Change Provider",    action: 3 },
    MenuRow::Item { label: "Add Provider",       action: 4 },
    MenuRow::Section("APP"),
    MenuRow::Item { label: "Exit",               action: 5 },
];
```

- [ ] **Step 4: Add new screens to `MenuScreen` enum in `src/tui/menu.rs`**

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MenuScreen {
    Main,
    ScannerSelector,
    ProviderSelector,
    ProviderForm,
}
```

- [ ] **Step 5: Add new fields to `MenuState` and update `new()` in `src/tui/menu.rs`**

Add to struct:
```rust
pub struct MenuState {
    pub selected_idx: usize,
    pub screen: MenuScreen,
    pub scanner_idx: usize,
    pub scanner_selected: [bool; 5],
    pub provider_configured: bool,
    pub project_configured: bool,
    // NEW:
    pub active_model: String,
    pub active_profile: String,
    pub profiles: Vec<(String, String)>,  // (profile_name, model)
    pub provider_idx: usize,
}
```

Update `MenuState::new`:
```rust
impl MenuState {
    pub fn new(
        provider_configured: bool,
        project_configured: bool,
        profiles: Vec<(String, String)>,
        active_model: String,
        active_profile: String,
    ) -> Self {
        Self {
            selected_idx: 0,
            screen: MenuScreen::Main,
            scanner_idx: 0,
            scanner_selected: [true; 5],
            provider_configured,
            project_configured,
            active_model,
            active_profile,
            profiles,
            provider_idx: 0,
        }
    }

    pub fn next(&mut self) {
        let max = match self.screen {
            MenuScreen::Main => 5,         // items 0-5
            MenuScreen::ScannerSelector => 5,
            MenuScreen::ProviderSelector | MenuScreen::ProviderForm => 0,
        };
        if self.selected_idx < max {
            self.selected_idx += 1;
        }
    }

    pub fn prev(&mut self) {
        if self.selected_idx > 0 {
            self.selected_idx -= 1;
        }
    }

    pub fn is_item_enabled(&self, idx: usize) -> bool {
        match idx {
            0 | 1 | 3 => self.provider_configured,  // Run Full Scan, Select Scanners, Change Provider
            _ => true,
        }
    }
    // ... rest unchanged ...
}
```

- [ ] **Step 6: Update `run_menu` and `run_menu_blocking` signatures in `src/tui/menu.rs`**

```rust
pub async fn run_menu(
    provider_configured: bool,
    project_configured: bool,
    profiles: Vec<(String, String)>,
    active_model: String,
    active_profile: String,
) -> Result<MenuAction> {
    tokio::task::spawn_blocking(move || {
        run_menu_blocking(provider_configured, project_configured, profiles, active_model, active_profile)
    })
    .await?
}

fn run_menu_blocking(
    provider_configured: bool,
    project_configured: bool,
    profiles: Vec<(String, String)>,
    active_model: String,
    active_profile: String,
) -> Result<MenuAction> {
    let mut terminal = ratatui::init();
    let mut state = MenuState::new(provider_configured, project_configured, profiles, active_model, active_profile);
    let result = run_menu_loop(&mut terminal, &mut state);
    ratatui::restore();
    result
}
```

- [ ] **Step 7: Add new `MenuAction` variants**

```rust
#[derive(Debug, Clone)]
pub enum MenuAction {
    RunScan(Vec<ScannerType>),
    ViewLastResults,
    ChangeProvider(String),   // profile name — from ProviderSelector
    ProviderAdded(String),    // newly created profile name — from ProviderForm
    Exit,
}
```

- [ ] **Step 8: Update `render_main_menu` in `src/tui/menu.rs` with Option C layout**

Replace the entire `render_main_menu` function:

```rust
fn render_main_menu(frame: &mut Frame, area: ratatui::layout::Rect, state: &MenuState) {
    use ratatui::text::{Line, Span, Text};
    use ratatui::layout::Alignment;

    let chunks = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(6),   // header block
        Constraint::Min(12),     // menu list
        Constraint::Length(1),   // key hints
        Constraint::Fill(1),
    ])
    .split(area);

    // ── Header block: banner left, version/model/profile right ──────────────
    let header_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = header_block.inner(chunks[1]);
    frame.render_widget(header_block, chunks[1]);

    let header_cols = Layout::horizontal([
        Constraint::Min(36),
        Constraint::Length(26),
    ])
    .split(inner);

    let banner_para = Paragraph::new(BANNER).style(Style::default().fg(Color::Cyan));
    frame.render_widget(banner_para, header_cols[0]);

    let warning = if !state.provider_configured {
        "\n⚠ No provider configured"
    } else {
        ""
    };
    let info = Text::from(vec![
        Line::from(vec![Span::styled(
            format!("v{}", env!("CARGO_PKG_VERSION")),
            Style::default().fg(Color::DarkGray),
        )]),
        Line::from(vec![Span::styled(
            state.active_model.chars().take(22).collect::<String>(),
            Style::default().fg(Color::Green),
        )]),
        Line::from(vec![Span::styled(
            state.active_profile.chars().take(22).collect::<String>(),
            Style::default().fg(Color::DarkGray),
        )]),
        Line::from(vec![Span::styled(
            warning.trim().to_string(),
            Style::default().fg(Color::Yellow),
        )]),
    ]);
    frame.render_widget(
        Paragraph::new(info).alignment(Alignment::Right),
        header_cols[1],
    );

    // ── Menu list with grouped sections ─────────────────────────────────────
    let items: Vec<ListItem> = MAIN_MENU_ROWS.iter().map(|row| {
        match row {
            MenuRow::Section(label) => {
                ListItem::new(format!("  {}", label))
                    .style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::ITALIC))
            }
            MenuRow::Item { label, action } => {
                let enabled = state.is_item_enabled(*action);
                let selected = state.selected_idx == *action;
                let prefix = if selected { "▶ " } else { "  " };
                let style = if !enabled {
                    Style::default().fg(Color::DarkGray)
                } else if selected {
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                ListItem::new(format!("{}{}", prefix, label)).style(style)
            }
        }
    }).collect();

    let list = List::new(items).block(Block::default().borders(Borders::ALL));
    let menu_area = Layout::horizontal([
        Constraint::Percentage(20),
        Constraint::Percentage(60),
        Constraint::Percentage(20),
    ])
    .split(chunks[2])[1];
    frame.render_widget(list, menu_area);

    let keys = Paragraph::new(" ↑↓ navigate · Enter select · q quit")
        .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(keys, chunks[3]);
}
```

- [ ] **Step 9: Update Main screen key handler in `run_menu_loop` for new indices**

In the `MenuScreen::Main` branch, update `KeyCode::Enter`:
```rust
MenuScreen::Main => match key.code {
    KeyCode::Up => state.prev(),
    KeyCode::Down => state.next(),
    KeyCode::Enter => {
        if !state.is_item_enabled(state.selected_idx) {
            continue;
        }
        match state.selected_idx {
            0 => {
                return Ok(MenuAction::RunScan(vec![
                    ScannerType::ThreatModel,
                    ScannerType::Sast,
                    ScannerType::SupplyChain,
                    ScannerType::ApiScan,
                    ScannerType::IacScan,
                    ScannerType::SecretsScan,
                    ScannerType::Report,
                ]));
            }
            1 => {
                state.screen = MenuScreen::ScannerSelector;
                state.scanner_idx = 0;
                state.selected_idx = 0;
            }
            2 => return Ok(MenuAction::ViewLastResults),
            3 => {
                state.screen = MenuScreen::ProviderSelector;
                state.provider_idx = 0;
            }
            4 => {
                state.screen = MenuScreen::ProviderForm;
            }
            5 => return Ok(MenuAction::Exit),
            _ => {}
        }
    }
    KeyCode::Char('q') => return Ok(MenuAction::Exit),
    _ => {}
},
```

- [ ] **Step 10: Run tests**

```bash
cargo test menu_state_new_stores menu_state_navigate_new menu_state_change_provider 2>&1 | tail -20
```
Expected: all 3 tests PASS.

- [ ] **Step 11: Update broken existing menu tests in `tests/tui_test.rs`**

Fix the 3 existing `MenuState::new` calls (they now need 5 args):
```rust
// menu_state_starts_at_first_item
let state = MenuState::new(true, true, vec![], String::new(), String::new());

// menu_state_navigate_wraps — update comment and assertions:
// 6 items: 0=RunFull, 1=SelectScanners, 2=ViewResults, 3=ChangeProvider, 4=AddProvider, 5=Exit
let mut state = MenuState::new(true, true, vec![], String::new(), String::new());
state.next(); assert_eq!(state.selected_idx, 1);
state.next(); state.next(); state.next(); state.next();
assert_eq!(state.selected_idx, 5);
state.next(); // clamp
assert_eq!(state.selected_idx, 5);
state.prev();
assert_eq!(state.selected_idx, 4);

// menu_state_disabled_items_when_unconfigured
let state = MenuState::new(false, false, vec![], String::new(), String::new());
assert!(!state.is_item_enabled(0)); // RunFull
assert!(!state.is_item_enabled(1)); // SelectScanners
assert!(state.is_item_enabled(2));  // ViewResults
assert!(!state.is_item_enabled(3)); // ChangeProvider
assert!(state.is_item_enabled(4));  // AddProvider
assert!(state.is_item_enabled(5));  // Exit

// menu_state_scanner_selector_toggle and menu_state_scanner_selector_selected_types
let mut state = MenuState::new(true, true, vec![], String::new(), String::new());
```

- [ ] **Step 12: Run all tests**

```bash
cargo test 2>&1 | tail -30
```
Expected: all tests pass.

- [ ] **Step 13: Commit**

```bash
git add src/tui/menu.rs tests/tui_test.rs
git commit -m "feat: Option C menu layout with grouped sections and new MenuAction variants"
```

---

## Task 5: Provider Selector Screen

**Files:**
- Modify: `src/tui/menu.rs`

- [ ] **Step 1: Add `render_provider_selector` to `src/tui/menu.rs`**

```rust
fn render_provider_selector(frame: &mut Frame, area: ratatui::layout::Rect, state: &MenuState) {
    let chunks = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(6),
        Constraint::Min(6),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .split(area);

    let header = Paragraph::new(BANNER)
        .block(Block::default().borders(Borders::ALL))
        .style(Style::default().fg(Color::Cyan));
    frame.render_widget(header, chunks[1]);

    let items: Vec<ListItem> = state.profiles.iter().enumerate().map(|(i, (name, model))| {
        let selected = state.provider_idx == i;
        let is_active = *name == state.active_profile;
        let bullet = if is_active { "●" } else { " " };
        let prefix = if selected { "▶" } else { " " };
        let style = if selected {
            Style::default().add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        let bullet_style = Style::default().fg(if is_active { Color::Green } else { Color::DarkGray });
        use ratatui::text::{Line, Span};
        ListItem::new(Line::from(vec![
            Span::raw(format!("{} ", prefix)),
            Span::styled(format!("{} ", bullet), bullet_style),
            Span::styled(format!("{:<20}", name.chars().take(20).collect::<String>()), style.clone()),
            Span::styled(
                model.chars().take(20).collect::<String>(),
                Style::default().fg(Color::DarkGray),
            ),
        ]))
    }).collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("SELECT PROVIDER"));
    let list_area = Layout::horizontal([
        Constraint::Percentage(10),
        Constraint::Percentage(80),
        Constraint::Percentage(10),
    ])
    .split(chunks[2])[1];
    frame.render_widget(list, list_area);

    let keys = Paragraph::new(" ↑↓ navigate · Enter select · Esc back")
        .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(keys, chunks[3]);
}
```

- [ ] **Step 2: Add `ProviderSelector` key handler in `run_menu_loop`**

In the `match state.screen` block, add after `ScannerSelector`:
```rust
MenuScreen::ProviderSelector => match key.code {
    KeyCode::Up => {
        if state.provider_idx > 0 {
            state.provider_idx -= 1;
        }
    }
    KeyCode::Down => {
        if state.provider_idx + 1 < state.profiles.len() {
            state.provider_idx += 1;
        }
    }
    KeyCode::Enter => {
        if let Some((name, _)) = state.profiles.get(state.provider_idx) {
            return Ok(MenuAction::ChangeProvider(name.clone()));
        }
    }
    KeyCode::Esc => {
        state.screen = MenuScreen::Main;
        state.selected_idx = 3; // restore to "Change Provider" row
    }
    _ => {}
},
```

- [ ] **Step 3: Add `ProviderSelector` branch to `render_menu`**

```rust
fn render_menu(frame: &mut Frame, state: &MenuState) {
    let area = frame.area();
    match state.screen {
        MenuScreen::Main => render_main_menu(frame, area, state),
        MenuScreen::ScannerSelector => render_scanner_selector(frame, area, state),
        MenuScreen::ProviderSelector => render_provider_selector(frame, area, state),
        MenuScreen::ProviderForm => render_provider_form(frame, area, state), // added in Task 6
    }
}
```

- [ ] **Step 4: Run all tests**

```bash
cargo test 2>&1 | tail -30
```
Expected: all tests pass (no compile errors from new match arms — `render_provider_form` stub not yet written; add a temporary stub if needed).

Temporary stub if compiler complains:
```rust
fn render_provider_form(frame: &mut Frame, area: ratatui::layout::Rect, state: &MenuState) {
    let _ = (frame, area, state);
}
```

- [ ] **Step 5: Commit**

```bash
git add src/tui/menu.rs
git commit -m "feat: add ProviderSelector TUI screen for changing active provider"
```

---

## Task 6: Provider Add Form — `ProviderFormState` + TUI screen

**Files:**
- Modify: `src/wizard/mod.rs`
- Modify: `src/tui/menu.rs`
- Modify: `tests/tui_test.rs`

- [ ] **Step 1: Export `KNOWN_PROVIDER_NAMES` from `src/wizard/mod.rs`**

Add before `provider_defaults`:
```rust
pub const KNOWN_PROVIDER_NAMES: &[&str] =
    &["anthropic", "openai", "cerebras", "litellm", "ollama", "zhipu"];
```

- [ ] **Step 2: Write failing tests**

Add to `tests/tui_test.rs`:
```rust
use zentra_cli::tui::menu::ProviderFormState;

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
    let mut form = ProviderFormState::default();
    form.focused_field = 3; // api_key field
    form.append_char('s');
    form.append_char('k');
    assert_eq!(form.api_key, "sk");
}

#[test]
fn provider_form_backspace_removes_last_char() {
    let mut form = ProviderFormState::default();
    form.focused_field = 4; // profile_name
    form.profile_name = "test".to_string();
    form.backspace();
    assert_eq!(form.profile_name, "tes");
}

#[test]
fn provider_form_cycle_provider_updates_defaults() {
    let mut form = ProviderFormState::default();
    let initial_model = form.model.clone();
    form.cycle_provider(1); // next provider
    // provider changed, model should reflect new provider defaults
    assert_eq!(form.provider_idx, 1);
    // model may differ
    let _ = initial_model;
}

#[test]
fn provider_form_masked_key_shows_prefix_only() {
    let mut form = ProviderFormState::default();
    form.api_key = "sk-ant-abc123xyz".to_string();
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
```

- [ ] **Step 3: Run tests to confirm they fail**

```bash
cargo test provider_form 2>&1 | tail -20
```
Expected: compile errors (`ProviderFormState` not found).

- [ ] **Step 4: Add `ProviderFormState` to `src/tui/menu.rs`**

First, add to the top-level imports in `src/tui/menu.rs`:
```rust
use crate::wizard::{provider_defaults, KNOWN_PROVIDER_NAMES};
```

Then add the struct after imports, before `MenuState`:
```rust
use crate::wizard::{provider_defaults, KNOWN_PROVIDER_NAMES}; // already added above, skip if present

#[derive(Debug, Clone)]
pub struct ProviderFormState {
    pub provider_idx: usize,
    pub model: String,
    pub base_url: String,
    pub api_key: String,
    pub profile_name: String,
    pub focused_field: usize,  // 0=provider, 1=model, 2=base_url, 3=api_key, 4=name, 5=save
    pub error: Option<String>,
}

impl Default for ProviderFormState {
    fn default() -> Self {
        let name = KNOWN_PROVIDER_NAMES[0];
        let d = provider_defaults(name);
        Self {
            provider_idx: 0,
            model: d.models.first().cloned().unwrap_or_default(),
            base_url: d.base_url,
            api_key: String::new(),
            profile_name: name.to_string(),
            focused_field: 0,
            error: None,
        }
    }
}

impl ProviderFormState {
    pub fn cycle_provider(&mut self, delta: isize) {
        let len = KNOWN_PROVIDER_NAMES.len() as isize;
        let new_idx = ((self.provider_idx as isize + delta).rem_euclid(len)) as usize;
        self.provider_idx = new_idx;
        let name = KNOWN_PROVIDER_NAMES[new_idx];
        let d = provider_defaults(name);
        self.model = d.models.first().cloned().unwrap_or_default();
        self.base_url = d.base_url;
        self.profile_name = name.to_string();
        self.error = None;
    }

    pub fn append_char(&mut self, c: char) {
        match self.focused_field {
            1 => self.model.push(c),
            2 => self.base_url.push(c),
            3 => self.api_key.push(c),
            4 => self.profile_name.push(c),
            _ => {}
        }
    }

    pub fn backspace(&mut self) {
        match self.focused_field {
            1 => { self.model.pop(); }
            2 => { self.base_url.pop(); }
            3 => { self.api_key.pop(); }
            4 => { self.profile_name.pop(); }
            _ => {}
        }
    }

    pub fn masked_key(&self) -> String {
        if self.api_key.len() <= 6 {
            "*".repeat(self.api_key.len())
        } else {
            format!("{}{}", &self.api_key[..6], "*".repeat(self.api_key.len() - 6))
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.profile_name.trim().is_empty() {
            anyhow::bail!("Profile name cannot be empty");
        }
        if self.model.trim().is_empty() {
            anyhow::bail!("Model cannot be empty");
        }
        let d = provider_defaults(KNOWN_PROVIDER_NAMES[self.provider_idx]);
        if !d.keyless && self.api_key.trim().is_empty() {
            anyhow::bail!("API key cannot be empty for this provider");
        }
        Ok(())
    }

    pub fn save(&self) -> anyhow::Result<String> {
        use crate::config::{keychain, AuthMethod, GlobalConfig, ProviderProfile};
        use crate::wizard::model_context_window;

        self.validate()?;

        let d = provider_defaults(KNOWN_PROVIDER_NAMES[self.provider_idx]);
        let cw = model_context_window(&self.model);

        let profile = ProviderProfile {
            kind: d.kind.clone(),
            base_url: self.base_url.clone(),
            model: self.model.clone(),
            keyless: d.keyless,
            auth_method: AuthMethod::ApiKey,
            context_window: Some(cw),
        };

        let mut global = GlobalConfig::load()?;
        global.profiles.insert(self.profile_name.clone(), profile);
        if global.default_profile.is_none() {
            global.default_profile = Some(self.profile_name.clone());
        }
        global.save()?;

        if !d.keyless && !self.api_key.is_empty() {
            keychain::set_key(&self.profile_name, &self.api_key)?;
        }

        Ok(self.profile_name.clone())
    }
}
```

Also add `pub form: ProviderFormState` to `MenuState` struct and initialize it in `new()`:
```rust
pub form: ProviderFormState,
// In new():
form: ProviderFormState::default(),
```

- [ ] **Step 5: Run the new tests**

```bash
cargo test provider_form 2>&1 | tail -20
```
Expected: all 6 tests PASS.

- [ ] **Step 6: Add `render_provider_form` to `src/tui/menu.rs`** (replaces the stub from Task 5)

```rust
fn render_provider_form(frame: &mut Frame, area: ratatui::layout::Rect, state: &MenuState) {
    use ratatui::text::{Line, Span};

    let form = &state.form;
    let provider_name = KNOWN_PROVIDER_NAMES[form.provider_idx];

    let field_style = |field_idx: usize| -> Style {
        if form.focused_field == field_idx {
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        }
    };

    let fields = vec![
        Line::from(vec![
            Span::raw("  Provider   "),
            Span::styled(format!("◀ {:<18} ▶", provider_name), field_style(0)),
        ]),
        Line::from(vec![
            Span::raw("  Model      "),
            Span::styled(format!("[{:<20}]", form.model.chars().take(20).collect::<String>()), field_style(1)),
        ]),
        Line::from(vec![
            Span::raw("  Base URL   "),
            Span::styled(format!("[{:<20}]", form.base_url.chars().take(20).collect::<String>()), field_style(2)),
        ]),
        Line::from(vec![
            Span::raw("  API Key    "),
            Span::styled(format!("[{:<20}]", form.masked_key().chars().take(20).collect::<String>()), field_style(3)),
        ]),
        Line::from(vec![
            Span::raw("  Name       "),
            Span::styled(format!("[{:<20}]", form.profile_name.chars().take(20).collect::<String>()), field_style(4)),
        ]),
        Line::from(Span::raw("")),
        Line::from(Span::styled("  ──────────────────────────────────────", Style::default().fg(Color::DarkGray))),
        Line::from(vec![
            Span::styled(
                if form.focused_field == 5 { "  ▶ Save" } else { "    Save" },
                field_style(5),
            ),
            Span::styled("          Esc Cancel", Style::default().fg(Color::DarkGray)),
        ]),
    ];

    let mut all_lines = fields;
    if let Some(ref err) = form.error {
        all_lines.push(Line::from(Span::styled(
            format!("  ✗ {}", err),
            Style::default().fg(Color::Red),
        )));
    }

    let content = ratatui::text::Text::from(all_lines);
    let paragraph = Paragraph::new(content)
        .block(Block::default().borders(Borders::ALL).title(" ADD PROVIDER ").title_style(Style::default().fg(Color::Cyan)));

    let form_area = Layout::horizontal([
        Constraint::Percentage(15),
        Constraint::Percentage(70),
        Constraint::Percentage(15),
    ])
    .split(Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(14),
        Constraint::Fill(1),
    ]).split(area)[1])[1];

    frame.render_widget(paragraph, form_area);
}
```

- [ ] **Step 7: Add `ProviderForm` key handler in `run_menu_loop`**

Add after `ProviderSelector` branch:
```rust
MenuScreen::ProviderForm => match key.code {
    KeyCode::Left => {
        if state.form.focused_field == 0 {
            state.form.cycle_provider(-1);
        }
    }
    KeyCode::Right => {
        if state.form.focused_field == 0 {
            state.form.cycle_provider(1);
        }
    }
    KeyCode::Tab | KeyCode::Down => {
        state.form.focused_field = (state.form.focused_field + 1) % 6;
    }
    KeyCode::BackTab | KeyCode::Up => {
        state.form.focused_field = state.form.focused_field.saturating_sub(1);
    }
    KeyCode::Char(c) => {
        state.form.append_char(c);
    }
    KeyCode::Backspace => {
        state.form.backspace();
    }
    KeyCode::Enter => {
        if state.form.focused_field == 5 {
            match state.form.save() {
                Ok(name) => return Ok(MenuAction::ProviderAdded(name)),
                Err(e) => state.form.error = Some(e.to_string()),
            }
        } else {
            state.form.focused_field = (state.form.focused_field + 1) % 6;
        }
    }
    KeyCode::Esc => {
        state.screen = MenuScreen::Main;
        state.selected_idx = 4; // restore to "Add Provider" row
        state.form = ProviderFormState::default(); // reset
    }
    _ => {}
},
```

- [ ] **Step 8: Run all tests**

```bash
cargo test 2>&1 | tail -30
```
Expected: all tests pass.

- [ ] **Step 9: Commit**

```bash
git add src/wizard/mod.rs src/tui/menu.rs tests/tui_test.rs
git commit -m "feat: full-TUI provider add form with ProviderFormState and ProviderForm screen"
```

---

## Task 7: `main.rs` Wire-up

**Files:**
- Modify: `src/main.rs`

- [ ] **Step 1: Update `main.rs` menu loop**

Replace the existing TUI menu loop with:

```rust
if std::env::args().len() == 1 {
    loop {
        // Reload config every iteration so menu reflects any changes
        let global = crate::config::GlobalConfig::load().unwrap_or_default();
        let provider_configured = !global.profiles.is_empty();
        let project_configured = ProjectConfig::load_from(&ProjectConfig::default_path()).is_ok();
        let profiles: Vec<(String, String)> = global.profiles
            .iter()
            .map(|(name, p)| (name.clone(), p.model.clone()))
            .collect();
        let active_profile = global.default_profile.clone().unwrap_or_default();
        let active_model = global.profiles.get(&active_profile)
            .map(|p| p.model.clone())
            .unwrap_or_default();

        match run_menu(provider_configured, project_configured, profiles, active_model, active_profile).await? {
            MenuAction::RunScan(scanners) => {
                commands::scan::run_with_scanners(scanners).await?;
                break;
            }
            MenuAction::ViewLastResults => {
                zentra_cli::tui::results::run_results().await?;
            }
            MenuAction::ChangeProvider(name) | MenuAction::ProviderAdded(name) => {
                commands::config::use_profile(&name).await?;
                // loop continues; GlobalConfig reloaded at top of next iteration
            }
            MenuAction::Exit => break,
        }
    }
    return Ok(());
}
```

Add the `GlobalConfig` import at the top of `main.rs` if not already present:
```rust
use zentra_cli::config::{GlobalConfig, ProjectConfig};
```

Remove the now-unused `MenuAction::Config` import/handling and the old `wizard::run_setup` call in the menu loop (the CLI `Config` command branch below still uses wizard).

- [ ] **Step 2: Build to catch compile errors**

```bash
cargo build 2>&1 | head -40
```
Expected: clean build. Fix any "non-exhaustive patterns" or unused import warnings.

- [ ] **Step 3: Run all tests**

```bash
cargo test 2>&1 | tail -30
```
Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/main.rs
git commit -m "feat: wire main.rs menu loop for new MenuAction variants and GlobalConfig reload"
```

---

## Task 8: Final Polish — clean build, test suite, smoke check

**Files:**
- Modify: `tests/tui_test.rs` (any remaining fixups)

- [ ] **Step 1: Full clean build**

```bash
cargo build --release 2>&1 | tail -20
```
Expected: zero errors, zero warnings (fix any that appear).

- [ ] **Step 2: Run full test suite**

```bash
cargo test 2>&1
```
Expected: all tests pass, no test is ignored.

- [ ] **Step 3: Verify `cargo clippy` is clean**

```bash
cargo clippy -- -D warnings 2>&1 | head -40
```
Fix any warnings before continuing.

- [ ] **Step 4: Manual smoke test — main menu**

Run `cargo run` in a terminal. Verify:
- Option C layout: logo left, version/model/profile right
- SCAN / PROVIDER / APP section labels appear
- "Change Provider" is greyed if no provider configured
- "Add Provider" is always enabled
- Arrow keys navigate (skipping section labels)

- [ ] **Step 5: Manual smoke test — provider form**

From main menu, navigate to "Add Provider" and press Enter. Verify:
- Form appears with ADD PROVIDER border
- Tab cycles through fields (Provider, Model, Base URL, API Key, Name, Save)
- Left/Right on Provider field cycles through known providers (anthropic → openai → ...)
- Selecting a new provider auto-fills Model, Base URL, Name
- Typing in text fields appends characters
- Backspace removes last character
- API Key field shows masked display (`sk-ant-***...`)
- Esc returns to main menu without saving

- [ ] **Step 6: Manual smoke test — provider selector**

From main menu, select "Change Provider" (requires an existing provider). Verify:
- Full-screen list shows configured profiles
- Active profile has `●` in green
- Arrow keys navigate
- Enter returns to menu and reloads (active provider updates in header)
- Esc returns without changing

- [ ] **Step 7: Manual smoke test — scan UI**

Run a scan. Verify:
- Top-right panel shows `project-name / ⎇ branch / vX.Y.Z`
- Timer shows "Hacked in Xs" and does NOT increment after scan completes
- Press `p` during scan, then "Abort Scan" — all running scanners show `✗`, animation stops
- After scan completes, press `p` — "Abort Scan" is NOT in the popup menu

- [ ] **Step 8: Final commit**

```bash
git add -A
git commit -m "feat: TUI polish complete — timer freeze, abort fix, header, menu redesign, provider TUI"
```
