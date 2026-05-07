# TUI UX Polish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Nine UX and behavioral improvements to the zentra-cli TUI covering abort behavior, provider selection, token counter accuracy, viewport centering, findings deduplication/ordering, completion animation, version display, default context window, and version bump.

**Architecture:** All changes are contained in six files — no new files, no new dependencies. Tasks are ordered so the data layer (state, findings) comes first, then the scan UI behavioral changes, then the render/display changes, then menu centering, then housekeeping.

**Tech Stack:** Rust, ratatui 0.29, crossterm 0.28, tokio, clap 4

---

## File Map

| File | Changes |
|------|---------|
| `Cargo.toml` | version `0.1.55` → `0.2.0` |
| `src/state/finding.rs` | Add `Severity::order() -> u8` |
| `src/state/mod.rs` | Truncate `detailed-findings.md` in `StateWriter::new()` |
| `src/tui/mod.rs` | `ScanOutcome::ChangeProvider(String)`; `UiState` gains `scan_aborted`, `peak_input_tokens`, `scan_start`, `profiles`, `provider_popup_open`, `provider_popup`; sort findings on `FindingAdded`; fix `token_pct()` |
| `src/tui/scan_ui.rs` | `POPUP_ITEMS` → 4 items; `run_scan_ui` / `run_loop` accept `abort_handle` + `profiles`; popup handler wired to abort-in-place and provider sub-popup; `render_activity` completion states; `render_header` two-column layout with version |
| `src/tui/menu.rs` | Y-centering both screens; banner in scanner selector; centered item text; `env!` version string |
| `src/commands/scan.rs` | Pass `abort_handle` + `profiles` to `run_scan_ui`; `ChangeProvider` loop arm; default context window `256_000` |

---

### Task 1: Version Bump + Severity::order()

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/state/finding.rs`

- [ ] **Step 1: Bump version in Cargo.toml**

In `Cargo.toml`, change line 3:
```toml
version = "0.2.0"
```

- [ ] **Step 2: Add `order()` to Severity**

In `src/state/finding.rs`, after the `impl fmt::Display for Severity` block (after line 24), add:

```rust
impl Severity {
    pub fn order(&self) -> u8 {
        match self {
            Severity::Critical => 0,
            Severity::High     => 1,
            Severity::Medium   => 2,
            Severity::Low      => 3,
            Severity::Info     => 4,
        }
    }
}
```

- [ ] **Step 3: Verify it compiles**

```bash
cargo check
```

Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml src/state/finding.rs
git commit -m "feat: bump to v0.2.0, add Severity::order()"
```

---

### Task 2: Clear Findings File on New Scan

**Files:**
- Modify: `src/state/mod.rs:15-19`

- [ ] **Step 1: Truncate detailed-findings.md in StateWriter::new()**

Replace the `StateWriter::new()` function body (lines 15–19 in `src/state/mod.rs`):

```rust
pub fn new(project_root: &Path) -> Result<Self> {
    let zentra_dir = project_root.join(".zentra");
    fs::create_dir_all(&zentra_dir)?;
    fs::create_dir_all(zentra_dir.join("reports"))?;
    // Truncate findings file so each new scan starts clean
    let findings_path = zentra_dir.join("detailed-findings.md");
    if findings_path.exists() {
        OpenOptions::new().write(true).truncate(true).open(&findings_path)?;
    }
    Ok(Self { zentra_dir })
}
```

- [ ] **Step 2: Verify it compiles**

```bash
cargo check
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add src/state/mod.rs
git commit -m "fix: truncate detailed-findings.md at scan start to prevent accumulation"
```

---

### Task 3: UiState — New Fields + ScanOutcome::ChangeProvider

**Files:**
- Modify: `src/tui/mod.rs`

This task adds all new state fields at once so subsequent tasks can reference them.

- [ ] **Step 1: Add ChangeProvider variant to ScanOutcome**

In `src/tui/mod.rs`, replace the `ScanOutcome` enum (lines 8–14):

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanOutcome {
    Completed,
    Aborted,
    Reconfigure,
    ChangeProvider(String),
    ExitApp,
}
```

- [ ] **Step 2: Add new fields to UiState struct**

Replace the `UiState` struct definition (lines 82–94):

```rust
pub struct UiState {
    pub scanners: Vec<UiScanner>,
    pub findings: Vec<Finding>,
    pub activity: String,
    pub selected_idx: usize,
    pub peak_input_tokens: u32,
    pub total_tokens: u32,
    pub context_window: u32,
    pub model_info: String,
    pub popup_open: bool,
    pub popup: PopupState,
    pub scan_done: bool,
    pub scan_aborted: bool,
    pub animation_index: usize,
    pub scan_start: std::time::Instant,
    pub profiles: Vec<String>,
    pub provider_popup_open: bool,
    pub provider_popup: PopupState,
}
```

- [ ] **Step 3: Update UiState::new() to accept profiles and initialise all fields**

Replace `UiState::new()` (lines 97–115):

```rust
pub fn new(
    scanner_types: Vec<ScannerType>,
    model_info: String,
    context_window: u32,
    profiles: Vec<String>,
) -> Self {
    let scanners = scanner_types
        .iter()
        .map(|&t| UiScanner::new(t, t == ScannerType::Report))
        .collect();
    Self {
        scanners,
        findings: Vec::new(),
        activity: String::new(),
        selected_idx: 0,
        peak_input_tokens: 0,
        total_tokens: 0,
        context_window,
        model_info,
        popup_open: false,
        popup: PopupState::new(),
        scan_done: false,
        scan_aborted: false,
        animation_index: 0,
        scan_start: std::time::Instant::now(),
        profiles,
        provider_popup_open: false,
        provider_popup: PopupState::new(),
    }
}
```

- [ ] **Step 4: Update apply_event — TokensUsed and FindingAdded**

Replace the `TokensUsed` arm in `apply_event` (line 149–151):

```rust
ScanEvent::TokensUsed { input, output } => {
    self.total_tokens += input + output;
    if input > self.peak_input_tokens {
        self.peak_input_tokens = input;
    }
}
```

Replace the `FindingAdded` arm (lines 131–135):

```rust
ScanEvent::FindingAdded(f) => {
    if let Some(s) = self.scanners.iter_mut().find(|s| s.scanner_type.name() == f.scanner) {
        s.add_finding(&f.severity);
    }
    self.findings.push(f);
    self.findings.sort_by_key(|f| f.severity.order());
    self.selected_idx = self.selected_idx.min(self.findings.len().saturating_sub(1));
}
```

- [ ] **Step 5: Fix token_pct() to use peak_input_tokens**

Replace `token_pct()` (lines 181–186):

```rust
pub fn token_pct(&self) -> u16 {
    if self.context_window == 0 {
        return 0;
    }
    ((self.peak_input_tokens as f64 / self.context_window as f64) * 100.0).min(100.0) as u16
}
```

- [ ] **Step 6: Add toggle_provider_popup helper**

After `toggle_popup()` (line 193), add:

```rust
pub fn toggle_provider_popup(&mut self) {
    self.provider_popup_open = !self.provider_popup_open;
    if self.provider_popup_open {
        self.provider_popup = PopupState::new();
    }
}
```

- [ ] **Step 7: Verify it compiles**

```bash
cargo check
```

Expected: errors in `scan_ui.rs` and `scan.rs` because `UiState::new` signature changed — that's expected, will be fixed in Task 4.

- [ ] **Step 8: Commit**

```bash
git add src/tui/mod.rs
git commit -m "feat: add ScanOutcome::ChangeProvider, peak token tracking, scan_start, profiles to UiState"
```

---

### Task 4: scan_ui.rs — Abort Handle + Provider Sub-Popup + Popup Items

**Files:**
- Modify: `src/tui/scan_ui.rs`

- [ ] **Step 1: Update POPUP_ITEMS to 4 entries**

Replace lines 15–19:

```rust
pub const POPUP_ITEMS: &[&str] = &[
    "Change Provider",
    "Add Provider",
    "Abort Scan",
    "Exit App",
];
```

- [ ] **Step 2: Update run_scan_ui signature and body**

Replace lines 35–45:

```rust
pub async fn run_scan_ui(
    mut rx: mpsc::Receiver<ScanEvent>,
    scanners: Vec<ScannerType>,
    model_info: String,
    context_window: u32,
    abort_handle: tokio::task::AbortHandle,
    profiles: Vec<String>,
) -> Result<ScanOutcome> {
    let mut terminal = ratatui::init();
    let result = run_loop(
        &mut terminal, &mut rx, scanners, model_info, context_window, abort_handle, profiles,
    ).await;
    ratatui::restore();
    result
}
```

- [ ] **Step 3: Update run_loop signature and UiState construction**

Replace lines 47–54:

```rust
async fn run_loop(
    terminal: &mut ratatui::DefaultTerminal,
    rx: &mut mpsc::Receiver<ScanEvent>,
    scanners: Vec<ScannerType>,
    model_info: String,
    context_window: u32,
    abort_handle: tokio::task::AbortHandle,
    profiles: Vec<String>,
) -> Result<ScanOutcome> {
    let mut state = UiState::new(scanners, model_info, context_window, profiles);
```

- [ ] **Step 4: Wire up the popup key handler for 4 items**

Replace the `state.popup_open` branch in the key handler (lines 68–82). The full `else if state.popup_open` block becomes:

```rust
} else if state.provider_popup_open {
    match key.code {
        KeyCode::Esc => state.toggle_provider_popup(),
        KeyCode::Up => state.provider_popup.prev(),
        KeyCode::Down => state.provider_popup.next(state.profiles.len()),
        KeyCode::Enter => {
            if let Some(name) = state.profiles.get(state.provider_popup.selected) {
                return Ok(ScanOutcome::ChangeProvider(name.clone()));
            }
        }
        _ => {}
    }
} else if state.popup_open {
    match key.code {
        KeyCode::Esc => state.toggle_popup(),
        KeyCode::Up => state.popup.prev(),
        KeyCode::Down => state.popup.next(POPUP_ITEMS.len()),
        KeyCode::Enter => {
            match state.popup.selected {
                0 => {
                    // Change Provider — open in-TUI profile picker
                    state.toggle_popup();
                    state.toggle_provider_popup();
                }
                1 => {
                    // Add Provider — launch wizard
                    return Ok(ScanOutcome::Reconfigure);
                }
                2 => {
                    // Abort Scan — keep UI open
                    abort_handle.abort();
                    state.scan_aborted = true;
                    state.scan_done = true;
                    state.activity = "✗ Scan aborted — browse findings · q to exit".to_string();
                    state.toggle_popup();
                }
                3 => return Ok(ScanOutcome::ExitApp),
                _ => {}
            }
        }
        _ => {}
    }
```

- [ ] **Step 5: Update render() to render provider sub-popup**

In the `render` function (line 116), after `if state.popup_open { render_popup(...) }`, add:

```rust
if state.provider_popup_open {
    render_provider_popup(frame, area, &state.provider_popup, &state.profiles);
}
```

- [ ] **Step 6: Add render_provider_popup function**

After `render_popup` (after line 336), add:

```rust
fn render_provider_popup(
    frame: &mut Frame,
    area: Rect,
    popup: &crate::tui::PopupState,
    profiles: &[String],
) {
    if profiles.is_empty() {
        return;
    }
    let popup_width = 40u16;
    let popup_height = (profiles.len() as u16) + 4;
    let popup_area = centered_rect(popup_width, popup_height, area);

    frame.render_widget(Clear, popup_area);

    let items: Vec<ListItem> = profiles
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let prefix = if i == popup.selected { "▶ " } else { "  " };
            let style = if i == popup.selected {
                Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow)
            } else {
                Style::default()
            };
            ListItem::new(format!("{}{}", prefix, name)).style(style)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title("  SELECT PROVIDER  ")
            .title_style(Style::default().fg(Color::Cyan)),
    );
    frame.render_widget(list, popup_area);
}
```

- [ ] **Step 7: Verify it compiles**

```bash
cargo check
```

Expected: errors in `scan.rs` (wrong call to `run_scan_ui`) — fixed in Task 6.

- [ ] **Step 8: Commit**

```bash
git add src/tui/scan_ui.rs
git commit -m "feat: split popup into Change/Add Provider, abort-in-place, provider sub-popup"
```

---

### Task 5: render_activity Completion States + render_header Version

**Files:**
- Modify: `src/tui/scan_ui.rs`

- [ ] **Step 1: Rewrite render_activity to handle done/aborted/running states**

Replace the entire `render_activity` function (lines 260–286):

```rust
fn render_activity(frame: &mut Frame, area: Rect, state: &UiState) {
    let content = if state.scan_done {
        let (icon, icon_color, verb) = if state.scan_aborted {
            ("✗", Color::Red, "Aborted".to_string())
        } else {
            let elapsed = state.scan_start.elapsed();
            let secs = elapsed.as_secs();
            let duration = if secs >= 60 {
                format!("Hacked in {}m {}s", secs / 60, secs % 60)
            } else {
                format!("Hacked in {}s", secs)
            };
            ("✓", Color::Green, duration)
        };
        Line::from(vec![
            Span::styled(
                format!("{:<2}", icon),
                Style::default().fg(icon_color).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("{: <22}", verb),
                Style::default().fg(icon_color).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" {}", state.activity),
                Style::default().fg(Color::DarkGray).add_modifier(Modifier::ITALIC),
            ),
        ])
    } else {
        let animation_speed = 20;
        let word_index = (state.animation_index / animation_speed) % ACTIVITY_VERBS.len();
        let current_verb = ACTIVITY_VERBS[word_index];
        let speed = 1.676767_f64;
        let brightness = (state.animation_index as f64 * speed).sin();
        let pulse = ((brightness * 60.0) + 190.0) as u8;
        let glow_color = Color::Rgb(pulse, pulse, 255);
        Line::from(vec![
            Span::styled(
                format!("{:<2}", LOADING_FRAMES[state.animation_index % LOADING_FRAMES.len()]),
                Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("{: <22}", current_verb),
                Style::default().fg(glow_color).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" {}", state.activity),
                Style::default().fg(Color::DarkGray).add_modifier(Modifier::ITALIC),
            ),
        ])
    };
    frame.render_widget(Paragraph::new(content), area);
}
```

- [ ] **Step 2: Rewrite render_header with two-column layout and version**

Replace the entire `render_header` function (lines 138–168):

```rust
fn render_header(frame: &mut Frame, area: Rect, state: &UiState) {
    // Split header block into left (logo + tokens) and right (version)
    let cols = Layout::horizontal([
        Constraint::Min(40),
        Constraint::Length(12),
    ])
    .split(area);

    let banner = if area.width >= 80 {
        " ____        _ \n|_  /___ _ _| |_ _ _ __ _\n / // -_) ' \\  _| '_/ _` |\n/___\\___|_||_\\__|_| \\__,_|"
    } else {
        "ZENTRA"
    };

    let pct = state.token_pct();
    let bar_width = 10usize;
    let filled = (pct as usize * bar_width / 100).min(bar_width);
    let bar = format!(
        "[{}{}] {}%",
        "█".repeat(filled),
        "░".repeat(bar_width - filled),
        pct
    );

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

    let version_text = format!("v{}", env!("CARGO_PKG_VERSION"));
    let right = Paragraph::new(version_text)
        .block(Block::default().borders(Borders::ALL))
        .style(Style::default().fg(Color::DarkGray))
        .alignment(ratatui::layout::Alignment::Right);
    frame.render_widget(right, cols[1]);
}
```

- [ ] **Step 3: Add Alignment to imports**

In the imports at the top of `scan_ui.rs`, add `Alignment` to the ratatui layout imports:

```rust
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    ...
```

- [ ] **Step 4: Verify it compiles**

```bash
cargo check
```

Expected: still errors in `scan.rs` (wrong `run_scan_ui` call) — fixed in Task 6.

- [ ] **Step 5: Commit**

```bash
git add src/tui/scan_ui.rs
git commit -m "feat: completion animation 'Hacked in X', version in header, peak token display"
```

---

### Task 6: scan.rs — Wire abort_handle + profiles + ChangeProvider + 256K default

**Files:**
- Modify: `src/commands/scan.rs`

- [ ] **Step 1: Add provider_override tracking to run_with_scanners**

Replace `run_with_scanners` (lines 34–46):

```rust
pub async fn run_with_scanners(scanners: Vec<ScannerType>) -> Result<()> {
    let depth = HistoryDepth::default();
    let mut provider_override: Option<String> = None;
    loop {
        match run_once(provider_override.clone(), scanners.clone(), depth.clone()).await? {
            ScanOutcome::Completed | ScanOutcome::Aborted => break,
            ScanOutcome::Reconfigure => {
                wizard::run_setup(None).await?;
            }
            ScanOutcome::ChangeProvider(name) => {
                provider_override = Some(name);
            }
            ScanOutcome::ExitApp => std::process::exit(0),
        }
    }
    Ok(())
}
```

- [ ] **Step 2: Add ChangeProvider arm to run()**

Replace the `run()` function loop body (lines 22–30):

```rust
loop {
    match run_once(provider_override.clone(), scanners.clone(), depth.clone()).await? {
        ScanOutcome::Completed | ScanOutcome::Aborted => break,
        ScanOutcome::Reconfigure => {
            wizard::run_setup(None).await?;
        }
        ScanOutcome::ChangeProvider(name) => {
            provider_override = Some(name);
        }
        ScanOutcome::ExitApp => std::process::exit(0),
    }
}
```

- [ ] **Step 3: Update run_once to pass abort_handle + profiles + 256K default**

Replace `run_once` from line 98 onwards (the three lines: `context_window`, `scan_task`, and `run_scan_ui` call), keeping everything before unchanged:

```rust
    let context_window = profile.context_window.unwrap_or(256_000);
    let model_info = format!("{} · {}", profile.model, profile_name);

    // Collect profile names for the in-TUI provider picker
    let profiles: Vec<String> = global.profiles.keys().cloned().collect();

    let (tx, rx) = mpsc::channel(128);
    let scanners_for_agent = scanners.clone();

    let scan_task = tokio::spawn(async move {
        OrchestratorAgent::new(provider, tool_registry, state_writer, tx, depth)
            .run(&scanners_for_agent)
            .await
    });

    let abort_handle = scan_task.abort_handle();
    let outcome = run_scan_ui(rx, scanners, model_info, context_window, abort_handle, profiles).await?;

    match outcome {
        ScanOutcome::Completed => {
            scan_task.await??;
            println!("\n✓ Scan complete. Findings in .zentra/");
        }
        _ => {
            scan_task.abort();
        }
    }

    Ok(outcome)
```

- [ ] **Step 4: Verify the build is clean**

```bash
cargo build
```

Expected: successful build, zero errors.

- [ ] **Step 5: Commit**

```bash
git add src/commands/scan.rs
git commit -m "feat: wire abort_handle, profiles, ChangeProvider loop arm, 256K default context window"
```

---

### Task 7: menu.rs — Viewport Centering + Scanner Selector Banner

**Files:**
- Modify: `src/tui/menu.rs`

- [ ] **Step 1: Replace render_main_menu with Y-centered layout + env! version**

Replace the entire `render_main_menu` function (lines 192–252):

```rust
fn render_main_menu(frame: &mut Frame, area: ratatui::layout::Rect, state: &MenuState) {
    // Banner height: 4 lines + subtitle + borders = 6 total
    // Menu height: 5 items + borders = 7 total
    // Keys: 1 line
    // Use Fill(1) top+bottom to center the content block vertically
    let chunks = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(6),
        Constraint::Min(7),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .split(area);

    let warning = if !state.provider_configured {
        "\n⚠  No provider configured — select Setup/Config to get started"
    } else {
        ""
    };
    let header_text = format!(
        "{}\nAI-powered Application Security · v{}{}",
        BANNER,
        env!("CARGO_PKG_VERSION"),
        warning
    );
    let header = Paragraph::new(header_text)
        .block(Block::default().borders(Borders::ALL))
        .style(Style::default().fg(Color::Cyan));
    frame.render_widget(header, chunks[1]);

    let menu_items = [
        "Run Full Scan",
        "Select Scanners",
        "View Last Results",
        "Setup / Config",
        "Exit",
    ];

    let items: Vec<ListItem> = menu_items
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let enabled = state.is_item_enabled(i);
            let selected = state.selected_idx == i;
            let prefix = if selected { "▶ " } else { "  " };
            let style = if !enabled {
                Style::default().fg(Color::DarkGray)
            } else if selected {
                Style::default().add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            ListItem::new(format!("{}{}", prefix, label)).style(style)
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL));
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

- [ ] **Step 2: Replace render_scanner_selector with Y-centered layout + banner**

Replace the entire `render_scanner_selector` function (lines 254–300):

```rust
fn render_scanner_selector(frame: &mut Frame, area: ratatui::layout::Rect, state: &MenuState) {
    // Banner: 6 rows, scanner list: 5 items + 3 extras + borders ≈ 10, keys: 1
    let chunks = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(6),
        Constraint::Min(10),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .split(area);

    let header = Paragraph::new(BANNER)
        .block(Block::default().borders(Borders::ALL))
        .style(Style::default().fg(Color::Cyan));
    frame.render_widget(header, chunks[1]);

    let scanner_names = [
        ("Threat Model", "STRIDE · attack surface · trust boundaries"),
        ("SAST", "OWASP Top 10 static analysis"),
        ("Supply Chain", "CVEs · deps · npm audit"),
        ("API Scan", "OWASP API Top 10 · OpenAPI"),
        ("IaC Scan", "Docker · Terraform · K8s"),
    ];

    let mut items: Vec<ListItem> = scanner_names
        .iter()
        .enumerate()
        .map(|(i, (name, desc))| {
            let check = if state.scanner_selected[i] { "✓" } else { " " };
            let selected = state.scanner_idx == i;
            let prefix = if selected { "▶" } else { " " };
            let style = if selected {
                Style::default().add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            ListItem::new(
                Line::from(vec![
                    Span::raw(format!("{} [{}] {:<16}", prefix, check, name)),
                    Span::styled(desc.to_string(), Style::default().fg(Color::DarkGray)),
                ])
            ).style(style)
        })
        .collect();

    items.push(ListItem::new("  ─────────────────────────────────────────")
        .style(Style::default().fg(Color::DarkGray)));
    items.push(ListItem::new("  [✓] Report              Always included   [locked]")
        .style(Style::default().fg(Color::DarkGray)));
    let run_label = format!(
        "▶ Run Selected ({} scanners)",
        state.scanner_selected.iter().filter(|&&b| b).count() + 1
    );
    let run_style = if state.scanner_idx == 5 {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    items.push(ListItem::new(run_label).style(run_style));

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("SELECT SCANNERS"));
    let list_area = Layout::horizontal([
        Constraint::Percentage(10),
        Constraint::Percentage(80),
        Constraint::Percentage(10),
    ])
    .split(chunks[2])[1];
    frame.render_widget(list, list_area);

    let keys = Paragraph::new(" Space toggle · Enter run · Esc back")
        .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(keys, chunks[3]);
}
```

- [ ] **Step 3: Full build check**

```bash
cargo build
```

Expected: clean build, zero warnings (other than any pre-existing ones).

- [ ] **Step 4: Commit**

```bash
git add src/tui/menu.rs
git commit -m "feat: Y-center main menu and scanner selector, add banner to scanner selector"
```

---

## Self-Review

**Spec coverage check:**

| Spec section | Covered by task |
|---|---|
| 2.1 Abort keeps UI open | Task 4 (abort_handle.abort() in popup, scan_aborted flag) |
| 2.2 Change vs Add Provider | Task 3 (ChangeProvider variant), Task 4 (popup split + sub-popup), Task 6 (loop arm) |
| 2.3 Peak input token counter | Task 3 (peak_input_tokens field + apply_event), Task 5 (render_header display) |
| 2.4 Menu viewport centering | Task 7 (Fill(1) + horizontal centering for both screens) |
| 2.5 Clear findings + sort | Task 2 (truncate file), Task 3 (sort on FindingAdded) |
| 2.6 Animation completion | Task 5 (render_activity done/aborted/running states) |
| 2.7 Version in scan UI header | Task 5 (render_header right column) |
| 2.8 Default context window 256K | Task 6 (unwrap_or(256_000)) |
| 2.9 Version bump | Task 1 (Cargo.toml) + Task 7 (env! in menu) |

All spec sections covered. No gaps.

**Type consistency:**
- `UiState::new()` gains a `profiles: Vec<String>` 4th argument — used in Task 3, consumed in Task 4 (`run_loop` passes it), and constructed in Task 6 (`scan.rs`). Consistent.
- `ScanOutcome::ChangeProvider(String)` — defined Task 3, matched in Task 4 (popup returns it), and matched in Task 6 (loop arm). Consistent.
- `abort_handle: tokio::task::AbortHandle` — created in Task 6 (`scan_task.abort_handle()`), passed to `run_scan_ui` in Task 4 (accepted in signature, called in popup). Consistent.
- `peak_input_tokens` — defined Task 3, displayed in Task 5. Consistent.
- `scan_start: std::time::Instant` — defined Task 3, read in Task 5 (`state.scan_start.elapsed()`). Consistent.
- `provider_popup_open`, `provider_popup` — defined Task 3, toggled/rendered in Task 4. Consistent.
- `render_provider_popup` takes `&[String]` — called with `&state.profiles` in Task 4. Consistent.

No placeholder content detected. All steps have complete code.
