# Scan UI Bug Fixes — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix 7 bugs in the TUI scan UI, results viewer, and main menu reported during live testing.

**Architecture:** Changes are purely within `src/tui/` — no new dependencies, no new files. Four files are modified; each task targets one file so subagents never conflict. Task 1 is the only one with a unit-testable bug (the parser); the rest are verified by running the binary.

**Tech Stack:** Rust · ratatui 0.29 · crossterm 0.28 · tokio

---

## File Map

```
Modified:
  src/tui/mod.rs       — Task 1: add scan_done field to UiState
  src/tui/scan_ui.rs   — Task 2: double-step fix, findings width, auto-close, logo height, detail pane size
  src/tui/results.rs   — Task 3: double-step fix, parser bug, findings width, detail pane size
  src/tui/menu.rs      — Task 4: center menu list

Modified (tests):
  tests/tui_test.rs    — Task 3: parser regression test
```

---

## Task 1: `mod.rs` — add `scan_done` to `UiState`

**Files:**
- Modify: `src/tui/mod.rs`

**Context:** `scan_ui.rs` (Task 2) needs a `scan_done: bool` field on `UiState` to track whether all scanners have finished, replacing the current auto-close-after-2s behaviour. Add the field here first so Task 2 can use it.

---

- [ ] **Step 1: Add `scan_done` field to `UiState` struct**

In `src/tui/mod.rs`, find the `UiState` struct (line 82) and add the field:

```rust
pub struct UiState {
    pub scanners: Vec<UiScanner>,
    pub findings: Vec<Finding>,
    pub activity: String,
    pub selected_idx: usize,
    pub total_tokens: u32,
    pub context_window: u32,
    pub model_info: String,
    pub popup_open: bool,
    pub popup: PopupState,
    pub scan_done: bool,   // ← add this line
}
```

- [ ] **Step 2: Initialise `scan_done` in `UiState::new`**

In the `new()` method (line 95), add `scan_done: false` to the `Self { … }` block:

```rust
Self {
    scanners,
    findings: Vec::new(),
    activity: String::new(),
    selected_idx: 0,
    total_tokens: 0,
    context_window,
    model_info,
    popup_open: false,
    popup: PopupState::new(),
    scan_done: false,   // ← add this line
}
```

- [ ] **Step 3: Build**

```
cargo build 2>&1 | tail -5
```

Expected: `Finished` with no errors. There will be an unused-field warning for `scan_done` until Task 2 uses it — that is fine.

- [ ] **Step 4: Commit**

```bash
git add src/tui/mod.rs
git commit -m "feat: add scan_done field to UiState for post-scan browse mode"
```

---

## Task 2: `scan_ui.rs` — five bug fixes

**Files:**
- Modify: `src/tui/scan_ui.rs`

**Context:** Five bugs live here. Read the current file in full before editing — the line numbers below match the file as of commit `dc1f937` (the spec commit). The bugs in order: (1) double-step navigation from missing KeyEventKind guard, (2) findings content not filling panel width, (3) scan auto-closes instead of letting user browse, (4) logo only shows top 2 lines because header too short, (5) detail pane too small.

**Prerequisites:** Task 1 must be complete (provides `UiState::scan_done`).

---

- [ ] **Step 1: Add `KeyEventKind` to the import**

Line 4 currently reads:
```rust
use crossterm::event::{Event, EventStream, KeyCode};
```

Replace with:
```rust
use crossterm::event::{Event, EventStream, KeyCode, KeyEventKind};
```

- [ ] **Step 2: Replace the key-event handler in `run_loop` (Bug 1 + Bug 4)**

The `run_loop` function currently (lines 44–85) has an `all_done()` auto-close block and no `KeyEventKind` guard. Replace the entire function body with:

```rust
async fn run_loop(
    terminal: &mut ratatui::DefaultTerminal,
    rx: &mut mpsc::Receiver<ScanEvent>,
    scanners: Vec<ScannerType>,
    model_info: String,
    context_window: u32,
) -> Result<ScanOutcome> {
    let mut state = UiState::new(scanners, model_info, context_window);
    let mut keys = EventStream::new();
    let mut ticker = tokio::time::interval(std::time::Duration::from_millis(80));

    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                state.apply_event(event);
            }
            Some(Ok(evt)) = keys.next() => {
                if let Event::Key(key) = evt {
                    if key.kind != KeyEventKind::Press {
                        // ignore release / repeat events to prevent double-step
                    } else if state.popup_open {
                        match key.code {
                            KeyCode::Esc => state.toggle_popup(),
                            KeyCode::Up => state.popup.prev(),
                            KeyCode::Down => state.popup.next(POPUP_ITEMS.len()),
                            KeyCode::Enter => {
                                match state.popup.selected {
                                    0 => return Ok(ScanOutcome::Reconfigure),
                                    1 => return Ok(ScanOutcome::Aborted),
                                    2 => return Ok(ScanOutcome::ExitApp),
                                    _ => {}
                                }
                            }
                            _ => {}
                        }
                    } else {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Esc => {
                                return Ok(if state.scan_done {
                                    ScanOutcome::Completed
                                } else {
                                    ScanOutcome::Aborted
                                });
                            }
                            KeyCode::Char('p') | KeyCode::Char('?') => state.toggle_popup(),
                            KeyCode::Down => state.select_next(),
                            KeyCode::Up => state.select_prev(),
                            _ => {}
                        }
                    }
                }
            }
            _ = ticker.tick() => {}
        }

        // Detect scan completion after any event (Bug 4)
        if state.all_done() && !state.scan_done {
            state.scan_done = true;
            state.activity = "✓ Scan complete — browse findings · q to exit".to_string();
        }

        terminal.draw(|f| render(f, &mut state))?;
    }
}
```

- [ ] **Step 3: Fix the vertical layout constraints (Bugs 6 + 8)**

In the `render` function (line 88), replace:

```rust
    let chunks = Layout::vertical([
        Constraint::Length(4),
        Constraint::Min(6),
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Length(1),
    ])
    .split(area);
```

with:

```rust
    let chunks = Layout::vertical([
        Constraint::Length(7),   // 4-line ASCII banner + model line + 2 borders
        Constraint::Min(6),
        Constraint::Length(1),
        Constraint::Length(8),   // detail: 6 inner rows for title/loc/desc/fix
        Constraint::Length(1),
    ])
    .split(area);
```

- [ ] **Step 4: Update `render_keys` signature and call to show done state**

Replace the `render_keys` function:

```rust
fn render_keys(frame: &mut Frame, area: Rect, popup_open: bool, scan_done: bool) {
    let text = if popup_open {
        " ↑↓ navigate · Enter select · Esc close"
    } else if scan_done {
        " ↑↓ select finding · q exit"
    } else {
        " ↑↓ navigate · p menu · q quit"
    };
    let paragraph = Paragraph::new(text).style(Style::default().fg(Color::DarkGray));
    frame.render_widget(paragraph, area);
}
```

Update the call inside `render` (was `render_keys(frame, chunks[4], state.popup_open)`):

```rust
    render_keys(frame, chunks[4], state.popup_open, state.scan_done);
```

- [ ] **Step 5: Fix findings width (Bug 3)**

Replace the `render_findings` function:

```rust
fn render_findings(frame: &mut Frame, area: Rect, state: &mut UiState) {
    let inner_width = area.width.saturating_sub(2) as usize; // subtract left+right border
    let items: Vec<ListItem> = state
        .findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let sev_color = match f.severity {
                crate::state::Severity::Critical => Color::Red,
                crate::state::Severity::High => Color::LightRed,
                crate::state::Severity::Medium => Color::Yellow,
                crate::state::Severity::Low => Color::Blue,
                crate::state::Severity::Info => Color::DarkGray,
            };
            let sev = format!("{}", f.severity);
            let loc = f.location.as_deref().unwrap_or("").chars().take(20).collect::<String>();
            let fixed = 8 + 8 + loc.len(); // sev col + scanner col + loc col
            let title_width = inner_width.saturating_sub(fixed).max(10);
            let title = f.title.chars().take(title_width).collect::<String>();
            let line = Line::from(vec![
                Span::styled(format!("{:<8}", sev), Style::default().fg(sev_color).add_modifier(Modifier::BOLD)),
                Span::raw(format!("{:<8}", f.scanner.chars().take(6).collect::<String>())),
                Span::raw(format!("{:<width$}", title, width = title_width)),
                Span::styled(loc, Style::default().fg(Color::DarkGray)),
            ]);
            let style = if i == state.selected_idx {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            ListItem::new(line).style(style)
        })
        .collect();

    let title = format!("FINDINGS — ALL ({})", state.total_findings());
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title));
    let mut list_state = ListState::default();
    if !state.findings.is_empty() {
        list_state.select(Some(state.selected_idx));
    }
    frame.render_stateful_widget(list, area, &mut list_state);
}
```

- [ ] **Step 6: Build**

```
cargo build 2>&1 | tail -5
```

Expected: `Finished` with no errors.

- [ ] **Step 7: Run full test suite**

```
cargo test 2>&1 | tail -5
```

Expected: all tests pass.

- [ ] **Step 8: Commit**

```bash
git add src/tui/scan_ui.rs
git commit -m "fix: scan UI navigation, logo, detail pane, findings width, post-scan browse"
```

---

## Task 3: `results.rs` — parser bug + double-step + width + detail pane

**Files:**
- Modify: `src/tui/results.rs`
- Modify: `tests/tui_test.rs`

**Context:** Four bugs here. The parser bug (Bug 5) is the only one with a unit test — write the failing test first. The other three are the same pattern as Task 2 fixes applied to the results viewer.

**Bug 5 root cause:** `StateWriter::write_finding` (in `src/state/mod.rs`) appends each block with `writeln!`, which adds an extra `\n` after `\n\n---\n`. So every block after the first starts with a blank line on disk. `parse_finding_block` reads `lines.next()` as `""`, strip_prefix fails, returns `None`. Fix: `.map(|b| b.trim())` after the split.

---

- [ ] **Step 1: Write the failing parser test**

Open `tests/tui_test.rs`. Add at the end of the file:

```rust
// ── Results Parser ─────────────────────────────────────────────────────────

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
```

- [ ] **Step 2: Run the test to confirm it fails**

```
cargo test --test tui_test parse_findings 2>&1 | tail -10
```

Expected: `FAILED` — assertion `expected 2 findings, got 1` or similar.

- [ ] **Step 3: Fix the parser**

In `src/tui/results.rs`, replace the `parse_findings` function (lines 15–20):

```rust
pub fn parse_findings(raw: &str) -> Vec<Finding> {
    raw.split("\n\n---\n")
        .map(|b| b.trim())
        .filter(|block| block.contains("## ["))
        .filter_map(parse_finding_block)
        .collect()
}
```

- [ ] **Step 4: Run the test to confirm it passes**

```
cargo test --test tui_test parse_findings 2>&1 | tail -5
```

Expected: `test parse_findings_returns_all_findings ... ok`

- [ ] **Step 5: Add `KeyEventKind` to the import and fix double-step (Bug 1)**

Line 5 currently reads:
```rust
use crossterm::event::{self, Event, KeyCode};
```

Replace with:
```rust
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
```

In `run_results_loop` (line 111), add a `KeyEventKind::Press` guard after the `if let Event::Key(key)` check:

```rust
fn run_results_loop(terminal: &mut ratatui::DefaultTerminal, state: &mut UiState) -> Result<()> {
    loop {
        terminal.draw(|f| render_results(f, state))?;
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Down => state.select_next(),
                    KeyCode::Up => state.select_prev(),
                    _ => {}
                }
            }
        }
    }
    Ok(())
}
```

- [ ] **Step 6: Fix the vertical layout constraints (Bug 8)**

In `render_results` (line 128), replace:

```rust
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(6),
        Constraint::Length(3),
        Constraint::Length(1),
    ])
    .split(area);
```

with:

```rust
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(6),
        Constraint::Length(8),   // detail: 6 inner rows
        Constraint::Length(1),
    ])
    .split(area);
```

- [ ] **Step 7: Fix findings width (Bug 3)**

Replace the `render_findings_list` function:

```rust
fn render_findings_list(frame: &mut Frame, area: ratatui::layout::Rect, state: &mut UiState) {
    let inner_width = area.width.saturating_sub(2) as usize;
    let items: Vec<ListItem> = state.findings.iter().enumerate().map(|(i, f)| {
        let sev_color = match f.severity {
            Severity::Critical => Color::Red,
            Severity::High => Color::LightRed,
            Severity::Medium => Color::Yellow,
            Severity::Low => Color::Blue,
            Severity::Info => Color::DarkGray,
        };
        let loc = f.location.as_deref().unwrap_or("").chars().take(20).collect::<String>();
        let fixed = 8 + 8 + loc.len();
        let title_width = inner_width.saturating_sub(fixed).max(10);
        let title = f.title.chars().take(title_width).collect::<String>();
        let line = Line::from(vec![
            Span::styled(format!("{:<8}", format!("{}", f.severity)), Style::default().fg(sev_color).add_modifier(Modifier::BOLD)),
            Span::raw(format!("{:<8}", f.scanner.chars().take(6).collect::<String>())),
            Span::raw(format!("{:<width$}", title, width = title_width)),
            Span::styled(loc, Style::default().fg(Color::DarkGray)),
        ]);
        let style = if i == state.selected_idx {
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default()
        };
        ListItem::new(line).style(style)
    }).collect();

    let title = format!("FINDINGS — ALL ({})", state.total_findings());
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title));
    let mut list_state = ListState::default();
    if !state.findings.is_empty() {
        list_state.select(Some(state.selected_idx));
    }
    frame.render_stateful_widget(list, area, &mut list_state);
}
```

- [ ] **Step 8: Run full test suite**

```
cargo test 2>&1 | tail -5
```

Expected: all tests pass.

- [ ] **Step 9: Commit**

```bash
git add src/tui/results.rs tests/tui_test.rs
git commit -m "fix: results parser returns all findings, double-step, width, detail pane"
```

---

## Task 4: `menu.rs` — center the menu list

**Files:**
- Modify: `src/tui/menu.rs`

**Context:** The main menu list renders full terminal-width. With short item text the bordered box has large blank margins on both sides. Fix: render the list inside a centered 60%-wide sub-layout of the menu area.

---

- [ ] **Step 1: Center the list in `render_main_menu`**

In `src/tui/menu.rs`, find `render_main_menu` (line 192). The current last lines build and render the list:

```rust
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(list, chunks[1]);
```

Replace those two lines with:

```rust
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL));
    let menu_area = Layout::horizontal([
        Constraint::Percentage(20),
        Constraint::Percentage(60),
        Constraint::Percentage(20),
    ])
    .split(chunks[1])[1];
    frame.render_widget(list, menu_area);
```

- [ ] **Step 2: Build**

```
cargo build 2>&1 | tail -5
```

Expected: `Finished` with no errors.

- [ ] **Step 3: Run full test suite**

```
cargo test 2>&1 | tail -5
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/tui/menu.rs
git commit -m "fix: center main menu list in viewport"
```

---

## Self-Review

### Spec coverage

| Bug | Spec section | Task |
|-----|-------------|------|
| 1 — double-step navigation | §2 Bug 1 | Tasks 2 + 3 |
| 2 — Enter / detail view | §2 Bug 2 | N/A (option B: always visible) |
| 3 — findings fill 50% | §2 Bug 3 | Tasks 2 + 3 |
| 4 — auto-close after scan | §2 Bug 4 | Task 2 |
| 5 — parser shows 1 result | §2 Bug 5 | Task 3 |
| 6 — logo broken | §2 Bug 6 | Task 2 |
| 7 — menu empty | §2 Bug 7 | Task 4 |
| 8 — detail pane crumpled | §2 Bug 8 | Tasks 2 + 3 |

### Placeholder scan

None — all code blocks are complete.

### Type consistency

- `UiState::scan_done: bool` — defined Task 1, used Task 2
- `render_keys(frame, area, popup_open, scan_done)` — signature changed Task 2, call site updated same task
- `parse_findings` — signature unchanged, only body changed
- `inner_width` / `title_width` / `fixed` — local variables, consistent in both Task 2 and Task 3
