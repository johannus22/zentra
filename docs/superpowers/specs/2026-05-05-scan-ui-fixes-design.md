# Scan UI Bug Fixes — Design Spec

**Date:** 2026-05-05
**Status:** Approved
**Author:** Rafael (Kodecraft Dev)

---

## 1. Overview

Seven bugs in the TUI scan UI and related screens, all found during live testing with litellm. The fixes touch four files: `src/tui/scan_ui.rs`, `src/tui/mod.rs`, `src/tui/results.rs`, and `src/tui/menu.rs`.

---

## 2. Bug Fixes

### Bug 1 — Double-step navigation

**Files:** `src/tui/scan_ui.rs`, `src/tui/results.rs`

**Root cause:** Crossterm fires `KeyEvent` for both `KeyEventKind::Press` and `KeyEventKind::Release`. The menu (`menu.rs`) already guards with `if key.kind != KeyEventKind::Press { continue; }`. The scan UI and results viewer do not, so every Up/Down keystroke fires twice — once for press, once for release — skipping every other index.

**Fix:** Add `if key.kind != KeyEventKind::Press { continue; }` to the key handler in both `run_loop` (scan_ui.rs) and `run_results_loop` (results.rs). Import `KeyEventKind` from `crossterm::event` in both files.

---

### Bug 2 — Enter key / detail view

**Files:** `src/tui/scan_ui.rs`

**Resolution:** With option B chosen (always-visible detail pane), navigating with Up/Down auto-updates the detail. No Enter interaction is required for detail viewing. The detail pane fix (Bug 8) makes it usable. No Enter handler needs to be added.

The key hint line stays as `"↑↓ navigate · p menu · q quit"` with a `[DONE]` suffix appended after scan completes (see Bug 4).

---

### Bug 3 — Findings fill only ~50% of the panel width

**Files:** `src/tui/scan_ui.rs` (`render_findings`), `src/tui/results.rs` (`render_findings_list`)

**Root cause:** Row spans use fixed widths: severity (8) + scanner (8) + title (32) + location (up to 20) = 68 chars. On terminals wider than ~100 chars the title column leaves a large blank gap on the right side of the findings panel.

**Fix:** In both `render_findings` and `render_findings_list`, compute the available inner width at render time from `area.width` and make the title column fill the remaining space:

```rust
let inner_width = area.width.saturating_sub(2) as usize; // subtract borders
let loc_str = f.location.as_deref().unwrap_or("").chars().take(20).collect::<String>();
let fixed = 8 + 8 + loc_str.len();
let title_width = inner_width.saturating_sub(fixed).max(10);
let title = f.title.chars().take(title_width).collect::<String>();
// spans: {:<8} sev, {:<8} scanner, {:<title_width} title, loc_str
```

---

### Bug 4 — Scan auto-closes 2 seconds after completion

**Files:** `src/tui/scan_ui.rs` (`run_loop`)

**Root cause:** When `state.all_done()` becomes true, the code draws the final frame, sleeps 2 seconds, and returns `ScanOutcome::Completed` — no user input required.

**Fix:**
- Remove the `all_done() → sleep → return` block entirely.
- Track scan completion in `UiState` with a `scan_done: bool` field (set to `true` when `all_done()` first becomes true after receiving an event).
- Update the activity line to `"✓ Scan complete — browse findings · q to exit"` once done.
- Change the `'q'` / `Esc` key handler: return `ScanOutcome::Completed` when `state.scan_done`, `ScanOutcome::Aborted` otherwise. This preserves the behavior in `scan.rs` (Completed → await scan task + print summary; Aborted → abort task).

---

### Bug 5 — View last results shows only 1 finding

**Files:** `src/tui/results.rs` (`parse_findings`)

**Root cause:** `StateWriter::write_finding` appends each finding as:
```
## [SEV] title\n...\n\n---\n
```
…and `writeln!` adds one more `\n`. So the file on disk is:
```
## [HIGH] Finding 1\n...\n\n---\n\n## [MEDIUM] Finding 2\n...
```
`parse_findings` splits on `"\n\n---\n"`, producing a second block that starts with `"\n## [MEDIUM]…"`. `parse_finding_block` reads the first line (`""`), finds no `##` header, and returns `None`. Only the first block succeeds.

**Fix:** Add `.map(|b| b.trim())` after the split call:

```rust
pub fn parse_findings(raw: &str) -> Vec<Finding> {
    raw.split("\n\n---\n")
        .map(|b| b.trim())
        .filter(|block| block.contains("## ["))
        .filter_map(parse_finding_block)
        .collect()
}
```

---

### Bug 6 — Zentra logo only shows top portion

**Files:** `src/tui/scan_ui.rs` (`render`, `render_header`)

**Root cause:** The ASCII banner is 4 lines tall. Combined with the model/tokens line, `render_header` needs 5 inner rows. With `Borders::ALL` that is 7 rows total. The current layout allocates `Constraint::Length(4)` — only 2 inner rows visible, cutting off lines 3–5 of the banner.

**Fix:** Change the first vertical constraint from `Constraint::Length(4)` to `Constraint::Length(7)`.

---

### Bug 7 — Main menu too empty / not centered

**Files:** `src/tui/menu.rs` (`render_main_menu`)

**Root cause:** The menu list renders at `chunks[1]` which spans the full terminal width. With short menu item text, the bordered box looks sparse and left-aligned.

**Fix:** Inside `render_main_menu`, split `chunks[1]` horizontally to center the list:

```rust
let menu_area = Layout::horizontal([
    Constraint::Percentage(20),
    Constraint::Percentage(60),
    Constraint::Percentage(20),
])
.split(chunks[1])[1]; // use the center column
frame.render_widget(list, menu_area);
```

The header banner and key hint line remain full-width.

---

### Bug 8 — Detail pane too small and crumpled

**Files:** `src/tui/scan_ui.rs` (`render`), `src/tui/results.rs` (`render_results`)

**Root cause:** Detail pane is `Constraint::Length(3)` → 1 inner row (3 − 2 borders). Long text wraps onto rows that aren't rendered, making all content appear on one line crammed to the left.

**Fix:** Change `Constraint::Length(3)` to `Constraint::Length(8)` in both the scan UI and results viewer vertical layouts. 6 inner rows fits: severity+title line, optional location line, 2–3 wrapped description lines, and the fix recommendation line — readable without dominating the viewport.

---

## 3. Files Changed

```
Modified:
  src/tui/scan_ui.rs   — Bugs 1, 3, 4, 6, 8
  src/tui/mod.rs       — Bug 4 (scan_done field on UiState)
  src/tui/results.rs   — Bugs 1, 3, 5, 8
  src/tui/menu.rs      — Bug 7
```

No new dependencies. No new files.

---

## 4. Testing

- **Bug 1:** Run scan; navigate with Up/Down — each press moves exactly one row.
- **Bug 3:** Run scan on a wide terminal (>120 cols); selected row highlight fills the full panel width.
- **Bug 4:** Let scan complete; UI stays open. Press `q` → returns to menu. Check that `scan.rs` prints `"✓ Scan complete. Findings in .zentra/"`.
- **Bug 5:** Run `zentra scan`, then `View Last Results` from the menu — all findings appear, not just 1.
- **Bug 6:** Open scan UI; all 4 lines of the ASCII logo + model/token line are visible.
- **Bug 7:** Open main menu; list is horizontally centered.
- **Bug 8:** Navigate findings; detail pane at bottom shows title, description, and fix recommendation without truncation.
