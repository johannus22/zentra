# TUI UX Polish — Design Spec

**Date:** 2026-05-07
**Status:** Approved
**Author:** Rafael (Kodecraft Dev)

---

## 1. Overview

Nine UX and behavioral improvements to the zentra-cli TUI, discovered during live testing. The changes touch `src/tui/scan_ui.rs`, `src/tui/mod.rs`, `src/tui/menu.rs`, `src/commands/scan.rs`, `src/state/mod.rs`, and `Cargo.toml`.

---

## 2. Changes

### 2.1 — Abort Scan Keeps UI Open

**Files:** `src/commands/scan.rs`, `src/tui/scan_ui.rs`, `src/tui/mod.rs`

**Problem:** Selecting "Abort Scan" from the in-scan popup currently returns `ScanOutcome::Aborted`, which exits the TUI entirely and discards any findings that were already collected.

**Fix:** Pass `scan_task.abort_handle()` into `run_scan_ui`. When "Abort Scan" is selected, call `abort_handle.abort()` directly, set `state.scan_aborted = true` and `state.scan_done = true`, update the activity line to `"✗ Scan aborted — browse findings · q to exit"`, and close the popup — without returning from `run_loop`. The UI stays alive. When the scan task is aborted the mpsc sender drops and `rx.recv()` returns `None`; the loop handles this gracefully (no state change needed). The user presses `q` to exit, which returns `ScanOutcome::Aborted` as before. `run_once` then skips `scan_task.await??` (already aborted) and breaks.

`run_scan_ui` signature change:
```rust
pub async fn run_scan_ui(
    mut rx: mpsc::Receiver<ScanEvent>,
    scanners: Vec<ScannerType>,
    model_info: String,
    context_window: u32,
    abort_handle: tokio::task::AbortHandle,
    profiles: Vec<String>,
) -> Result<ScanOutcome>
```

`UiState` gains:
```rust
pub scan_aborted: bool,
```

---

### 2.2 — Provider Selection: Change vs Add

**Files:** `src/tui/scan_ui.rs`, `src/tui/mod.rs`, `src/commands/scan.rs`

**Problem:** "Change Model / Provider" in the scan popup always opens the wizard to add a new provider, making it impossible to switch to an already-configured profile without leaving the app.

**Fix:** Split into two separate popup items and add an in-TUI profile picker.

`POPUP_ITEMS` becomes:
```rust
pub const POPUP_ITEMS: &[&str] = &[
    "Change Provider",   // pick from existing profiles
    "Add Provider",      // wizard to add new
    "Abort Scan",
    "Exit App",
];
```

`ScanOutcome` gains:
```rust
ChangeProvider(String),   // profile name selected in-TUI
```

`run_scan_ui` receives `profiles: Vec<String>` (loaded from `GlobalConfig` in `run_once` before the scan starts). `UiState` stores this list and a secondary `provider_popup: PopupState` plus `provider_popup_open: bool`.

When the user selects "Change Provider" (index 0), close the main popup and open the secondary provider picker popup, rendering the profile list the same way as the main popup. Selecting a profile name returns `ScanOutcome::ChangeProvider(name)`.

In `run` and `run_with_scanners` (scan.rs), a new loop arm handles this outcome:
```rust
ScanOutcome::ChangeProvider(name) => {
    provider_override = Some(name);  // next run_once uses this profile
}
```
"Add Provider" returns `ScanOutcome::Reconfigure` as before.

---

### 2.3 — Token Counter: Peak Input per Call

**Files:** `src/tui/mod.rs`, `src/tui/scan_ui.rs`

**Problem:** `total_tokens` sums token usage across all parallel scanner agents over the entire scan. Since 5+ agents each make many calls, this rapidly exceeds the context window and the progress bar pegs at 100%, making it meaningless.

**Fix:** Track the maximum input token count seen in any single LLM call. This is directly comparable to the context window limit and answers "how close did the heaviest call get?".

`UiState` changes:
```rust
pub peak_input_tokens: u32,   // max input tokens in any single call
pub total_tokens: u32,        // cumulative total (informational)
```

`apply_event` for `TokensUsed`:
```rust
ScanEvent::TokensUsed { input, output } => {
    self.total_tokens += input + output;
    if input > self.peak_input_tokens {
        self.peak_input_tokens = input;
    }
}
```

`token_pct()` uses `peak_input_tokens`. Header display:
```
peak: {peak_input} / {context_window} [{bar}] {pct}%  total: {total}
```

---

### 2.4 — Menu and Scanner Selector: Viewport Centering

**Files:** `src/tui/menu.rs`

**Problem:** Both screens anchor content to the top of the terminal, leaving large dead space below. Menu items are crowded to the left inside the list box.

**Fix — Y-axis centering:** Both `render_main_menu` and `render_scanner_selector` use `Constraint::Fill(1)` top and bottom padding so content floats in the vertical center of the terminal:
```rust
let chunks = Layout::vertical([
    Constraint::Fill(1),   // top spacer
    Constraint::Length(6), // banner
    Constraint::Min(7),    // list content
    Constraint::Length(1), // key hints
    Constraint::Fill(1),   // bottom spacer
]).split(area);
```

**Fix — X-axis centering:** The existing 20/60/20 horizontal split is kept for X-centering. Menu item text is centered within the list box using `Alignment::Center` on the paragraph or by padding label strings symmetrically.

**Fix — Scanner selector gets banner:** `render_scanner_selector` prepends the `BANNER` block (same as main menu) above the scanner list, using the same layout pattern.

---

### 2.5 — Findings: Clear on New Scan + Sort by Severity

**Files:** `src/state/mod.rs`, `src/tui/mod.rs`

**Problem (clear):** `write_finding` appends to `detailed-findings.md` with `append(true)`. Re-running a scan accumulates findings from previous scans in the file indefinitely.

**Fix:** `StateWriter::new()` truncates `detailed-findings.md` at construction time:
```rust
let findings_path = zentra_dir.join("detailed-findings.md");
if findings_path.exists() {
    OpenOptions::new().write(true).truncate(true).open(&findings_path)?;
}
```
This runs once per scan at startup before any findings are written.

**Problem (order):** Findings appear in arrival order (interleaved from parallel scanners). Critical findings should appear first.

**Fix:** `Severity` gains an `order()` method returning `u8`:
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

`apply_event` for `FindingAdded` sorts after push:
```rust
self.findings.push(f);
self.findings.sort_by_key(|f| f.severity.order());
```

The `selected_idx` is clamped after sort to avoid stale selection.

---

### 2.6 — Animation: "Hacked in X" on Scan Completion

**Files:** `src/tui/scan_ui.rs`, `src/tui/mod.rs`

**Problem:** When the scan finishes, the animated braille spinner and rotating activity verbs keep running, giving no sense of completion.

**Fix:** `UiState` gains:
```rust
pub scan_start: std::time::Instant,
```
Set in `UiState::new()` to `Instant::now()`.

`render_activity` checks `state.scan_done`:
- **When done:** Replace the spinner with `✓` (styled green), replace the rotating verb with `"Hacked in Xm Ys"` computed from `scan_start.elapsed()`, keep the activity string for the last tool call.
- **When aborted:** Replace spinner with `✗` (styled red), show `"Aborted"` in the verb slot.
- **When running:** Existing rotating-verb braille animation unchanged.

Duration format: `"Hacked in 2m 34s"` (omit minutes if under 60s: `"Hacked in 47s"`).

---

### 2.7 — Version in Scan UI Header

**Files:** `src/tui/scan_ui.rs`

The scan UI header (`render_header`) shows a two-column layout inside the header block: left column gets the ASCII logo + model/tokens line; right column shows `v{version}` right-aligned at the top-right corner of the banner. Version is read at compile time: `env!("CARGO_PKG_VERSION")`.

---

### 2.8 — Default Context Window 256K

**Files:** `src/commands/scan.rs`

Change the fallback in `run_once`:
```rust
// Before
let context_window = profile.context_window.unwrap_or_else(|| provider.context_window());
// After
let context_window = profile.context_window.unwrap_or(256_000);
```

---

### 2.9 — Version Bump to 0.2.0

**Files:** `Cargo.toml`, `src/tui/menu.rs`

`Cargo.toml`: `version = "0.2.0"`.

`render_main_menu` header string uses `env!("CARGO_PKG_VERSION")` instead of the hardcoded `v0.1.0`.

---

## 3. Files Changed

```
Modified:
  Cargo.toml                   — version bump to 0.2.0
  src/tui/mod.rs               — UiState: scan_aborted, peak_input_tokens, scan_start,
                                   profiles, provider_popup_open, provider_popup;
                                   ScanOutcome::ChangeProvider(String);
                                   Severity::order(); sort findings on FindingAdded
  src/tui/scan_ui.rs           — run_scan_ui signature; abort_handle usage;
                                   provider sub-popup; render_activity completion state;
                                   render_header version column; POPUP_ITEMS 4 items
  src/tui/menu.rs              — Y-centering both screens; banner in scanner selector;
                                   centered item text; env! version string
  src/commands/scan.rs         — pass abort_handle + profiles to run_scan_ui;
                                   ChangeProvider loop arm; default context window 256K
  src/state/mod.rs             — truncate detailed-findings.md in StateWriter::new()
```

No new dependencies. No new files.

---

## 4. Testing

- **2.1 Abort:** Open scan, press `p` → "Abort Scan" → UI stays open showing partial findings, activity line shows `✗ Scan aborted`. Press `q` to exit.
- **2.2 Change Provider:** Press `p` → "Change Provider" → profile list appears → select a profile → scan restarts with that profile. "Add Provider" opens the wizard.
- **2.3 Tokens:** Run a full scan; token bar stays below 100% for normal-sized repos; hover over the peak value — it should be a plausible single-call input size (not millions).
- **2.4 Centering:** Open main menu and scanner selector on a tall terminal (>40 rows) — content is vertically centered with equal padding above and below.
- **2.5 Findings:** Run scan → check `.zentra/detailed-findings.md` — Critical findings appear first. Run scan again — file contains only the new scan's findings.
- **2.6 Animation:** Let scan complete — spinner becomes `✓`, verb slot shows `"Hacked in Xm Ys"`.
- **2.7 Version:** Open scan UI — `v0.2.0` appears in the top-right of the header banner.
- **2.8 Default CW:** Remove `context_window` from a profile config — header shows 256000 as the limit.
- **2.9 Version:** `cargo run -- --version` → `zentra-cli 0.2.0`.
