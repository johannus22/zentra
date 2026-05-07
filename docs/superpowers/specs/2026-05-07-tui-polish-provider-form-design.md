# TUI Polish & Provider Form — Design Spec
**Date:** 2026-05-07  
**Branch:** feat/framework-scanner-branch-display  
**Status:** Approved

---

## Overview

Five areas of improvement to the zentra-cli TUI: two bug fixes (timer freeze, abort behavior), one header enhancement (project context in scan UI), a main menu redesign (Option C layout with provider management), and a new full-TUI provider management flow (selector screen + add-provider form).

---

## Section 1 — Bug Fixes

### 1.1 Timer Freeze on Scan Complete

**Problem:** `render_activity` reads `state.scan_start.elapsed()` every frame, so "Hacked in Xm Xs" keeps ticking after the scan finishes.

**Fix:**
- Add `scan_end: Option<std::time::Instant>` to `UiState`.
- When `all_done()` flips `scan_done = true` in `run_loop`, also set `state.scan_end = Some(Instant::now())`.
- In `render_activity`, compute elapsed as:
  ```rust
  let elapsed = state.scan_end
      .map(|end| end.duration_since(state.scan_start))
      .unwrap_or_else(|| state.scan_start.elapsed());
  ```
  The display is frozen the instant the scan finishes.

### 1.2 Abort Clears Running Scanners

**Problem:** When abort is clicked, scanners still show the spinning animation.

**Fix:** In the abort branch of the popup Enter handler (`popup.selected == 2`), before calling `abort_handle.abort()`:
```rust
for s in &mut state.scanners {
    if s.status == ScanStatus::Running {
        s.status = ScanStatus::Failed;
    }
}
state.scan_end = Some(Instant::now());
```
`render_scanners` only animates on `ScanStatus::Running`, so all spinners freeze and show `✗` immediately.

### 1.3 Abort Disabled After Scan Completes

**Problem:** If the scan is already done and the user opens the popup, "Abort Scan" appears but does nothing meaningful (or shows `✗` on already-completed scanners).

**Fix:** Build the popup item list dynamically. If `state.scan_done` is `true`, exclude "Abort Scan" from the rendered list:
```rust
pub fn popup_items(scan_done: bool) -> Vec<&'static str> {
    let mut items = vec!["Change Provider and Restart Scan", "Add Provider", "Exit App"];
    if !scan_done {
        items.insert(2, "Abort Scan");
    }
    items
}
```
`POPUP_ITEMS` constant is removed; call `popup_items(state.scan_done)` wherever the popup is rendered or navigated.

---

## Section 2 — Scan UI Header Right Panel

**Problem:** The top-right panel shows only `v{version}\n⎇ {branch}`, which wastes space and gives no project context.

**Change:** Add `project_name: String` to `UiState` and to `run_scan_ui`'s signature. Derived in `run_once` from `std::env::current_dir()` basename (same call site as `current_branch()`).

**Right panel layout** (column widened from `Length(18)` to `Length(22)`):
```
zentra-cli            ← Color::Green, BOLD, truncated to 16 chars
⎇ feat/tui-polish    ← Color::DarkGray, truncated to 18 chars
v0.2.0                ← Color::DarkGray (dim)
```

`render_header` right column:
```rust
let right_text = format!(
    "{}\n⎇ {}\nv{}",
    project_name.chars().take(16).collect::<String>(),
    branch_display,
    env!("CARGO_PKG_VERSION"),
);
```
Project name line rendered in `Color::Green` + `BOLD` via a `Line` with multiple `Span`s.

---

## Section 3 — Main Menu Redesign

### 3.1 Layout (Option C — Compact)

Header block split into two columns inside the cyan border:
- **Left:** full 4-line ASCII banner in `Color::Cyan`
- **Right (stacked):** `v{version}` dim, `{model}` in `Color::Green`, `{active_profile}` in `Color::DarkGray`

### 3.2 Grouped Menu Items

Section labels are non-selectable `ListItem`s rendered in `Color::DarkGray` with `ITALIC`. Selectable items are indexed 0–5 (action indices). `next()`/`prev()` skip over section-label positions.

Display order:
```
[dim] SCAN
[0]   Run Full Scan          (disabled if no provider)
[1]   Select Scanners        (disabled if no provider)
[2]   View Last Results
[dim] PROVIDER
[3]   Change Provider        (disabled if no provider)
[4]   Add Provider
[dim] APP
[5]   Exit
```

### 3.3 `MenuState` Changes

New fields:
```rust
pub active_model: String,
pub active_profile: String,
pub profiles: Vec<(String, String)>,  // (profile_name, model)
pub provider_idx: usize,              // for ProviderSelector screen
pub form: ProviderFormState,          // for ProviderForm screen
```

`MenuState::new` gains these as parameters.

### 3.4 `run_menu` Signature Change

```rust
pub async fn run_menu(
    provider_configured: bool,
    project_configured: bool,
    profiles: Vec<(String, String)>,
    active_model: String,
    active_profile: String,
) -> Result<MenuAction>
```

`main.rs` loads `GlobalConfig` at the top of each loop iteration to build these values fresh.

### 3.5 `MenuAction` Changes

```rust
pub enum MenuAction {
    RunScan(Vec<ScannerType>),
    ViewLastResults,
    ChangeProvider(String),    // new — profile name selected from ProviderSelector
    ProviderAdded(String),     // new — newly created profile name saved from ProviderForm
    Exit,
}
```

"Add Provider" (action index 4) is handled as an *internal* screen transition inside `run_menu` — the loop transitions to `MenuScreen::ProviderForm` the same way "Select Scanners" transitions to `ScannerSelector`. No `MenuAction` escapes to `main.rs` until the form is saved or cancelled.

`main.rs` handles:
- `ChangeProvider(name)` → `commands::config::use_profile(&name).await?` then continue loop
- `ProviderAdded(name)` → same as `ChangeProvider(name)` — sets new profile as active

---

## Section 4 — Provider Selector Screen

A new `MenuScreen::ProviderSelector` — full-screen list of configured profiles.

**Layout** (same vertical structure as `ScannerSelector`):
```
[banner header]
──────────────────────────────────────────
  ● anthropic        claude-opus-4-7
    cerebras          llama-3.3-70b
    my-local          ollama/gemma3
──────────────────────────────────────────
  Enter select · Esc back
```

- Active profile (matching `active_profile`) prefixed with `●` in `Color::Green`; others show a space.
- `provider_idx` in `MenuState` tracks the highlighted row.
- `Up`/`Down` navigate; `Enter` returns `MenuAction::ChangeProvider(name)`; `Esc` returns to `MenuScreen::Main` with `selected_idx` restored to the "Change Provider" row (index 3).

---

## Section 5 — Provider Add TUI Form

A new `MenuScreen::ProviderForm` — full-screen form for adding a new provider profile. Replaces the CLI wizard entirely for the TUI flow.

### 5.1 `ProviderFormState`

```rust
pub struct ProviderFormState {
    pub provider_idx: usize,    // index into KNOWN_PROVIDERS
    pub model: String,
    pub base_url: String,
    pub api_key: String,
    pub profile_name: String,
    pub focused_field: usize,   // 0=provider, 1=model, 2=base_url, 3=api_key, 4=name, 5=save
    pub error: Option<String>,  // validation message shown at bottom
}
```

`KNOWN_PROVIDERS` is a `&[(&str, ProviderDefaults)]` built from the same data as `wizard::provider_defaults`. Cycling through them auto-populates `model`, `base_url`, `profile_name` with defaults.

### 5.2 Form Layout

```
┌─ ADD PROVIDER ──────────────────────────────────────┐
│                                                      │
│  Provider   [ anthropic            ◀▶ ]             │
│  Model      [ claude-opus-4-7         ]             │
│  Base URL   [ https://api.anthropic.. ]             │
│  API Key    [ sk-ant-**************   ]             │
│  Name       [ anthropic               ]             │
│                                                      │
│  ──────────────────────────────────────────         │
│  ▶ Save          Esc Cancel                         │
│                                                      │
│  [error message if any]                             │
└──────────────────────────────────────────────────────┘
```

Active field highlighted with `Color::Yellow` border/cursor indicator.

### 5.3 Input Handling

| Key | Effect |
|-----|--------|
| `←` / `→` on Provider field | Cycle `provider_idx`; auto-fill model, base_url, profile_name |
| `Char(c)` on text field | Append char to field string |
| `Backspace` on text field | Pop last char |
| `Tab` / `Down` | `focused_field = (focused_field + 1) % 6` |
| `Shift+Tab` / `Up` | `focused_field = focused_field.saturating_sub(1)` |
| `Enter` on Save (field 5) | Validate → save → return `MenuAction::ProviderAdded` |
| `Esc` | Return to `MenuScreen::Main` without saving |

API key display: first 6 chars shown, remainder replaced with `*`. Stored in full in `ProviderFormState.api_key`.

### 5.4 Save Logic

On Enter with `focused_field == 5`:
1. Validate: `profile_name`, `model`, `api_key` non-empty. Set `form.error` if not.
2. Build `ProfileConfig` from form fields (same structure as wizard output).
3. Insert into `GlobalConfig`, save to disk.
4. Store `api_key` in keychain under profile name.
5. Return `MenuAction::ProviderAdded(profile_name)`.

No subprocess, no terminal drop — fully in-TUI.

---

## Files Affected

| File | Change |
|------|--------|
| `src/tui/mod.rs` | Add `scan_end`, `project_name` to `UiState`; add `ProviderFormState` struct |
| `src/tui/scan_ui.rs` | Timer freeze, abort fixes, dynamic popup items, project_name param |
| `src/tui/menu.rs` | Full redesign: Option C layout, `ProviderFormState`, `ProviderSelector`, `ProviderForm` screens |
| `src/commands/scan.rs` | Pass `project_name` to `run_scan_ui` |
| `src/main.rs` | Reload `GlobalConfig` each loop, pass profiles/model/profile to `run_menu`, handle new `MenuAction` variants |
| `src/agent/mod.rs` | No change |
| `src/scanners/framework_analysis.rs` | No change |
| `tests/tui_test.rs` | Update for new `UiState::new` and `run_menu` signatures |

---

## Non-Goals

- No changes to the CLI wizard (`wizard/mod.rs`) — it remains functional for `zentra config setup`
- No changes to the scan orchestrator or framework analysis logic
- No persistence of "last used provider" separate from global default
