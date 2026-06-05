# Clone Repo & Scan — Design

**Date:** 2026-06-02
**Status:** Approved (pending spec review)

## Summary

Add a new main-menu item, **Clone Repo & Scan**, that clones an external git
repository into a throwaway temp directory, runs the full scan against it, copies
the resulting findings into the current project's `.zentra/audits/<repo-name>/`,
and discards the clone. The existing **Run Full Scan** item is renamed to
**Run Full Scan (this directory)** to disambiguate.

Clone/scan failures are surfaced on the main menu as a dismissible, collapsible
error span instead of being printed to a torn-down terminal.

## Decisions (from brainstorming)

| Question | Decision |
|----------|----------|
| Primary use case | Audit external repos — clone is throwaway, findings are the deliverable |
| Clone + output location | Clone into a temp dir; copy results into `cwd/.zentra/audits/<repo>/`; delete clone |
| Auth | Lean on the user's local `git` (credential helper / SSH keys). No credential UI |
| Entry point | TUI menu only (no CLI flag for v1) |
| Scanner set | Always full scan (all 5 scanners + Report), same as Run Full Scan |
| Error display | Collapsible span below the menu list (not stdout) |
| Re-audit collision | Overwrite `.zentra/audits/<repo>/` |

## Why `set_current_dir` (not a threaded target path)

The scanner's `fs_tools` resolve everything **relative to the current working
directory**: `read_file` rejects absolute paths and `..` components;
`grep_code`/`list_files` default to `.`. The LLM agent explores the cwd. So
scanning a different directory requires `set_current_dir` into the clone — there
is no target-path parameter that would help. This mirrors the test suite's
existing `set_current_dir` usage guarded by `CWD_LOCK`.

## Components

### 1. Menu changes (`src/tui/menu.rs`)

New 8-item main menu:

```
0  Run Full Scan (this directory)   ← renamed from "Run Full Scan"
1  Clone Repo & Scan                ← NEW
2  Run Pentest
3  Select Scanners
4  View Last Results
5  Change Provider
6  Add Provider
7  Exit
```

- Bump `MAX_MENU_ACTION` 6 → 7; renumber `ACTION_*` consts; add
  `ACTION_CLONE_AND_SCAN = 1`. The existing `debug_assert!` keeps
  `MAX_MENU_ACTION` in sync with `main_menu_actions()`.
- `is_item_enabled`: gate `ACTION_CLONE_AND_SCAN` on `provider_configured`
  (same as full scan).
- New `MenuAction::CloneAndScan(String)` carrying the repo URL.

### 2. Repo URL input screen (`src/tui/menu.rs`)

New `MenuScreen::RepoInput`, modeled on `ProviderForm` but single-field.

- `MenuState` additions: `repo_url: String`, `repo_input_error: Option<String>`.
- Render: bordered box titled `CLONE & SCAN`, a `Repo URL` field, hint
  `Enter clone & scan · Esc cancel`.
- Keys: printable chars / Backspace edit the URL; `Enter` validates then returns
  `MenuAction::CloneAndScan(url)`; `Esc` returns to Main.
- Validation on Enter: non-empty and scheme looks like a git remote (`https://`,
  `http://`, `git://`, `ssh://`, or `git@…`). On failure, set
  `repo_input_error` and stay. The URL is passed to `git` as an argument (never
  through a shell), so there is no injection surface.

### 3. Collapsible error span (`src/tui/menu.rs`)

- `MenuState` additions: `last_error: Option<String>`, `error_expanded: bool`.
- `run_menu(...)` gains a `last_error: Option<String>` parameter; `main.rs`
  feeds the captured clone-and-scan error into the next menu render.
- `render_main_menu` layout: insert a `Length(1)` error-summary row between the
  menu list and the key-hints row, rendered only when `last_error.is_some()`.
  Collapsed shows `✗ <first line>  · e expand · x dismiss` in red. When
  `error_expanded`, draw a bordered "Error details" wrapped paragraph in the
  bottom `Fill(1)` region.
- Main-screen keys: `e` toggles expand (only when an error exists); `x`/`Esc`
  dismiss (clear `last_error`). Error also auto-clears when the user
  successfully launches another action.

### 4. Clone-and-scan core (`src/commands/scan.rs` → `run_clone_and_scan(url)`)

Dispatched from `main.rs` via a new `MenuAction::CloneAndScan(url)` arm.
Returns `Result<()>`; `main.rs` maps `Err` → `last_error` (never `?`-propagates),
so a clone failure can never crash the app.

Steps:

1. Derive a sanitized repo name from the URL (last path segment, strip `.git`).
2. Create a temp dir via `tempfile::TempDir` (auto-cleans on drop — survives
   panic). **Requires promoting `tempfile` from dev-dependency to a regular
   dependency.**
3. Print `Cloning <url> …` and shell out:
   `git clone --depth 1 <url> <tempdir>` (inherits the user's git credentials).
   The TUI is torn down here, so stdout is fine.
4. On clone failure → return `Err` with a clear message (auth / not-found / git
   missing). No partial state.
5. Capture the original cwd, then `set_current_dir(tempdir)`. Run the existing
   full-scan core (all 5 scanners + Report). The live scan TUI shows the cloned
   repo's name/branch in its header.
6. After the scan, copy the clone's `.zentra/` artifacts into
   `<original_cwd>/.zentra/audits/<repo-name>/` (findings, reports,
   architecture.md, threat-model, etc.). Overwrite if it already exists.
7. Restore cwd via a restore guard (Drop) so it happens even if the scan errors,
   then let `TempDir` drop to delete the clone.
8. Print `✓ Audit complete. Results in .zentra/audits/<repo-name>/`.

### 5. Dispatch (`src/main.rs`)

- Add `MenuAction::CloneAndScan(url)` arm calling `run_clone_and_scan(url)`;
  on `Err`, store the error string and pass it as `last_error` to the next
  `run_menu` call.
- Thread the `last_error: Option<String>` parameter through `run_menu` /
  `run_menu_blocking` / `MenuState::new`.

## Error handling & edge cases

- **No `git` / clone fails** → caught at step 4, surfaced via the collapsible
  span, back to menu.
- **No provider configured** → menu item disabled (greyed), can't be entered.
- **cwd restoration** → Drop guard restores the original cwd even on scan
  panic/abort, so the process can't be stranded in the temp dir.
- **Empty/garbage URL** → rejected on the input screen before any clone.

## Testing

Unit:
- URL validation (accept/reject by scheme).
- Repo-name derivation (`https://github.com/foo/bar.git` → `bar`).
- Menu index / `MAX_MENU_ACTION` consistency (existing `debug_assert`).
- `is_item_enabled` for the new item.
- Collapsible-span state transitions (`e` toggle, `x` dismiss, auto-clear).

Integration (`tests/`):
- `run_clone_and_scan` against a local throwaway git repo (clone a `file://`
  path created with `tempfile`, LLM mocked via `wiremock`); assert results land
  in `.zentra/audits/<name>/` and the temp clone is gone afterward.
- CWD-mutating tests acquire the existing `CWD_LOCK`.

## Out of scope (v1)

- CLI flag (`zentra scan --repo <url>`).
- Explicit token/PAT input for private repos.
- Respecting the Select-Scanners subset for clones (always full).
- Branch/ref selection (clones default branch, shallow).
