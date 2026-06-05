# Clone Repo & Scan Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a "Clone Repo & Scan" main-menu item that clones an external git repo into a throwaway temp dir, runs the full scan against it, copies findings into `cwd/.zentra/audits/<repo>/`, discards the clone, and surfaces clone failures in a collapsible error span on the main menu.

**Architecture:** Clone logic lives in a new `src/commands/clone.rs` module exposing small testable units (`validate_repo_url`, `derive_repo_name`, `clone_repo`, `copy_dir_recursive`, `CwdGuard`, `run_clone_and_scan`). Scanning a different directory uses `set_current_dir` into the clone (the LLM `fs_tools` are cwd-relative by design), reusing the existing `commands::scan::run_with_scanners` core. The TUI gains a `RepoInput` screen and a collapsible `last_error` span; `main.rs` catches clone errors and feeds them back into the next menu render.

**Tech Stack:** Rust 2021, ratatui 0.29, crossterm 0.28, tokio, anyhow, tempfile (promoted to a regular dependency), wiremock (dev).

---

## File Structure

- **Modify** `Cargo.toml` — promote `tempfile` to a regular dependency.
- **Create** `src/commands/clone.rs` — clone-and-scan core + helpers (one responsibility: cloning an external repo and routing its scan output).
- **Modify** `src/commands/mod.rs` — register `pub mod clone;`.
- **Modify** `src/tui/menu.rs` — rename item, add `Clone Repo & Scan`, `MenuAction::CloneAndScan`, `MenuScreen::RepoInput`, repo-URL field + collapsible error state/rendering, `last_error` param on `run_menu`.
- **Modify** `src/main.rs` — dispatch `CloneAndScan`, thread `last_error` across the menu loop.
- **Modify** `tests/tui_test.rs` — update menu-index assertions; add repo-input + error-span tests.
- **Create** `tests/clone_test.rs` — integration tests for `clone_repo` + `copy_dir_recursive` + helpers.

---

## Task 1: Promote `tempfile` to a runtime dependency

**Files:**
- Modify: `Cargo.toml:14-44`

- [ ] **Step 1: Move the `tempfile` line from `[dev-dependencies]` into `[dependencies]`**

In `[dependencies]` (keep alphabetical-ish ordering near the bottom), add:

```toml
tempfile = "3"
```

And delete the `tempfile = "3"` line under `[dev-dependencies]`, leaving:

```toml
[dev-dependencies]
wiremock = "0.6"
```

- [ ] **Step 2: Verify it still builds**

Run: `cargo build`
Expected: compiles with no errors (tempfile now available to `src/`).

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "build: promote tempfile to a runtime dependency"
```

---

## Task 2: Clone helpers — URL validation & repo-name derivation

**Files:**
- Create: `src/commands/clone.rs`
- Modify: `src/commands/mod.rs`
- Test: `tests/clone_test.rs`

- [ ] **Step 1: Register the module**

In `src/commands/mod.rs`, add alongside the other `pub mod` lines:

```rust
pub mod clone;
```

- [ ] **Step 2: Write the failing test**

Create `tests/clone_test.rs`:

```rust
use zentra_cli::commands::clone::{derive_repo_name, validate_repo_url};

#[test]
fn validates_accepted_url_schemes() {
    assert!(validate_repo_url("https://github.com/foo/bar.git").is_ok());
    assert!(validate_repo_url("http://example.com/x.git").is_ok());
    assert!(validate_repo_url("git://example.com/x.git").is_ok());
    assert!(validate_repo_url("ssh://git@example.com/x.git").is_ok());
    assert!(validate_repo_url("git@github.com:foo/bar.git").is_ok());
}

#[test]
fn rejects_empty_and_unknown_schemes() {
    assert!(validate_repo_url("").is_err());
    assert!(validate_repo_url("   ").is_err());
    assert!(validate_repo_url("file:///etc/passwd").is_err());
    assert!(validate_repo_url("not a url").is_err());
}

#[test]
fn derives_repo_name_from_url() {
    assert_eq!(derive_repo_name("https://github.com/foo/bar.git"), "bar");
    assert_eq!(derive_repo_name("https://github.com/foo/bar"), "bar");
    assert_eq!(derive_repo_name("git@github.com:foo/baz.git"), "baz");
    assert_eq!(derive_repo_name("https://example.com/a/b/c/"), "c");
}

#[test]
fn derives_safe_fallback_for_weird_input() {
    // No path segment -> non-empty, filesystem-safe fallback
    let name = derive_repo_name("https://");
    assert!(!name.is_empty());
    assert!(name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_'));
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test --test clone_test`
Expected: FAIL — `clone` module / functions not found (compile error).

- [ ] **Step 4: Write minimal implementation**

Create `src/commands/clone.rs`:

```rust
use anyhow::{bail, Result};

/// Accept only URL forms `git clone` understands as remotes. The URL is always
/// passed to `git` as an argument (never through a shell), so this is a
/// usability guard, not an injection guard. `file://` is rejected to keep the
/// feature aimed at external remotes.
pub fn validate_repo_url(url: &str) -> Result<()> {
    let u = url.trim();
    if u.is_empty() {
        bail!("Repo URL cannot be empty");
    }
    let ok = u.starts_with("https://")
        || u.starts_with("http://")
        || u.starts_with("git://")
        || u.starts_with("ssh://")
        || (u.starts_with("git@") && u.contains(':'));
    if !ok {
        bail!("Repo URL must start with https://, http://, git://, ssh://, or git@host:path");
    }
    Ok(())
}

/// Derive a filesystem-safe directory name from a git URL: take the last
/// non-empty path segment, strip a trailing `.git`, and sanitize. Falls back to
/// `"repo"` when nothing usable remains.
pub fn derive_repo_name(url: &str) -> String {
    let trimmed = url.trim().trim_end_matches('/');
    // Handle scp-like `git@host:owner/repo` by splitting on both ':' and '/'.
    let last = trimmed
        .rsplit(|c| c == '/' || c == ':')
        .find(|s| !s.is_empty())
        .unwrap_or("");
    let stripped = last.strip_suffix(".git").unwrap_or(last);
    let sanitized: String = stripped
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let cleaned = sanitized.trim_matches('-').to_string();
    if cleaned.is_empty() {
        "repo".to_string()
    } else {
        cleaned
    }
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test --test clone_test`
Expected: PASS (all four tests).

- [ ] **Step 6: Commit**

```bash
git add src/commands/mod.rs src/commands/clone.rs tests/clone_test.rs
git commit -m "feat(clone): add repo URL validation and name derivation"
```

---

## Task 3: Clone helpers — `clone_repo`, `copy_dir_recursive`, `CwdGuard`

**Files:**
- Modify: `src/commands/clone.rs`
- Test: `tests/clone_test.rs`

- [ ] **Step 1: Write the failing tests**

Append to `tests/clone_test.rs`:

```rust
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;
use zentra_cli::commands::clone::{clone_repo, copy_dir_recursive, CwdGuard};

fn git(args: &[&str], dir: &Path) {
    let status = Command::new("git")
        .args(args)
        .current_dir(dir)
        .status()
        .expect("git should be installed");
    assert!(status.success(), "git {:?} failed", args);
}

#[test]
fn clone_repo_clones_a_local_source_repo() {
    // Build a source repo with one commit.
    let src = TempDir::new().unwrap();
    git(&["init", "-q"], src.path());
    git(&["config", "user.email", "t@test.test"], src.path());
    git(&["config", "user.name", "t"], src.path());
    std::fs::write(src.path().join("README.md"), "hello").unwrap();
    git(&["add", "."], src.path());
    git(&["commit", "-qm", "init"], src.path());

    let dest_parent = TempDir::new().unwrap();
    let dest = dest_parent.path().join("clone");
    let url = format!("file://{}", src.path().display());

    clone_repo(&url, &dest).unwrap();
    assert!(dest.join("README.md").exists());
}

#[test]
fn clone_repo_errors_on_missing_source() {
    let dest_parent = TempDir::new().unwrap();
    let dest = dest_parent.path().join("clone");
    let err = clone_repo("https://invalid.invalid/nope.git", &dest).unwrap_err();
    assert!(err.to_string().contains("git clone failed"), "got: {err}");
}

#[test]
fn copy_dir_recursive_copies_nested_files() {
    let src = TempDir::new().unwrap();
    std::fs::create_dir_all(src.path().join("reports")).unwrap();
    std::fs::write(src.path().join("detailed-findings.md"), "f").unwrap();
    std::fs::write(src.path().join("reports/r.json"), "{}").unwrap();

    let dst_parent = TempDir::new().unwrap();
    let dst = dst_parent.path().join("audits/bar");
    copy_dir_recursive(src.path(), &dst).unwrap();

    assert!(dst.join("detailed-findings.md").exists());
    assert!(dst.join("reports/r.json").exists());
}

#[test]
fn cwd_guard_restores_original_directory_on_drop() {
    let _lock = clone_cwd_lock().lock().unwrap_or_else(|e| e.into_inner());
    let original = std::env::current_dir().unwrap();
    let target = TempDir::new().unwrap();
    {
        let _guard = CwdGuard::change_to(target.path()).unwrap();
        // canonicalize both sides to neutralize macOS /private symlinking
        assert_eq!(
            std::env::current_dir().unwrap().canonicalize().unwrap(),
            target.path().canonicalize().unwrap()
        );
    }
    assert_eq!(std::env::current_dir().unwrap(), original);
}

// Local lock so cwd-mutating tests in this file don't race each other.
static CLONE_CWD_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
fn clone_cwd_lock() -> &'static std::sync::Mutex<()> {
    CLONE_CWD_LOCK.get_or_init(|| std::sync::Mutex::new(()))
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test clone_test`
Expected: FAIL — `clone_repo`, `copy_dir_recursive`, `CwdGuard` not found.

- [ ] **Step 3: Write minimal implementation**

Append to `src/commands/clone.rs`:

```rust
use anyhow::Context;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Shallow-clone `url` into `dest` using the user's local `git` (inherits their
/// credential helper / SSH keys). `dest` must not already exist.
pub fn clone_repo(url: &str, dest: &Path) -> Result<()> {
    let output = Command::new("git")
        .arg("clone")
        .arg("--depth")
        .arg("1")
        .arg(url)
        .arg(dest)
        .output()
        .context("failed to run `git` — is it installed and on PATH?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git clone failed: {}", stderr.trim());
    }
    Ok(())
}

/// Recursively copy the contents of `src` into `dst`, creating `dst` (and
/// parents) as needed. Overwrites existing files.
pub fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)
        .with_context(|| format!("failed to create {}", dst.display()))?;
    for entry in std::fs::read_dir(src)
        .with_context(|| format!("failed to read {}", src.display()))?
    {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)
                .with_context(|| format!("failed to copy {}", from.display()))?;
        }
    }
    Ok(())
}

/// Restores the process current directory to its original value when dropped,
/// so a panic or early return inside a scan can't strand the process in the
/// temp clone.
pub struct CwdGuard {
    original: PathBuf,
}

impl CwdGuard {
    pub fn change_to(target: &Path) -> Result<Self> {
        let original = std::env::current_dir().context("failed to read current dir")?;
        std::env::set_current_dir(target)
            .with_context(|| format!("failed to enter {}", target.display()))?;
        Ok(Self { original })
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.original);
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --test clone_test`
Expected: PASS (all tests, including Task 2's).

- [ ] **Step 5: Commit**

```bash
git add src/commands/clone.rs tests/clone_test.rs
git commit -m "feat(clone): add clone_repo, copy_dir_recursive, and CwdGuard"
```

---

## Task 4: `run_clone_and_scan` orchestration

**Files:**
- Modify: `src/commands/clone.rs`

This orchestrator depends on global config + an LLM provider (via `commands::scan::run_with_scanners`), so it is verified through its component tests (Tasks 2–3) plus a manual smoke check, not a new automated end-to-end test — mirroring how the existing suite tests the orchestrator/scanner seams rather than full `run()`.

- [ ] **Step 1: Add the imports and full-scanner helper**

At the top of `src/commands/clone.rs`, add:

```rust
use crate::agent::ScannerType;
```

- [ ] **Step 2: Implement `run_clone_and_scan`**

Append to `src/commands/clone.rs`:

```rust
/// Clone an external repo into a throwaway temp dir, run the full scan against
/// it, copy the resulting `.zentra/` artifacts into
/// `cwd/.zentra/audits/<repo>/`, then discard the clone.
pub async fn run_clone_and_scan(url: String) -> Result<()> {
    validate_repo_url(&url)?;
    let repo_name = derive_repo_name(&url);

    // Capture where audit output should land before we change directories.
    let audit_root = std::env::current_dir()?
        .join(".zentra")
        .join("audits")
        .join(&repo_name);

    let temp = tempfile::TempDir::new().context("failed to create temp dir for clone")?;
    let clone_dir = temp.path().join("repo");

    println!("Cloning {url} …");
    clone_repo(&url, &clone_dir)?;

    let full_scan = vec![
        ScannerType::ThreatModel,
        ScannerType::Sast,
        ScannerType::SupplyChain,
        ScannerType::ApiScan,
        ScannerType::IacScan,
        ScannerType::Report,
    ];

    {
        // Enter the clone; the guard restores cwd on drop (incl. panic/early return).
        let _guard = CwdGuard::change_to(&clone_dir)?;
        crate::commands::scan::run_with_scanners(full_scan).await?;

        // Copy the clone's .zentra/ output into the original project's audits dir.
        let clone_zentra = clone_dir.join(".zentra");
        if clone_zentra.exists() {
            if audit_root.exists() {
                std::fs::remove_dir_all(&audit_root).ok();
            }
            copy_dir_recursive(&clone_zentra, &audit_root)?;
        }
    } // guard drops here -> cwd restored

    println!(
        "\n✓ Audit complete. Results in .zentra/audits/{}/",
        repo_name
    );
    Ok(())
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo build`
Expected: compiles (note `run_with_scanners` is already `pub` in `src/commands/scan.rs`).

- [ ] **Step 4: Commit**

```bash
git add src/commands/clone.rs
git commit -m "feat(clone): orchestrate clone -> full scan -> audit output"
```

---

## Task 5: Menu — rename item, add entry, new `MenuAction`

**Files:**
- Modify: `src/tui/menu.rs:30-51` (consts + labels), `src/tui/menu.rs:74-82` (`MenuAction`), `src/tui/menu.rs:466-476` (`is_item_enabled`)
- Test: `tests/tui_test.rs:886-909`, `tests/tui_test.rs:565-608`, `tests/tui_test.rs:934-946`

- [ ] **Step 1: Update the failing menu-label tests**

In `tests/tui_test.rs`, replace `menu_state_main_menu_has_run_pentest_action` (lines ~886-892) and `menu_state_main_menu_has_seven_actions` (lines ~894-909) with:

```rust
#[test]
fn menu_state_main_menu_has_clone_action() {
    let actions = main_menu_actions();
    assert_eq!(actions[0], "Run Full Scan (this directory)");
    assert_eq!(actions[1], "Clone Repo & Scan");
    assert_eq!(actions[2], "Run Pentest");
}

#[test]
fn menu_state_main_menu_has_eight_actions() {
    assert_eq!(main_menu_actions().len(), 8);
    assert_eq!(
        main_menu_actions(),
        &[
            "Run Full Scan (this directory)",
            "Clone Repo & Scan",
            "Run Pentest",
            "Select Scanners",
            "View Last Results",
            "Change Provider",
            "Add Provider",
            "Exit",
        ]
    );
}
```

Update `menu_state_navigate_wraps` (lines ~565-588) body to expect 8 items:

```rust
    // 8 items: indices 0..=7
    state.next(); // 1
    state.next(); // 2
    state.next(); // 3
    state.next(); // 4
    state.next(); // 5
    state.next(); // 6
    assert_eq!(state.selected_idx, 6);
    state.next(); // 7
    assert_eq!(state.selected_idx, 7);
    state.next(); // clamp at max
    assert_eq!(state.selected_idx, 7);
    state.prev();
    assert_eq!(state.selected_idx, 6);
```

Update `menu_state_disabled_items_when_unconfigured` (lines ~590-608) assertions to the new indices:

```rust
    assert!(!state.is_item_enabled(0)); // Run Full Scan (this directory)
    assert!(!state.is_item_enabled(1)); // Clone Repo & Scan
    assert!(state.is_item_enabled(2)); // Run Pentest
    assert!(!state.is_item_enabled(3)); // Select Scanners
    assert!(state.is_item_enabled(4)); // View Last Results
    assert!(!state.is_item_enabled(5)); // Change Provider
    assert!(state.is_item_enabled(6)); // Add Provider
    assert!(state.is_item_enabled(7)); // Exit
```

Update `menu_state_change_provider_requires_provider` (lines ~934-946):

```rust
    assert!(!state.is_item_enabled(5)); // Change Provider = index 5
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test tui_test menu_state`
Expected: FAIL — labels/lengths/indices don't match yet.

- [ ] **Step 3: Update the menu constants and labels**

In `src/tui/menu.rs`, replace the const block (lines ~30-51) with:

```rust
const ACTION_RUN_FULL_SCAN: usize = 0;
const ACTION_CLONE_AND_SCAN: usize = 1;
const ACTION_RUN_PENTEST: usize = 2;
const ACTION_SELECT_SCANNERS: usize = 3;
const ACTION_VIEW_RESULTS: usize = 4;
const ACTION_CHANGE_PROVIDER: usize = 5;
const ACTION_ADD_PROVIDER: usize = 6;
const ACTION_EXIT: usize = 7;

/// Highest selectable action index in the main menu (8 items: 0-7).
const MAX_MENU_ACTION: usize = 7;

pub fn main_menu_actions() -> &'static [&'static str] {
    &[
        "Run Full Scan (this directory)",
        "Clone Repo & Scan",
        "Run Pentest",
        "Select Scanners",
        "View Last Results",
        "Change Provider",
        "Add Provider",
        "Exit",
    ]
}
```

- [ ] **Step 4: Add the `MenuAction` variant**

In `src/tui/menu.rs`, in `enum MenuAction` (lines ~74-82), add after `RunPentest`:

```rust
    CloneAndScan(String), // repo URL — from RepoInput screen
```

- [ ] **Step 5: Gate the new item on provider config**

In `is_item_enabled` (lines ~466-476), extend the gated arm to include the clone action:

```rust
    pub fn is_item_enabled(&self, idx: usize) -> bool {
        match idx {
            i if i == ACTION_RUN_FULL_SCAN
                || i == ACTION_CLONE_AND_SCAN
                || i == ACTION_SELECT_SCANNERS
                || i == ACTION_CHANGE_PROVIDER =>
            {
                self.provider_configured
            }
            _ => true,
        }
    }
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test --test tui_test menu_state`
Expected: PASS. (The `debug_assert!` in `run_menu_blocking` also keeps `MAX_MENU_ACTION` in sync.)

- [ ] **Step 7: Commit**

```bash
git add src/tui/menu.rs tests/tui_test.rs
git commit -m "feat(menu): rename full scan and add Clone Repo & Scan item"
```

---

## Task 6: Menu — `RepoInput` screen state & transition

**Files:**
- Modify: `src/tui/menu.rs` (`MenuScreen` enum ~84-90, `MenuState` struct ~396-415, `MenuState::new` ~417-447, `next()` max ~449-458)
- Test: `tests/tui_test.rs`

- [ ] **Step 1: Write the failing test**

Append to `tests/tui_test.rs` (the import line at the top already pulls `MenuScreen`, `MenuState`; add `MenuAction` if not present):

```rust
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test tui_test repo_input`
Expected: FAIL — `MenuScreen::RepoInput`, `repo_url`, `open_repo_input`, `validate_repo_input` don't exist.

- [ ] **Step 3: Add the screen variant**

In `src/tui/menu.rs`, add to `enum MenuScreen` (lines ~84-90):

```rust
    RepoInput,
```

- [ ] **Step 4: Add state fields**

In `struct MenuState` (lines ~396-415), add fields:

```rust
    pub repo_url: String,
    pub repo_input_error: Option<String>,
    pub last_error: Option<String>,
    pub error_expanded: bool,
```

In `MenuState::new` (lines ~417-447), initialize them in the returned struct literal:

```rust
            repo_url: String::new(),
            repo_input_error: None,
            last_error: None,
            error_expanded: false,
```

- [ ] **Step 5: Add helper methods**

In `impl MenuState`, add:

```rust
    pub fn open_repo_input(&mut self) {
        self.screen = MenuScreen::RepoInput;
        self.repo_url.clear();
        self.repo_input_error = None;
    }

    pub fn validate_repo_input(&self) -> anyhow::Result<()> {
        crate::commands::clone::validate_repo_url(&self.repo_url)
    }
```

- [ ] **Step 6: Keep `next()` clamped on the new screen**

In `next()` (lines ~449-458), extend the match so `RepoInput` clamps at 0 like the other input screens:

```rust
        let max = match self.screen {
            MenuScreen::Main => MAX_MENU_ACTION,
            MenuScreen::ScannerSelector => 5,
            MenuScreen::ProviderSelector
            | MenuScreen::ProviderForm
            | MenuScreen::RepoInput => 0,
        };
```

- [ ] **Step 7: Run test to verify it passes**

Run: `cargo test --test tui_test repo_input`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/tui/menu.rs tests/tui_test.rs
git commit -m "feat(menu): add RepoInput screen state and validation"
```

---

## Task 7: Menu — collapsible error span state

**Files:**
- Modify: `src/tui/menu.rs` (`impl MenuState`)
- Test: `tests/tui_test.rs`

- [ ] **Step 1: Write the failing test**

Append to `tests/tui_test.rs`:

```rust
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test tui_test error_span`
Expected: FAIL — `toggle_error_expanded` / `dismiss_error` not found.

- [ ] **Step 3: Implement the methods**

In `impl MenuState`, add:

```rust
    pub fn toggle_error_expanded(&mut self) {
        if self.last_error.is_some() {
            self.error_expanded = !self.error_expanded;
        }
    }

    pub fn dismiss_error(&mut self) {
        self.last_error = None;
        self.error_expanded = false;
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --test tui_test error_span toggle_error`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/tui/menu.rs tests/tui_test.rs
git commit -m "feat(menu): add collapsible error span state"
```

---

## Task 8: Menu — `run_menu` `last_error` param + key handling + rendering

**Files:**
- Modify: `src/tui/menu.rs` (`run_menu` ~682-703, `run_menu_blocking` ~705-731, `run_menu_loop` Main + new RepoInput arms, `render_main_menu` ~955-1002, add `render_repo_input`, `render_menu` dispatch ~887-895)

- [ ] **Step 1: Thread `last_error` into `run_menu` / `run_menu_blocking`**

In `run_menu` (lines ~682-703), add a parameter `last_error: Option<String>` (append it after `branch_name`) and forward it to `run_menu_blocking`. In `run_menu_blocking` (lines ~705-731), add the same parameter and, immediately after `let mut state = MenuState::new(...)`, set:

```rust
    state.last_error = last_error;
```

(Adding the param to `run_menu`/`run_menu_blocking` — not to `MenuState::new` — keeps all existing `MenuState::new(...)` test callsites compiling unchanged.)

- [ ] **Step 2: Dispatch render for the new screen**

In `render_menu` (lines ~887-895), add an arm:

```rust
        MenuScreen::RepoInput => render_repo_input(frame, area, state),
```

- [ ] **Step 3: Handle Main-screen error keys + clone entry**

In `run_menu_loop`, in the `MenuScreen::Main` key match:

Add the clone action under the `KeyCode::Enter` `match state.selected_idx` block, after the `ACTION_RUN_FULL_SCAN` arm:

```rust
                                ACTION_CLONE_AND_SCAN => {
                                    state.last_error = None;
                                    state.error_expanded = false;
                                    state.open_repo_input();
                                }
```

Add these arms to the Main `match key.code` (alongside `Up`/`Down`/`Enter`/`Char('q')`):

```rust
                        KeyCode::Char('e') => state.toggle_error_expanded(),
                        KeyCode::Char('x') => state.dismiss_error(),
                        KeyCode::Esc => state.dismiss_error(),
```

- [ ] **Step 4: Add the RepoInput key-handling arm**

In `run_menu_loop`, add a new top-level arm to `match state.screen` (mirroring `ProviderForm`'s structure):

```rust
                    MenuScreen::RepoInput => match key.code {
                        KeyCode::Char(c) => {
                            state.repo_input_error = None;
                            state.repo_url.push(c);
                        }
                        KeyCode::Backspace => {
                            state.repo_input_error = None;
                            state.repo_url.pop();
                        }
                        KeyCode::Enter => match state.validate_repo_input() {
                            Ok(()) => {
                                let url = state.repo_url.trim().to_string();
                                return Ok(MenuAction::CloneAndScan(url));
                            }
                            Err(e) => state.repo_input_error = Some(e.to_string()),
                        },
                        KeyCode::Esc => {
                            state.screen = MenuScreen::Main;
                            state.selected_idx = ACTION_CLONE_AND_SCAN;
                        }
                        _ => {}
                    },
```

- [ ] **Step 5: Render the error span in `render_main_menu`**

Replace the layout + tail of `render_main_menu` (lines ~955-1002) so an error row sits between the menu list and the hints, and expanded details fill the bottom region:

```rust
fn render_main_menu(frame: &mut Frame, area: ratatui::layout::Rect, state: &MenuState) {
    let chunks = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(HEADER_HEIGHT),
        Constraint::Min(12),   // menu list
        Constraint::Length(1), // error summary (blank when no error)
        Constraint::Length(1), // key hints
        Constraint::Fill(1),   // expanded error details
    ])
    .split(area);

    let header_center = Layout::horizontal([
        Constraint::Percentage(30),
        Constraint::Percentage(40),
        Constraint::Percentage(30),
    ])
    .split(chunks[1])[1];

    render_banner_header(frame, header_center, state);

    let items: Vec<ListItem> = main_menu_actions()
        .iter()
        .enumerate()
        .map(|(action, label)| {
            let enabled = state.is_item_enabled(action);
            let selected = state.selected_idx == action;
            let prefix = if selected { "▶ " } else { "  " };
            let style = if !enabled {
                Style::default().fg(Color::DarkGray)
            } else if selected {
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            ListItem::new(format!("{}{}", prefix, label)).style(style)
        })
        .collect();

    let list = List::new(items).block(Block::default().borders(Borders::ALL));
    let menu_area = centered_middle_column(chunks[2]);
    frame.render_widget(list, menu_area);

    // Collapsible error summary line.
    if let Some(err) = &state.last_error {
        let first_line = err.lines().next().unwrap_or("");
        let toggle = if state.error_expanded { "collapse" } else { "expand" };
        let summary = format!(
            "✗ {}  · e {} · x dismiss",
            clip_with_ellipsis(first_line, 48),
            toggle
        );
        frame.render_widget(
            Paragraph::new(summary).style(Style::default().fg(Color::Red)),
            centered_middle_column(chunks[3]),
        );
    }

    let keys = Paragraph::new(" ↑↓ navigate · Enter select · q quit")
        .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(keys, centered_middle_column(chunks[4]));

    // Expanded details box.
    if state.error_expanded {
        if let Some(err) = &state.last_error {
            let details = Paragraph::new(err.clone())
                .style(Style::default().fg(Color::Red))
                .wrap(Wrap { trim: false })
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Error details "),
                );
            frame.render_widget(details, centered_middle_column(chunks[5]));
        }
    }
}
```

- [ ] **Step 6: Add `render_repo_input`**

Add a new function near `render_provider_form`:

```rust
fn render_repo_input(frame: &mut Frame, area: ratatui::layout::Rect, state: &MenuState) {
    let outer = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(HEADER_HEIGHT),
        Constraint::Length(7),
        Constraint::Fill(1),
    ])
    .split(area);

    let header_center = Layout::horizontal([
        Constraint::Percentage(30),
        Constraint::Percentage(40),
        Constraint::Percentage(30),
    ])
    .split(outer[1])[1];
    render_banner_header(frame, header_center, state);

    let form_area = Layout::horizontal([
        Constraint::Percentage(20),
        Constraint::Percentage(60),
        Constraint::Percentage(20),
    ])
    .split(outer[2])[1];

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" CLONE & SCAN ")
        .title_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(form_area);
    frame.render_widget(block, form_area);

    let max_w = inner.width.saturating_sub(11) as usize;
    let mut lines = vec![
        Line::from(vec![
            Span::raw("  Repo URL  "),
            Span::styled(
                clip_with_ellipsis(&state.repo_url, max_w),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            " Enter clone & scan · Esc cancel",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    if let Some(err) = &state.repo_input_error {
        lines.push(Line::from(Span::styled(
            format!(" ✗ {}", err),
            Style::default().fg(Color::Red),
        )));
    }
    frame.render_widget(Paragraph::new(Text::from(lines)), inner);
}
```

- [ ] **Step 7: Build and run the full TUI test suite**

Run: `cargo test --test tui_test`
Expected: PASS (all menu tests, including updated index assertions).

- [ ] **Step 8: Commit**

```bash
git add src/tui/menu.rs
git commit -m "feat(menu): render RepoInput screen and collapsible error span"
```

---

## Task 9: `main.rs` — dispatch clone-and-scan + thread `last_error`

**Files:**
- Modify: `src/main.rs:11-81`

- [ ] **Step 1: Track `last_error` across the menu loop**

In `src/main.rs`, immediately before `loop {` (line ~12), add:

```rust
        let mut last_error: Option<String> = None;
```

- [ ] **Step 2: Pass `last_error` into `run_menu`**

In the `run_menu(...)` call (lines ~48-57), append the new argument after `branch_name`. Because the value is moved, take it each iteration:

```rust
            match run_menu(
                provider_configured,
                project_configured,
                profiles,
                active_model,
                active_profile,
                project_name,
                branch_name,
                last_error.take(),
            )
            .await?
```

- [ ] **Step 3: Add the `CloneAndScan` dispatch arm**

In the `match` on the menu action, add after the `RunScan` arm (lines ~59-62):

```rust
                MenuAction::CloneAndScan(url) => {
                    if let Err(e) = commands::clone::run_clone_and_scan(url).await {
                        last_error = Some(e.to_string());
                    }
                    // loop continues; error (if any) renders on the next menu draw
                }
```

- [ ] **Step 4: Build**

Run: `cargo build`
Expected: compiles. (`run_clone_and_scan` is `async`, dispatched arm `.await`s it; errors are captured, not `?`-propagated.)

- [ ] **Step 5: Run the whole test suite**

Run: `cargo test`
Expected: PASS — all existing + new tests.

- [ ] **Step 6: Commit**

```bash
git add src/main.rs
git commit -m "feat: dispatch Clone Repo & Scan and surface errors on the menu"
```

---

## Task 10: Manual smoke test & docs touch-up

**Files:**
- Modify: `CLAUDE.md` (Module Map / menu note, if applicable), `AGENTS.md` (if it lists menu items)

- [ ] **Step 1: Smoke test the happy path**

Run: `cargo run`
Then: arrow to **Clone Repo & Scan**, press Enter, paste a small public repo URL (e.g. `https://github.com/octocat/Hello-World.git`), press Enter.
Expected: `Cloning … `, the live scan UI runs, then `✓ Audit complete. Results in .zentra/audits/Hello-World/`. Verify `.zentra/audits/Hello-World/detailed-findings.md` exists and the temp clone is gone.

- [ ] **Step 2: Smoke test the error path**

Run: `cargo run`
Then: **Clone Repo & Scan** → Enter → type `https://github.com/this/does-not-exist-zzz.git` → Enter.
Expected: returns to the main menu with a red `✗ Clone failed: …` line; press `e` to expand the details box, `x` to dismiss.

- [ ] **Step 3: Update docs if needed**

If `CLAUDE.md` or `AGENTS.md` enumerate the menu items or the `tui/menu.rs` responsibilities, add a one-line note that `tui/menu.rs` now hosts the `RepoInput` screen and that clone-and-scan lives in `commands/clone.rs`. (Skip if neither doc lists these.)

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "docs: note Clone Repo & Scan menu flow"
```

---

## Self-Review Notes

- **Spec coverage:** menu rename + new item (Task 5), URL input screen + validation (Tasks 2, 6, 8), local-git clone (Task 3), temp clone + copy to `.zentra/audits/<repo>/` + discard (Tasks 3, 4), full-scan set (Task 4), collapsible error span placement/behavior (Tasks 7, 8, 9), `set_current_dir` rationale (Task 3 `CwdGuard`), `tempfile` promotion (Task 1), testing seams (Tasks 2, 3, 5–8). All spec sections map to tasks.
- **Out of scope (per spec):** no CLI flag, no PAT input, no scanner-subset support, no branch selection — none added.
- **Type consistency:** `validate_repo_url` / `derive_repo_name` / `clone_repo` / `copy_dir_recursive` / `CwdGuard::change_to` / `run_clone_and_scan` names are used identically across the module, tests, menu (`validate_repo_input` delegates to `validate_repo_url`), and `main.rs`. `MenuAction::CloneAndScan(String)`, `MenuScreen::RepoInput`, and the new `MenuState` fields (`repo_url`, `repo_input_error`, `last_error`, `error_expanded`) are referenced consistently.
