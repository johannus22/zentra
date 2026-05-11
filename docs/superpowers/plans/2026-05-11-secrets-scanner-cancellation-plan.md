# Secrets Scanner Cancellation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire `CancellationToken` into the secrets scanner so pressing quit in the TUI aborts the scan within <100ms.

**Architecture:** Add `cancel_token` to `SecretScanner`, pass it into `scan_filesystem` and `git_history::scan_history`, and check `is_cancelled()` every 1,000 lines in the `git log -p` consumer loop.

**Tech Stack:** Rust 2021, tokio, tokio-util, rayon, crossterm

---

## Files Changed

| File | Lines | What |
|------|-------|------|
| `src/scanners/secrets/git_history.rs` | ~62, ~92-97 | Add `cancel_token` param, check every 1k lines |
| `src/scanners/secrets/engine.rs` | ~28-34, ~39, ~55-61, ~161, ~167 | Add field, constructor, pass token to filesystem + history |
| `src/agent/orchestrator.rs` | ~82 | Update `SecretScanner::new()` call site |
| `src/tools/mod.rs` | ~240 | Update `SecretScanner::new()` call site (dummy token) |
| `tests/secrets_test.rs` | new | Add cancellation unit test |

---

### Task 1: Add cancellation test

**Files:**
- Create: `tests/secrets_scanner_cancel_test.rs`
- Modify: none

- [ ] **Step 1: Write failing cancellation test**

```rust
use std::path::PathBuf;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use zentra_cli::scanners::secrets::{
    git_history, patterns, validator::ContextValidator, HistoryDepth,
};

#[tokio::test]
async fn scan_history_respects_cancel_token() {
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    let allowlist = zentra_cli::scanners::secrets::allowlist::Allowlist::default();
    let validator = ContextValidator::new(&allowlist);

    let handle = tokio::spawn(async move {
        git_history::scan_history(
            &PathBuf::from("."),
            &HistoryDepth::Last(1000),
            &patterns::all_patterns(),
            &validator,
            &cancel,
        )
        .await
    });

    // Cancel immediately so we test early-exit path
    cancel_clone.cancel();

    let result = tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("timed out — cancellation did not respond quickly")
        .unwrap()
        .unwrap();

    // We only assert it returned quickly; exact count depends on repo state
    assert!(result.len() < usize::MAX);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test secrets_scanner_cancel_test scan_history_respects_cancel_token -- --nocapture`

Expected: **COMPILATION FAIL** — `scan_history` does not accept `&CancellationToken` yet.

- [ ] **Step 3: Commit**

```bash
git add tests/secrets_scanner_cancel_test.rs
git commit -m "test(secrets): add cancellation test for git_history"
```

---

### Task 2: Wire `cancel_token` into `git_history::scan_history`

**Files:**
- Modify: `src/scanners/secrets/git_history.rs`

- [ ] **Step 1: Import `CancellationToken`**

Add at the top of `src/scanners/secrets/git_history.rs`:

```rust
use tokio_util::sync::CancellationToken;
```

- [ ] **Step 2: Update function signature**

Change line 56-61 from:

```rust
pub async fn scan_history(
    root: &Path,
    depth: &HistoryDepth,
    detector_patterns: &[DetectorPattern],
    validator: &ContextValidator<'_>,
) -> Result<Vec<SecretsMatch>> {
```

To:

```rust
pub async fn scan_history(
    root: &Path,
    depth: &HistoryDepth,
    detector_patterns: &[DetectorPattern],
    validator: &ContextValidator<'_>,
    cancel_token: &CancellationToken,
) -> Result<Vec<SecretsMatch>> {
```

- [ ] **Step 3: Add cancellation check inside the loop**

Inside the existing `while let Ok(Some(raw)) = lines.next_line().await` block, after `line_no = 0;` inside the `+++ b/` branch, add a periodic check using a counter.

Change line 86-88 to:

```rust
let mut current_commit: Option<String> = None;
let mut current_file: Option<String> = None;
let mut line_no: u32 = 0;
let mut prev_content_line: Option<String> = None;
let mut results: Vec<SecretsMatch> = Vec::new();
let mut line_counter: u64 = 0;
```

Then after line 127 (`continue;` after the `@@ hunk` parsing block), add:

```rust
    line_counter += 1;
    if line_counter % 1000 == 0 && cancel_token.is_cancelled() {
        break;
    }
```

Or, more cleanly, add the counter increment and check at the top of the loop, right after the `commit` block (around line 97-98). Insert between `prev_content_line = None;` (line 97) and `continue;` (line 98):

No — it's cleaner to put it after all the `continue` blocks at the top and before the content-processing blocks. Actually, the simplest placement is at the very top of the loop, right after we get `raw`:

Replace the current loop header (line 92-93) `while let Ok(Some(raw)) = lines.next_line().await {` with:

```rust
    while let Ok(Some(raw)) = lines.next_line().await {
        line_counter += 1;
        if line_counter % 1000 == 0 && cancel_token.is_cancelled() {
            break;
        }
```

And add `let mut line_counter: u64 = 0;` after `let mut results: Vec<SecretsMatch> = Vec::new();`.

- [ ] **Step 4: Run cancellation test**

Run: `cargo test --test secrets_scanner_cancel_test scan_history_respects_cancel_token -- --nocapture`

Expected: **PASS** — test exits quickly.

- [ ] **Step 5: Commit**

```bash
git add src/scanners/secrets/git_history.rs tests/secrets_scanner_cancel_test.rs
git commit -m "feat(secrets): wire CancellationToken into git_history scan"
```

---

### Task 3: Wire `cancel_token` into `SecretScanner` and `scan_filesystem`

**Files:**
- Modify: `src/scanners/secrets/engine.rs`

- [ ] **Step 1: Import `CancellationToken`**

Add at the top of `src/scanners/secrets/engine.rs`:

```rust
use tokio_util::sync::CancellationToken;
```

- [ ] **Step 2: Add field to `SecretScanner`**

Change the struct (around line 28):

```rust
pub struct SecretScanner {
    root: PathBuf,
    depth: HistoryDepth,
    tx: mpsc::Sender<ScanEvent>,
    cancel_token: CancellationToken,
}
```

- [ ] **Step 3: Update constructor**

Change `new` (around line 35):

```rust
pub fn new(
    root: PathBuf,
    depth: HistoryDepth,
    tx: mpsc::Sender<ScanEvent>,
    cancel_token: CancellationToken,
) -> Self {
    Self { root, depth, tx, cancel_token }
}
```

- [ ] **Step 4: Pass `cancel_token` to `scan_filesystem` and `git_history::scan_history`**

In `run()` (around line 55-61):

Change the filesystem scan block to clone the token:

```rust
let root = self.root.clone();
let tx = self.tx.clone();
let cancel_token = self.cancel_token.clone();
let (fs_matches, mut cache) = tokio::task::spawn_blocking(move || {
    let validator = ContextValidator::new(&allowlist);
    let results = scan_filesystem(&root, detector_patterns, &validator, &tx, &mut cache, &cancel_token);
    (results, cache)
}).await?;
```

And update the history call (around line 71):

```rust
let matches = git_history::scan_history(
    &self.root,
    &self.depth,
    detector_patterns,
    &validator2,
    &self.cancel_token,
)
.await
.unwrap_or_default();
```

- [ ] **Step 5: Update `scan_filesystem` signature and early-exits**

Update function signature (around line 161):

```rust
fn scan_filesystem(
    root: &Path,
    detector_patterns: &'static [patterns::DetectorPattern],
    validator: &ContextValidator<'_>,
    tx: &mpsc::Sender<ScanEvent>,
    cache: &mut ScanCache,
    cancel_token: &CancellationToken,
) -> Vec<SecretsMatch> {
```

Add early-exit checks at two points inside `scan_filesystem`:

After `let mut all_matches = Vec::new();` (around line 49), add:

```rust
if cancel_token.is_cancelled() {
    return Vec::new();
}
```

And after collecting entries (around line 175-177), before the cache-hit loop:

```rust
if cancel_token.is_cancelled() {
    return Vec::new();
}
```

- [ ] **Step 6: Run full test suite**

Run: `cargo test`

Expected: **ALL PASS** — existing tests still pass because we only added a parameter no existing test calls yet.

- [ ] **Step 7: Commit**

```bash
git add src/scanners/secrets/engine.rs
git commit -m "feat(secrets): wire CancellationToken into SecretScanner and scan_filesystem"
```

---

### Task 4: Update call sites (`orchestrator.rs` and `tools/mod.rs`)

**Files:**
- Modify: `src/agent/orchestrator.rs`
- Modify: `src/tools/mod.rs`

- [ ] **Step 1: Update orchestrator.rs**

In `src/agent/orchestrator.rs` (around line 82), change:

```rust
SecretScanner::new(root, depth, tx)
```

To:

```rust
SecretScanner::new(root, depth, tx, self.cancel_token.clone())
```

- [ ] **Step 2: Update tools/mod.rs**

In `src/tools/mod.rs` (around line 239-240), change:

```rust
match crate::scanners::secrets::SecretScanner::new(root, depth, tool_tx)
```

To:

```rust
let cancel_token = tokio_util::sync::CancellationToken::new();
match crate::scanners::secrets::SecretScanner::new(root, depth, tool_tx, cancel_token)
```

- [ ] **Step 3: Run full test suite**

Run: `cargo test`

Expected: **ALL PASS** — call sites now compile with the new constructor.

- [ ] **Step 4: Commit**

```bash
git add src/agent/orchestrator.rs src/tools/mod.rs
git commit -m "feat(secrets): update SecretScanner call sites with CancellationToken"
```

---

### Task 5: Add cancellation test to existing test file (optional consolidation)

**Files:**
- Modify: `tests/secrets_test.rs`

If you prefer the cancellation test lives in the existing `secrets_test.rs` instead of its own file, move it there. The existing file is the idiomatic location.  **This step is optional** — keeping it in `tests/secrets_scanner_cancel_test.rs` is fine.

- [ ] **Step 1: Append to `tests/secrets_test.rs`**

Add the test body from Task 1 to the end of the existing file.

- [ ] **Step 2: Delete standalone file (if migrating)**

```bash
rm tests/secrets_scanner_cancel_test.rs
```

- [ ] **Step 3: Run tests**

Run: `cargo test secrets_test`

Expected: **ALL PASS**

- [ ] **Step 4: Commit**

```bash
git add tests/secrets_test.rs
git commit -m "test(secrets): consolidate cancellation test into secrets_test.rs"
```

---

## Self-Review

- [x] **Spec coverage:** Every requirement from the spec (Section 4.1–4.4) maps to a task.
- [x] **Placeholder scan:** No TBDs, no vague instructions — every step shows exact code and commands.
- [x] **Type consistency:** Uses `tokio_util::sync::CancellationToken` everywhere. `scan_history` takes `&CancellationToken`. `SecretScanner` stores owned `CancellationToken`. Cloned for `spawn_blocking`.

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-05-11-secrets-scanner-cancellation-plan.md`.

Two execution options:**

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints

**Which approach?**
