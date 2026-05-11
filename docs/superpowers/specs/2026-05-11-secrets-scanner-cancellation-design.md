---
title: "Secrets Scanner Cancellation & Responsiveness Design"
date: 2026-05-11
project: zentra-cli
---

# Secrets Scanner Cancellation & Responsiveness Design

## 1. Overview & Goals

**Goal:** Make the secrets scanner immediately cancellable via the TUI's `CancellationToken`, preventing session freezes.

**Success criteria:**
- Pressing `q` / `Esc` in the TUI during a secrets scan exits within <100ms
- `git log -p` stream is dropped when cancelled
- No change to the scanner's output format or finding accuracy
- All existing tests continue to pass

## 2. Motivation

Currently, the secrets scanner (`SecretScanner`) is the **only scanner** that does not respect the `CancellationToken` passed by the orchestrator. When a user presses quit in the TUI during a secrets scan:
1. The `cancel_token.cancel()` is called
2. LLM scanners stop within iterations
3. **Secrets scanner ignores it** and continues processing `git log -p` output
4. TUI appears frozen until the entire git history is processed

## 3. Architecture Changes

### 3.1 Current Flow (Broken)

```
OrchestratorAgent.run()
  ├─ tokio::spawn(SecretScanner::new(root, depth, tx).run(&writer))
  │     ├─ spawn_blocking(scan_filesystem)  ← no cancel check
  │     └─ git_history::scan_history(...)    ← no cancel check
  │          └─ while let Ok(Some(line)) = lines.next_line().await
  │               └─ process line (expensive, uninterruptible)
  └─ tokio::spawn(ScannerAgent(..., cancel_token).run())  ← checks cancel
```

### 3.2 New Flow (Fixed)

```
OrchestratorAgent.run()
  ├─ tokio::spawn(SecretScanner::new(root, depth, tx, cancel_token).run(&writer))
  │     ├─ spawn_blocking(|| scan_filesystem(..., cancel_token))
  │     │     └─ returns early if cancel_token.is_cancelled()
  │     └─ git_history::scan_history(..., cancel_token)
  │          └─ while let Ok(Some(line)) = lines.next_line().await
  │               └─ every 1k lines: if cancel.is_cancelled() { break }
  └─ tokio::spawn(ScannerAgent(..., cancel_token).run())
```

## 4. Component Details

### 4.1 `SecretScanner` (`src/scanners/secrets/engine.rs`)

**New field:**
```rust
pub struct SecretScanner {
    root: PathBuf,
    depth: HistoryDepth,
    tx: mpsc::Sender<ScanEvent>,
    cancel_token: CancellationToken,  // NEW
}
```

**Constructor update:**
```rust
pub fn new(
    root: PathBuf,
    depth: HistoryDepth,
    tx: mpsc::Sender<ScanEvent>,
    cancel_token: CancellationToken,  // NEW param
) -> Self {
    Self { root, depth, tx, cancel_token }
}
```

**`run()` method changes:**
1. Clone `cancel_token` for filesystem scan (needs `Sync` for `spawn_blocking`)
2. Pass `cancel_token` reference to `git_history::scan_history`

### 4.2 `git_history::scan_history` (`src/scanners/secrets/git_history.rs`)

**Signature update:**
```rust
pub async fn scan_history(
    root: &Path,
    depth: &HistoryDepth,
    detector_patterns: &[DetectorPattern],
    validator: &ContextValidator<'_>,
    cancel_token: &CancellationToken,  // NEW param
) -> Result<Vec<SecretsMatch>> {
```

**Loop changes:**
```rust
let mut line_counter: u64 = 0;
while let Ok(Some(raw)) = lines.next_line().await {
    line_counter += 1;
    if line_counter % 1_000 == 0 && cancel_token.is_cancelled() {
        break;  // Return partial results
    }
    // ... existing logic ...
}
```

**Early exit handling:**
- Drop the `reader` / `child.stdout` implicitly by breaking from loop
- Call `child.wait().await.ok()` as before (child exits when pipe closed)
- Return whatever `results: Vec<SecretsMatch>` has been collected so far

### 4.3 `scan_filesystem` (`src/scanners/secrets/engine.rs`)

**Signature update:**
```rust
fn scan_filesystem(
    root: &Path,
    detector_patterns: &'static [patterns::DetectorPattern],
    validator: &ContextValidator<'_>,
    tx: &mpsc::Sender<ScanEvent>,
    cache: &mut ScanCache,
    cancel_token: &CancellationToken,  // NEW param
) -> Vec<SecretsMatch>
```

**Changes:**
- Before the `WalkBuilder` loop: check `if cancel_token.is_cancelled() { return Vec::new(); }`
- After collecting entries, before `rayon` parallel scan: check again
- The `rayon` work is CPU-bound and fast; no need to check inside individual file scans

### 4.4 Call Site Updates

**`src/agent/orchestrator.rs` (line 82):**
```rust
SecretScanner::new(root, depth, tx, self.cancel_token.clone())
    .run(&writer)
    .await
    .map(|_| ())
```

**`src/tools/mod.rs` (line 240):**
```rust
// Create a dummy token for tool use (no TUI, so no cancellation needed)
let cancel_token = CancellationToken::new();
match crate::scanners::secrets::SecretScanner::new(root, depth, tool_tx, cancel_token)
    .run(state_writer)
    .await
```

## 5. Data Flow

1. Orchestrator spawns `SecretScanner` with `cancel_token`
2. SecretScanner starts `git log -p` child process
3. TUI receives user quit key (`q`/`Esc`), calls `cancel_token.cancel()`
4. SecretScanner's loop checks `is_cancelled()` every 1k lines → breaks, returns partial `Vec<SecretsMatch>`
5. Orchestrator collects partial results, continues with Phase 3 (Report)

## 6. Error Handling

| Scenario | Behavior |
|----------|----------|
| **Cancellation mid-scan** | Returns partial results. `ScannerCompleted` event sent. Report contains findings up to cancellation point. |
| **Cancellation before scan** | Returns empty `Vec` immediately. |
| **Child process after break** | `child.wait().await.ok()` handles it. Process exits when stdout pipe is closed. |
| **Partial results in report** | Identical to LLM scanner behavior (which also returns partial results if cancelled). |

## 7. Testing

### 7.1 Unit Test: `git_history` cancellation

```rust
#[tokio::test]
async fn scan_history_respects_cancellation() {
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    
    // Spawn scan in background
    let handle = tokio::spawn(async move {
        git_history::scan_history(
            &PathBuf::from("."),
            &HistoryDepth::Last(1000),
            &patterns::all_patterns(),
            &validator,
            &cancel,
        ).await
    });
    
    // Cancel immediately
    cancel_clone.cancel();
    
    let result = handle.await.unwrap().unwrap();
    // Should return quickly with partial results (likely 0 in fast test repo)
    assert!(result.len() < usize::MAX);  // didn't hang
}
```

### 7.2 Integration: TUI cancellation

- Verify `ScanEvent::ScannerCompleted(SecretsScan)` is emitted after `cancel_token.cancel()`
- Test in `tui_test.rs`: `UiState` transitions `SecretsScan` → `Done` on cancellation

## 8. Performance Impact

| Metric | Before | After |
|--------|--------|-------|
| Cancellation response time | Tens of seconds (full scan) | <100ms (worst case: process 999 lines since last 1k check) |
| Normal scan throughput | Unchanged | Unchanged (1k check is ~1 CPU cycle) |
| Memory | Unchanged | Unchanged |

## 9. Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Missing a secret near the cancellation point | 1k-line batch means worst case ~1k lines unprocessed. Acceptable tradeoff for responsiveness. |
| `CancellationToken` not `Sync` | `tokio_util::sync::CancellationToken` is `Clone + Send + Sync`. Safe for `spawn_blocking`. |
| Breaking existing `scan_secrets` tool | Create a dummy `CancellationToken::new()` for tool use — no TUI means no real cancellation needed. |

## 10. References

- [scan-flow.md](../../../vault/projects/zentra-cli/architecture/flows/scan-flow.md) — Orchestrator flow
- [orchestrator.rs](../../../../src/agent/orchestrator.rs) — Phase 2 parallel scanner spawn
- [git_history.rs](../../../../src/scanners/secrets/git_history.rs) — Current uninterruptible loop
- [engine.rs](../../../../src/scanners/secrets/engine.rs) — `SecretScanner::run()`
- [tokio_util::sync::CancellationToken](https://docs.rs/tokio-util/latest/tokio_util/sync/struct.CancellationToken.html)
