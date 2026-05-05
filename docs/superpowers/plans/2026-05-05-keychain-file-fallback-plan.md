# Keychain File Fallback Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When the OS keychain silently drops a write (observed on Windows), fall back to `~/.zentra/keys/<profile>.key` so `zentra scan` never fails with "No API key found" after a successful setup.

**Architecture:** `set_key` verifies its own write by immediately reading back; on failure it writes to a file and returns `KeyStorage::File`. `get_key` tries keyring first, then the file. `delete_key` cleans both. The wizard matches on `KeyStorage` to print the correct confirmation.

**Tech Stack:** `keyring 3`, `dirs 5`, `std::fs` — no new dependencies.

---

## File Map

```
Modified:
  src/config/keychain.rs   — KeyStorage enum, updated set_key/get_key/delete_key, key_file_path helper
  src/wizard/mod.rs        — match KeyStorage to print correct confirmation message

Modified (tests):
  tests/config_test.rs     — 3 new tests for file fallback read, delete, and absent-key
```

---

### Task 1: keychain.rs — file fallback + tests

**Files:**
- Modify: `src/config/keychain.rs`
- Modify: `tests/config_test.rs`

**Context:** Current `keychain.rs` has `set_key(profile, key) -> Result<()>`. You are changing it to `set_key(profile, key) -> Result<KeyStorage>` and adding file fallback logic. The wizard currently calls `keychain::set_key(&name, key)?;` and will compile with a warning (unused return value) until Task 2 fixes it — that's expected.

---

- [ ] **Step 1: Write the failing tests**

Read `tests/config_test.rs` to see the end of the file (to avoid duplicating imports). Then append:

```rust
// ── Keychain File Fallback ─────────────────────────────────────────────────

use zentra_cli::config::keychain;

#[test]
fn keychain_file_fallback_get_reads_key_file() {
    let profile = "zentra-test-fb-read";
    let path = keychain::key_file_path(profile).expect("home dir required");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "test-api-key-value").unwrap();

    // keyring has no entry for this profile → falls through to file
    let result = keychain::get_key(profile).expect("get_key should not error");
    assert_eq!(result, Some("test-api-key-value".to_string()));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn keychain_file_fallback_delete_removes_file() {
    let profile = "zentra-test-fb-del";
    let path = keychain::key_file_path(profile).expect("home dir required");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "dummy-key").unwrap();

    keychain::delete_key(profile).expect("delete_key should not error");

    assert!(!path.exists(), "file should be removed after delete_key");
}

#[test]
fn keychain_get_returns_none_when_both_absent() {
    // Profile name unlikely to exist in any real keychain or file
    let result = keychain::get_key("zentra-test-absent-zzzzz")
        .expect("get_key should not error");
    assert_eq!(result, None);
}
```

- [ ] **Step 2: Run tests to verify they fail**

```
cargo test --test config_test keychain 2>&1 | head -20
```

Expected: compile error — `key_file_path` not found on `keychain`.

- [ ] **Step 3: Replace src/config/keychain.rs**

Write the entire file:

```rust
use anyhow::{Context, Result};
use std::path::PathBuf;

pub fn service_name(profile: &str) -> String {
    format!("zentra.{}", profile)
}

pub fn masked_display() -> &'static str {
    "••••••••••••"
}

pub fn key_file_path(profile: &str) -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".zentra").join("keys").join(format!("{}.key", profile)))
}

pub enum KeyStorage {
    Keychain,
    File,
}

pub fn set_key(profile: &str, api_key: &str) -> Result<KeyStorage> {
    let entry = keyring::Entry::new(&service_name(profile), "api_key")
        .context("Failed to access OS keychain")?;

    let keyring_ok = match entry.set_password(api_key) {
        Ok(()) => entry.get_password().map(|s| s == api_key).unwrap_or(false),
        Err(_) => false,
    };

    if keyring_ok {
        return Ok(KeyStorage::Keychain);
    }

    let path = key_file_path(profile)
        .ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("Failed to create ~/.zentra/keys/")?;
    }
    std::fs::write(&path, api_key).context("Failed to write API key to file")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .context("Failed to set file permissions")?;
    }
    Ok(KeyStorage::File)
}

pub fn get_key(profile: &str) -> Result<Option<String>> {
    let entry = keyring::Entry::new(&service_name(profile), "api_key")
        .context("Failed to access OS keychain")?;
    match entry.get_password() {
        Ok(key) => return Ok(Some(key)),
        Err(keyring::Error::NoEntry) => {}
        Err(e) => return Err(anyhow::anyhow!("Keychain read failed: {}", e)),
    }
    if let Some(path) = key_file_path(profile) {
        if path.exists() {
            let key = std::fs::read_to_string(&path)
                .context("Failed to read API key from file")?;
            return Ok(Some(key));
        }
    }
    Ok(None)
}

pub fn delete_key(profile: &str) -> Result<()> {
    let entry = keyring::Entry::new(&service_name(profile), "api_key")
        .context("Failed to access OS keychain")?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => {}
        Err(e) => return Err(anyhow::anyhow!("Keychain delete failed: {}", e)),
    }
    if let Some(path) = key_file_path(profile) {
        if path.exists() {
            std::fs::remove_file(&path).ok();
        }
    }
    Ok(())
}

pub fn set_oauth_tokens(profile: &str, tokens: &crate::auth::OAuthTokens) -> Result<()> {
    let json = serde_json::to_string(tokens)?;
    let entry = keyring::Entry::new(&service_name(profile), "oauth_tokens")
        .context("Failed to access OS keychain")?;
    entry.set_password(&json)
        .context("Failed to store OAuth tokens in keychain")?;
    Ok(())
}

pub fn get_oauth_tokens(profile: &str) -> Result<Option<crate::auth::OAuthTokens>> {
    let entry = keyring::Entry::new(&service_name(profile), "oauth_tokens")
        .context("Failed to access OS keychain")?;
    match entry.get_password() {
        Ok(json) => Ok(Some(serde_json::from_str(&json)?)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(anyhow::anyhow!("Keychain read failed: {}", e)),
    }
}

pub fn delete_oauth_tokens(profile: &str) -> Result<()> {
    let entry = keyring::Entry::new(&service_name(profile), "oauth_tokens")
        .context("Failed to access OS keychain")?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(anyhow::anyhow!("Keychain delete failed: {}", e)),
    }
}
```

- [ ] **Step 4: Run the new keychain tests**

```
cargo test --test config_test keychain 2>&1 | tail -10
```

Expected: all 3 `keychain_*` tests pass. There may be a compiler warning about unused `KeyStorage` from the wizard call — that is expected and resolved in Task 2.

- [ ] **Step 5: Run full test suite**

```
cargo test 2>&1 | tail -5
```

Expected: all tests pass (warning about unused `KeyStorage` is OK, not an error).

- [ ] **Step 6: Commit**

```bash
git add src/config/keychain.rs tests/config_test.rs
git commit -m "fix: file fallback for keychain writes that don't persist"
```

---

### Task 2: wizard.rs — match on KeyStorage

**Files:**
- Modify: `src/wizard/mod.rs` (lines 280–283)

**Context:** Current code (lines 280–283 of wizard/mod.rs):

```rust
    } else if let Some(ref key) = api_key_opt {
        keychain::set_key(&name, key)?;
        println!("✓ API key saved to OS keychain (never written to disk)");
    }
```

`set_key` now returns `Result<KeyStorage>`. Replace the call + println with a match.

---

- [ ] **Step 1: Apply the change to wizard/mod.rs**

Find this exact block:

```rust
    } else if let Some(ref key) = api_key_opt {
        keychain::set_key(&name, key)?;
        println!("✓ API key saved to OS keychain (never written to disk)");
    }
```

Replace with:

```rust
    } else if let Some(ref key) = api_key_opt {
        match keychain::set_key(&name, key)? {
            keychain::KeyStorage::Keychain => {
                println!("✓ API key saved to OS keychain (never written to disk)");
            }
            keychain::KeyStorage::File => {
                println!("⚠ OS keychain unavailable — API key saved to file (~/.zentra/keys/)");
            }
        }
    }
```

- [ ] **Step 2: Build**

```
cargo build 2>&1 | tail -5
```

Expected: `Finished` with no errors and no warnings about unused KeyStorage.

- [ ] **Step 3: Run full test suite**

```
cargo test 2>&1 | tail -5
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/wizard/mod.rs
git commit -m "fix: show correct storage confirmation after keychain file fallback"
```

---

## Self-Review

### Spec coverage

| Requirement | Task |
|---|---|
| `set_key` verifies write, falls back to file | Task 1 |
| `get_key` tries keyring then file | Task 1 |
| `delete_key` cleans both | Task 1 |
| `key_file_path` pub helper for tests | Task 1 |
| Unix 0o600 permissions | Task 1 |
| `KeyStorage` return type drives wizard message | Task 1 + Task 2 |
| Wizard prints correct message for both paths | Task 2 |
| 3 tests: read, delete, absent | Task 1 |

### Placeholder scan

None — all code blocks are complete and compilable.

### Type consistency

- `KeyStorage::Keychain` / `KeyStorage::File` — defined Task 1, consumed Task 2
- `key_file_path(profile: &str) -> Option<PathBuf>` — defined Task 1, used in all three tests
- `set_key(profile: &str, api_key: &str) -> Result<KeyStorage>` — defined Task 1, matched Task 2
- `get_key`, `delete_key` signatures unchanged — callers in `scan.rs` and `commands/config.rs` need no update
