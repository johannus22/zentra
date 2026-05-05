# Keychain File Fallback — Design Spec

**Date:** 2026-05-05
**Status:** Approved
**Author:** Rafael (Kodecraft Dev)

---

## 1. Problem

On some Windows configurations the `keyring` crate's `set_password` returns `Ok(())` but the credential is never actually written to Windows Credential Manager. The wizard reports success, but `get_password` on the next process invocation returns `NoEntry`. The user sees "No API key found for profile 'X'" when running `zentra scan`.

Root cause: the `keyring` crate silently discards the write on affected Windows builds (credential does not appear in Credential Manager at all).

---

## 2. Fix

Modify `src/config/keychain.rs` to verify every write and fall back to a file if the keyring is unreliable. No other files change.

---

## 3. Fallback File Layout

```
~/.zentra/keys/
  <profile-name>.key    ← raw API key, plaintext
```

- Directory: `~/.zentra/keys/` created with `create_dir_all` if absent.
- File content: raw API key string, no trailing newline.
- Permissions: `0o600` on Unix via `fs::set_permissions`; Windows relies on the home directory being user-private (same convention as `~/.aws/credentials` and `~/.ssh/`).

---

## 4. Modified Behaviour

### `set_key(profile, key)`

1. Try `entry.set_password(key)`.
2. If `set_password` errors → skip keyring, go to step 4.
3. Immediately call `entry.get_password()` to verify the write persisted.
4. If verification returns `Ok(key)` → return `Ok(KeyStorage::Keychain)`.
5. If verification fails (`NoEntry` or any error) → write key to `~/.zentra/keys/<profile>.key`, return `Ok(KeyStorage::File)`.

`set_key` returns `Result<KeyStorage>` so the wizard can print the right confirmation message:
- `KeyStorage::Keychain` → `"✓ API key saved to OS keychain (never written to disk)"`
- `KeyStorage::File` → `"⚠ OS keychain unavailable — API key saved to file (~/.zentra/keys/)"`

### `get_key(profile) -> Result<Option<String>>`

1. Try `entry.get_password()`.
2. If `Ok(key)` → return `Some(key)`.
3. If `NoEntry` → check `~/.zentra/keys/<profile>.key`.
   - If file exists → return `Some(contents)`.
   - If file absent → return `None`.
4. Any other keyring error → propagate as `Err`.

### `delete_key(profile)`

Delete keyring entry (existing behaviour) **and** delete `~/.zentra/keys/<profile>.key` if it exists. Both operations are best-effort (ignore `NoEntry` / file-not-found).

---

## 5. Helper: Key File Path

```rust
fn key_file_path(profile: &str) -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".zentra").join("keys").join(format!("{}.key", profile)))
}
```

---

## 6. Error Handling

| Scenario | Behaviour |
|---|---|
| keyring write succeeds, verify succeeds | Normal flow, normal message |
| keyring write succeeds, verify fails | Write file, print `⚠ OS keychain unavailable` warning |
| keyring write errors | Write file, print `⚠ OS keychain unavailable` warning |
| File write fails | Propagate error — user cannot proceed |
| keyring read → `NoEntry`, file exists | Return file key |
| keyring read → other error | Propagate |
| keyring read → `NoEntry`, file absent | Return `None` (caller sees "no key" as before) |
| delete: both keyring and file | Both cleaned up; missing-entry / file-not-found ignored |

---

## 7. Files Changed

```
Modified:
  src/config/keychain.rs   — set_key (returns KeyStorage), get_key, delete_key + key_file_path helper
  src/wizard/mod.rs        — match on KeyStorage to print correct message (one match block)

Modified (tests):
  tests/config_test.rs     — tests for file fallback behaviour
```

---

## 8. Testing

- `keychain_file_fallback_set_and_get` — write via file path directly, verify `get_key` finds it (tests the file read path without needing a real keyring).
- `keychain_file_fallback_delete_removes_file` — write file, call delete, verify file gone.
- `keychain_get_key_returns_none_when_both_absent` — no keyring entry, no file → `None`.

`key_file_path` is `pub(crate)` so tests can write a key file directly at the returned path, then call `get_key` — which will get `NoEntry` from the keyring in test environments and fall through to the file, exercising the read path naturally.
