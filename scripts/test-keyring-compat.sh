#!/usr/bin/env bash
# Opt-in integration evidence. Linux needs libdbus development files,
# dbus-run-session, dbus-monitor, dbus-send, and gnome-keyring-daemon.
# macOS temporarily switches the default keychain to a disposable test keychain.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
os=$(uname -s)
if [[ $os == Linux && ${ZENTRA_ISOLATED_DBUS_TEST:-} != 1 ]]; then
    exec dbus-run-session -- env ZENTRA_ISOLATED_DBUS_TEST=1 bash "$0"
fi
tmp=$(mktemp -d)
monitor_pid=
daemon_pid=
previous_keychain=
test_keychain=
cleanup() {
    if [[ -n $monitor_pid ]]; then kill "$monitor_pid" 2>/dev/null || true; fi
    if [[ -n $daemon_pid ]]; then kill "$daemon_pid" 2>/dev/null || true; wait "$daemon_pid" || true; fi
    if [[ -n $previous_keychain ]]; then security default-keychain -d user -s "$previous_keychain"; fi
    if [[ -n $test_keychain ]]; then security delete-keychain "$test_keychain"; fi
    rm -rf "$tmp"
}
trap cleanup EXIT
export XDG_DATA_HOME="$tmp/data" XDG_CONFIG_HOME="$tmp/config" XDG_CACHE_HOME="$tmp/cache"
export XDG_RUNTIME_DIR="$tmp/runtime"
mkdir -p "$XDG_RUNTIME_DIR" "$tmp/old/src"
chmod 700 "$XDG_RUNTIME_DIR"
unset ZENTRA_NO_OS_KEYCHAIN
export ZENTRA_ISOLATED_CREDENTIAL_TEST=1
if [[ $os == Linux ]]; then
gnome-keyring-daemon --foreground --unlock --components=secrets \
    <<< 'zentra-synthetic-test-password' > "$tmp/daemon.log" 2>&1 &
daemon_pid=$!
# Wait for our daemon, not D-Bus activation of another daemon.
for attempt in {1..50}; do
    if dbus-send --session --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus \
        org.freedesktop.DBus.NameHasOwner string:org.freedesktop.secrets | grep -q true; then break; fi
    kill -0 "$daemon_pid"
    sleep 0.1
done
dbus-send --session --print-reply --dest=org.freedesktop.secrets /org/freedesktop/secrets \
    org.freedesktop.Secret.Service.ReadAlias string:default
elif [[ $os == Darwin ]]; then
    previous_keychain=$(security default-keychain -d user | sed 's/^[[:space:]]*"//;s/"$//')
    test_keychain="$tmp/zentra-test.keychain-db"
    security create-keychain -p zentra-test-password "$test_keychain"
    security unlock-keychain -p zentra-test-password "$test_keychain"
    security set-keychain-settings -lut 21600 "$test_keychain"
    security default-keychain -d user -s "$test_keychain"
else
    echo "Unsupported credential-test platform: $os" >&2
    exit 1
fi
cat > "$tmp/old/Cargo.toml" <<'TOML'
[package]
name = "zentra-keyring-v3-fixture"
version = "0.0.0"
edition = "2021"
[dependencies]
keyring = "=3.6.3"
aes-gcm = "0.10"
base64 = "0.22"
[target.'cfg(target_os = "linux")'.dependencies]
keyring = { version = "=3.6.3", features = ["sync-secret-service", "crypto-rust"] }
dbus-secret-service = { version = "4.1.0", features = ["crypto-rust"] }
[target.'cfg(target_os = "macos")'.dependencies]
keyring = { version = "=3.6.3", features = ["apple-native"] }
TOML
cp "$root/tests/fixtures/keyring_v3_writer.rs" "$tmp/old/src/main.rs"
# A separate temporary project keeps old keyring out of Zentra's dependency graph.
cargo build --manifest-path "$tmp/old/Cargo.toml" --target-dir "$tmp/old-target"
export ZENTRA_KEYRING_V3_FIXTURE="$tmp/old-target/debug/zentra-keyring-v3-fixture"
export ZENTRA_CREDENTIAL_TEST_SERVICE="zentra-test-$(date +%s)-$$-$RANDOM"
# Compile the exact production credential modules in a small temporary harness,
# avoiding unrelated CLI/TLS dependencies. Reuse the application's locked versions.
mkdir -p "$tmp/new/src/config"
cp "$root/src/config/credential_store.rs" "$root/src/config/secret_store.rs" "$tmp/new/src/config/"
printf '%s\n' 'mod config { pub(crate) mod credential_store; pub mod secret_store; }' > "$tmp/new/src/lib.rs"
version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$root/Cargo.toml" | head -n 1)
cat > "$tmp/new/Cargo.toml" <<TOML
[package]
name = "zentra-cli"
version = "$version"
edition = "2021"
[dependencies]
anyhow = "1"
aes-gcm = "0.10"
base64 = "0.22"
rand = "0.8"
keyring-core = "1.0.1"
tempfile = "3"
[target.'cfg(target_os = "linux")'.dependencies]
dbus-secret-service-keyring-store = { version = "1.0.1", features = ["crypto-rust"] }
dbus-secret-service = { version = "4.1.0", features = ["crypto-rust"] }
[target.'cfg(target_os = "macos")'.dependencies]
apple-native-keyring-store = { version = "1.0.2", features = ["keychain"] }
TOML
cp "$root/Cargo.lock" "$tmp/new/Cargo.lock"
cargo update --workspace --quiet --manifest-path "$tmp/new/Cargo.toml"
cargo test --lib --no-run --locked --manifest-path "$tmp/new/Cargo.toml" --message-format=json > "$tmp/build.json"
new_bin=$(sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' "$tmp/build.json")
[[ -x $new_bin ]]
if [[ $os == Darwin ]]; then
    # Public APIs only: create placeholder items already trusting both test
    # binaries. The old library, not this setup, writes all expected test data.
    # This tests old-written data, not preservation of old creator-only ACLs.
    codesign --force --sign - --timestamp=none "$ZENTRA_KEYRING_V3_FIXTURE"
    codesign --force --sign - --timestamp=none "$new_bin"
    old_hash=$(codesign -d --verbose=4 "$ZENTRA_KEYRING_V3_FIXTURE" 2>&1 | sed -n 's/^CDHash=//p')
    new_hash=$(codesign -d --verbose=4 "$new_bin" 2>&1 | sed -n 's/^CDHash=//p')
    [[ $old_hash =~ ^[0-9a-f]{40}$ && $new_hash =~ ^[0-9a-f]{40}$ ]]
    authorize_item() {
        security add-generic-password -s "$1" -a "$2" \
            -T "$ZENTRA_KEYRING_V3_FIXTURE" -T "$new_bin" \
            -w 'uninitialized-synthetic-placeholder' "$test_keychain"
        security set-generic-password-partition-list -s "$1" -a "$2" \
            -S "apple-tool:,cdhash:$old_hash,cdhash:$new_hash" \
            -k zentra-test-password "$test_keychain" > /dev/null
    }
    for account in secret-store-key-v1 api_key oauth_tokens new_user; do
        authorize_item "$ZENTRA_CREDENTIAL_TEST_SERVICE" "$account"
    done
    authorize_item "$ZENTRA_CREDENTIAL_TEST_SERVICE-legacy" api_key
fi
if [[ $os == Linux ]]; then
dbus-monitor --session "type='method_call',interface='org.freedesktop.Secret.Service',member='OpenSession'" \
    > "$tmp/sessions.log" 2> "$tmp/monitor.log" &
monitor_pid=$!
fi
"$new_bin" --exact config::secret_store::tests::v3_credentials_remain_usable --ignored --nocapture
if [[ $os == Linux ]]; then
kill "$monitor_pid"
wait "$monitor_pid" || true
monitor_pid=
grep -q 'dh-ietf1024-sha256-aes128-cbc-pkcs7' "$tmp/sessions.log"
if grep -q 'string "plain"' "$tmp/sessions.log"; then
    echo 'Plaintext Secret Service session detected' >&2
    exit 1
fi
echo 'Old/new credentials and envelopes interoperated; DH observed and no plaintext sessions observed.'
else
    echo 'Old/new credentials and envelopes interoperated in the disposable macOS login keychain.'
fi
