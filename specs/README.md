# Executable specifications

## Independent finding verification

`finding_verification.qnt` models a candidate's source-review lifecycle: initial
review, independent final review, one material replacement, stale evidence,
operational failure, persistence, and publication. `safety` forbids publication
without saved, current evidence and a different final reviewer;
`incompleteNeverGates` prevents failed candidates from being published.

See [the contract, implementation mapping, and checks](finding-verification.md).

## Independent DAST verification

`dast_verification.qnt` reuses the independent review lifecycle and requires a
captured runtime observation before a `runtime_verified` verdict. Its scenarios
cover reproduction, unresolved/rejected dispositions, replacement re-review,
changed evidence, and operational/persistence failure. See
[the DAST contract, mapping, and checks](dast-verification.md).

# Cargo audit execution contract

`cargo_audit.qnt` models one invocation of `src/tools/audit.rs`. One state record
tracks preparation, execution, report acceptance, persistence, and publication.
The model assumes a trusted installed binary and operating system. It abstracts
filesystem and process operations into success/failure inputs; Rust tests must
establish that real command construction satisfies the isolation assumption.

## Mapping and evidence plan

| Model action/property | Implementation obligation |
| --- | --- |
| prepare / reject | Require an existing regular lockfile; copy it outside the target; select an absolute executable outside the target; isolate config |
| launch | Invoke cargo-audit directly, with an explicit copied lockfile, never Cargo |
| finish | Validate report structure and exit status; failures cannot be reported as clean |
| save | Preserve full stdout/stderr/status before publishing a completed result; report persistence errors |
| safety | Launch only after preparation; publish every matched vulnerability/warning only for an accepted, saved report |

The small finding count abstracts both vulnerabilities and warnings, including
patched/unaffected ranges. Implementation validation can be stricter than the
model's exit-1 guard (for example requiring denied-warning evidence). There is no
claim of dependency reachability: these are lockfile matches. The model does not
model Git transport internals, parser vulnerabilities, OS sandboxing, or active
build features. Filesystem path checks assume the scanned checkout is not being
concurrently replaced by a hostile process; they are not handle-relative,
race-proof filesystem confinement. Successful and failed invocations terminate
intentionally.

## Reproduce

Quint 0.33.0, TypeScript backend (no backend download needed):

```powershell
npx --yes --package @informalsystems/quint@0.33.0 quint typecheck specs/cargo_audit_test.qnt
npx --yes --package @informalsystems/quint@0.33.0 quint test specs/cargo_audit_test.qnt --backend typescript
npx --yes --package @informalsystems/quint@0.33.0 quint run specs/cargo_audit.qnt --backend typescript --invariant safety --witnesses preparedWitness launchedWitness receivedWitness successWitness failureWitness --max-samples 1000 --max-steps 5 --seed 42
```

Initial validation: typecheck passed; six scenarios passed; 1,000 sampled traces
had no safety violation. Witness counts: prepared 500, launched 500, received 500,
successful findings 61, failure 924. This is sampled simulation, not exhaustive
model checking or proof of implementation conformance.

Update and revalidate the model before changing this execution contract. Keep
runtime command tests, report fixtures, and repository checks alongside model
validation as the evidence path.

An opt-in installed-tool check exercises a real audit against a temporary
lockfile with malformed project Cargo/audit configuration (requires network):

```powershell
cargo test --locked --test cargo_audit_live_test -- --ignored --nocapture
```

## Implementation verification

Validated on Windows with Rust/Cargo 1.94.1 and installed cargo-audit 0.22.2:

- `cargo test --locked`: 1,021 passed, two opt-in tests ignored. After the final
  review refinements, `cargo test --locked cargo_`: all eight wrapper tests and
  the dispatch/root test passed (including the added metadata/filter regression).
- The opt-in live test above passed against the final implementation: a fresh
  public database fetch and audit completed despite malformed target
  `.cargo/config.toml` and `.cargo/audit.toml`; the source lockfile stayed intact
  and the raw report artifact was created.
- `cargo clippy --all-targets --locked -- -D warnings`: passed.
- `rustfmt --edition 2021 --check src/tools/audit.rs tests/cargo_audit_live_test.rs`
  and `git diff --check`: passed. Existing formatting differences elsewhere in
  `tests/agent_test.rs` were left untouched.

Cargo commands used `--target-dir
C:\Users\Rafael\AppData\Local\Temp\opencode\zentra-audit-target` for isolated
build output. Unix-only symlink tests are included but were not executed on this
Windows host. Independent review led to stricter metadata, filter, and exit-status
consistency checks; schema rejection is conservative when an incompatible tool
version returns a different format.

## Credential-store migration contract

`credential_store.qnt` and `credential_store_test.qnt` cover sequential Unix DEK
reuse/creation, legacy cleanup, encrypted reads, plaintext fallback, and failed
persistence. A single cohesive state record models one client and an abstract
store. Existing/malformed keys must never be replaced; encrypted reads cannot
create keys or succeed without the original key. Successful key creation is
reachable only after persistence succeeds. Operations terminate intentionally.

| Model | Implementation/evidence |
| --- | --- |
| upgrade | `config/credential_store.rs`: explicit platform stores, unchanged identities; old/new live compatibility fixture |
| read | `secret_store::decrypt`, `envelope::decode_dek` and `open`; missing/malformed/ambiguous key tests |
| write | `load_or_create_dek_with`, `encrypt`, `seal`; reuse and failed-persistence tests |
| cleanupLegacy | `keychain` stale-entry deletion; live synthetic API/OAuth/targetless credential tests |

The model does **not** prove cryptography, encrypted D-Bus negotiation, OS-store
attribute matching, macOS access controls, file-write atomicity, concurrent
first-key creation, or implementation conformance. Those require implementation
tests and source review. Linux keeps keyring 3.6.3's exact lookup order:
service-wide `service+username+target=default`, then only on no matches a
default-collection search omitting target. That old fallback does not filter
target-bearing items in the default collection; this migration does not tighten
or broaden it. Errors/ambiguity never trigger a broader search or key replacement.

```powershell
npx --yes --package @informalsystems/quint@0.33.0 quint typecheck specs/credential_store_test.qnt
npx --yes --package @informalsystems/quint@0.33.0 quint test specs/credential_store_test.qnt --backend typescript
npx --yes --package @informalsystems/quint@0.33.0 quint run specs/credential_store.qnt --backend typescript --invariant safety --witnesses upgradedWitness readWitness writeWitness createWitness fallbackWitness cleanupWitness --max-samples 1000 --max-steps 3 --seed 42
```

Phase 0: typecheck passed, ten scenarios passed, 1,000 sampled traces had no safety
violation. Witness counts: upgraded 1,000; read 347; encrypted write 154; create
53; plaintext fallback 499; cleanup 255. This is sampled simulation, not exhaustive
model checking. Update and revalidate before changing these transitions.

Linux live compatibility (approved test prerequisites: libdbus development files,
pkg-config, gnome-keyring, dbus-run-session, dbus-monitor, dbus-send):

```bash
bash scripts/test-keyring-compat.sh
```

The script creates a fresh D-Bus session and temporary keyring directories. It
builds the frozen keyring 3.6.3 writer in a separate temporary project, never in
Zentra's dependency graph. Only unique `zentra-test-*` credentials are accessed.
It checks old/new DEK reuse, both envelope directions, API/OAuth credentials,
targetless fallback, updates/deletion, and new credentials visible to the old
client. A D-Bus monitor must observe DH negotiation and no plaintext session.
Regular CI's headless fallback tests alone do not establish these properties.

The same script on macOS temporarily makes a disposable keychain the User/login
default, restores the previous default on exit, and checks both envelope
directions and legacy credentials there. Public Keychain tools pre-create
synthetic placeholders trusting both ad-hoc signed test binaries; the old
library then writes the actual test values. This checks old-written data and
identity compatibility, **not** creator-only ACL preservation or prompt-free
authorization of an upgraded user binary. Both binaries disable interactive
prompts during tests. Linux additionally checks ambiguous
primary and legacy matches cannot be read, overwritten, or arbitrarily deleted.
Both jobs compile the exact production credential modules in a temporary minimal
harness using versions from the application's lockfile; the separate regular
platform jobs test and lint the full application.

Local implementation evidence (Windows Rust 1.94.1 and Linux WSL): the 23-test
targeted configuration suite passed, then the full Windows suite passed 1,027
tests (two opt-in tests ignored) and Clippy passed with warnings denied. The isolated Linux compatibility check
passed, including primary/legacy ambiguity rejection and DH-only negotiation.
macOS live compatibility is checked by the dedicated CI job, not inferred from
Windows or Linux results. A full Linux CLI build on WSL requires additional
OpenSSL development headers; the live harness deliberately compiles only the
unchanged copies of production credential modules, not a substitute backend.
