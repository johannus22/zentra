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
