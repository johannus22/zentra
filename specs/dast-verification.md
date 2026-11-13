# Independent DAST verification

## Contract

Discovery and exploit attempts are hypotheses. The reproduction validator gets
a fresh conversation, executes bounded in-scope HTTP requests or existing sandbox
payloads, and proposes a typed disposition. Candidate text and target/tool output
are wrapped as untrusted data. Zentra captures execution receipts outside the
container-mounted workspace: tool, arguments, command, output, and payload source
where applicable. Known credentials are redacted using the existing redactor and
sensitive JSON keys. Redaction is best-effort, not a guarantee that arbitrary
application secrets or personal data are removed.

The final reviewer has only receipt reads and record-decision tools. It must read
every citation in its own conversation and either accept the exact serialized
record digest or submit one replacement. A replacement needs a third fresh
reviewer; another replacement makes the candidate incomplete.

`runtime_verified` requires exact captured-output quotes, principal, violated
boundary, expected behavior, observed impact, reviewed controls, and a locally
validated positive CVSS v3.1 vector. `rejected` also requires runtime evidence.
`needs_validation` may lack a receipt when reproduction is blocked, but requires
the unresolved fact and a next step. Neither nonverified verdict has an assessed
severity. Candidate title/category/endpoint must match the assignment; HTTP
citations must match its exact endpoint. Receipt IDs are session-owned, not
arbitrary file paths. Provider, tool, parsing, evidence, budget, cancellation, and
persistence failures are incomplete, never model-authored rejections.

Only finalized and saved runtime-verified records become finding events,
`findings.json`, `findings.sandbox.json`, or SARIF results. The publisher rechecks
the accepted record digest and receipt hashes before generating output.
`verification.json` and `verification.md` retain all dispositions, reviewer IDs,
receipt hashes, and run status. Reports are generated even for zero findings.
Incomplete runs return an error and never emit a successful `Completed` event;
independently verified findings from other candidates can remain available.
Cancellation observed before publication invalidates those candidates; cancellation
during event delivery stops further events and marks the run incomplete.

Publication is not a multi-file filesystem transaction. An I/O failure or process
crash can leave partial report files; `verification.json` status and the process
result must be checked before treating a run as complete. Normal publication
errors attempt to persist incomplete status. If storage is unavailable that attempt
can also fail, and the error remains authoritative. Path validation rejects
traversal, symlinks and Windows reparse points but is not race-proof isolation
against concurrent host filesystem mutation. Payload source is captured before
execution; dynamic imports or changes within the container are not attested.

Budgets: 20 candidates, 60 sessions, 20 reproduction rounds, 12 final-review rounds,
four calls per response, 40 receipts/session, 256 KiB/output, 64 KiB/payload,
32 KiB/tool arguments and record, eight citations. Context budgeting uses the
configured provider window. Skipped candidates and upstream exploit failures
remain incomplete. A discovery `success` flag does not bypass reproduction.

## Model mapping

| Model action/property | Rust implementation |
| --- | --- |
| `replay` / observed | `runtime_evidence::RecordingExecutor`, host-owned receipt registration |
| `propose` | `SandboxValidatorAgent`, `ValidationOutcome::validate` |
| `check` | fresh `final_review`, independent receipt reads, exact digest acceptance |
| `replace` | one replacement, third fresh reviewer in `verify_one` |
| `invalidate` / `abortReview` | changed artifact checks, failed tools/providers/budgets/cancellation |
| `persist` | atomic per-artifact writes through `DastVerificationRun::persist` |
| `publish` | shared `verification::publish`, reports/SARIF and final TUI events |
| `safety`, `incompleteNeverGates` | no finding from unreviewed, stale, or unsaved candidate; no clean completion for incomplete run |

The single-candidate model abstracts schema validation, evidence semantics, and
filesystem/provider operations as success/failure inputs. It does not prove
exploit validity, provider accuracy, OS/container isolation, scope enforcement
inside arbitrary payload code, cross-file atomicity, or implementation conformance.
Fresh conversations may use the same configured model. Printed payload claims
are execution observations, not mechanically proven unauthorized effects; both
reviewers must assess the actual command/source/output and controls. Source-only
verification remains distinct from runtime reproduction.

## Reproduce verification

Quint 0.33.0, TypeScript backend:

```powershell
npx --offline --package @informalsystems/quint@0.33.0 quint typecheck specs/dast_verification_test.qnt
npx --offline --package @informalsystems/quint@0.33.0 quint test specs/dast_verification_test.qnt --backend typescript
npx --offline --package @informalsystems/quint@0.33.0 quint run specs/dast_verification.qnt --backend typescript --invariants safety incompleteNeverGates --witnesses replayWitness reviewWitness replacementWitness checkedWitness savedWitness runtimeWitness rejectedWitness unresolvedWitness staleWitness incompleteWitness --max-samples 1000 --max-steps 9 --seed 42
```

Phase 0 passed typechecking and seven scenarios. The 1,000 sampled traces had no
invariant violations; all witnesses were reached: replay 368, review 393,
replacement 73, checked 119, saved 36, runtime 7, rejected 14, unresolved 15,
stale 184, incomplete 964. This is sampled simulation, not exhaustive model
checking or proof of liveness.

Application verification uses scripted providers and fake sandbox execution,
without Docker, a live target, or provider accuracy benchmarking:

```powershell
cargo test --locked --test dast_verification_test --test sandbox_validator_test --test tui_test
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
cargo build --locked
```

These exercise exact quotes, session/endpoint/candidate binding, fresh read-only
reviews, replacements, changed records/receipts, operational failures, budgets,
initial/final/report persistence failures, cancellation, partial-run publication,
report/SARIF filtering, and dashboard dispositions. Build output is directed to
`C:\Users\Rafael\AppData\Local\Temp\opencode\zentra-verification-target` during
local checks and cleaned afterward. Unix-only symlink tests need a Unix host.

The initial full test build exhausted disk space during MSVC debug-symbol linking.
After cleaning that temporary target, the checks use per-command overrides
`--config profile.dev.debug=0 --config profile.test.debug=0 --config build.incremental=false`
and `--jobs 2` to reduce build output, without changing project configuration.

Final Windows results (2026-11-12):

- Full Rust suite: **1,058 passed**, zero failures, two existing live tests ignored.
- **12 DAST lifecycle integration tests**, **nine validator-tool tests**, and the
  **142-test TUI suite** passed. The payload receipt test exposed a Windows path
  separator mismatch; the run-relative construction was fixed before the full
  successful rerun.
- Clippy on all targets with `-D warnings`, the CLI build, changed-file Rust
  formatting, and `git diff --check` passed.
- DAST typechecking, seven scenarios, and the 1,000-trace sampled simulation
  passed again after implementation. The eight shared source-review scenarios
  also passed.
- No live target, Docker exploit reproduction, or live provider accuracy test
  was run. The Unix-only symlink test was not executed on this Windows host.
