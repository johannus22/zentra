# Independent source verification

## Contract and implementation plan

Static discoveries are candidates. Two fresh provider conversations must review a
candidate before its final disposition is published. A source-verified record can
gate CI; it is not a runtime reproduction. Needs-validation and rejected records
retain their evidence separately. Provider, budget, schema, stale-source, and
persistence failures are incomplete verification, never successful confirmation.

1. `state/verification.rs`, `agent/verification.rs`: typed verdicts, bounded
   read-only investigation, checked citations, fresh final-record verification.
2. `agent/orchestrator.rs`, `commands/ci.rs`, `ci/exit.rs`: persist authoritative
   results, reverify carried candidates, gate only finalized source findings,
   fail ordinary CI on incomplete verification. Preserve report-only policy.
3. Reports, documentation, and fixtures: separate candidate dispositions, test
   real orchestration/provider boundaries, and run repository checks.

Each stage must preserve `safety` and `incompleteNeverGates` in
`specs/finding_verification.qnt`. One coordinator owns publication; independent
sessions communicate through returned records. The model abstracts file/schema
validation and persistence outcomes. Rust tests establish those boundaries.

## Phase 0 evidence

Quint 0.33.0 (existing cached installation), TypeScript backend:

```powershell
npx --offline --package @informalsystems/quint@0.33.0 quint typecheck specs/finding_verification_test.qnt
npx --offline --package @informalsystems/quint@0.33.0 quint test specs/finding_verification_test.qnt --backend typescript
npx --offline --package @informalsystems/quint@0.33.0 quint run specs/finding_verification.qnt --backend typescript --invariants safety incompleteNeverGates --witnesses reviewWitness replacementWitness checkedWitness savedWitness sourceVerifiedWitness rejectedWitness unresolvedWitness staleWitness incompleteWitness --max-samples 1000 --max-steps 8 --seed 42
```

Typecheck passed; eight tests passed. 1,000 sampled traces found no invariant
violation. Witnesses: review 473, replacement 108, checked 154, saved 51,
source-verified 16, rejected 19, unresolved 16, stale 184, incomplete 949.
Terminal states intentionally stop. This is sampled simulation, not exhaustive
model checking or proof that model judgments about vulnerabilities are correct.

## Provenance

The independent adversarial review, separate unresolved/rejected verdicts, and
fresh review of material replacements are adapted from Cloudflare's
`security-audit-skill` (`skills/security-audit/SKILL.md` and
`skills/security-audit/VALIDATION-AND-REPORTING.md`), reference commit
[`c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`](https://github.com/cloudflare/security-audit-skill/tree/c1c8a8c1471069fb0e188eeaff69b8e8db6564a8). See
`LICENSES/cloudflare-security-audit-skill-MIT.txt`. Zentra implements its own Rust
runtime and source-verification contract. Cloudflare's observed-result confirmation
contract is stronger than source verification; these labels are not interchangeable.

## Implementation mapping

| Model state/action | Runtime and evidence |
| --- | --- |
| candidate / review | `agent/verification.rs::verify_candidate` starts a fresh conversation, clears prior annotations, and validates a typed `Verdict` |
| check | A separate final conversation must independently read every citation and accept the exact record digest |
| replace | A complete replacement becomes the proposed record for a third fresh conversation; another disagreement is incomplete |
| invalidate / abortReview | Provider, context, turn/candidate/session budget, malformed evidence, cancellation, and changed-source errors become incomplete records |
| persist | An in-progress JSON artifact invalidates prior results before review; final JSON is written after its Markdown companion |
| publish | Only a successfully returned, persisted run is projected into findings and the `FindingsVerified` event |
| safety / incompleteNeverGates | CI replaces discovery events with the verified snapshot; severity gates and SARIF accept only `source_verified` |

`tests/verification_test.rs` uses scripted providers through the real verifier and
headless orchestrator. It checks fresh conversations, exact quotes, independent
reads, replacements, revised severity, rejection/unresolved outcomes, malicious
tool calls, failures, cancellation, stale source, initial/final persistence failure,
run caps, and TUI replacement. Orchestrator tests cover resumed and incremental
candidates. Legacy screening remains API-compatible but cannot mint the new
source-verified disposition.

## Bounds and limitations

- Normally two review sessions per candidate; at most three after a replacement.
  Limits: 50 candidates, 120 sessions/run, 12 provider rounds/session, four tool
  calls/response, 100,000 bytes/file, 32,768 bytes/decision, and 1–8 citations with
  at most 20 lines each. Listings/searches are bounded and disclose their limits.
- Reviewer access is rooted explicitly in the project, rejects traversal,
  symlinks and nonregular/oversized/non-UTF-8 files, applies the read-only security
  gate even with global safeguards disabled, and redacts known secret patterns.
  Hashes are checked between reviews and before final publication. These checks
  are not race-proof filesystem isolation against concurrent hostile mutation.
- Separate conversations may use the same configured model. Deterministic tests
  establish enforcement, not model accuracy, independent model errors, or actual
  vulnerability reproduction. No live provider accuracy benchmark was run.
- Verification completeness means all discovered candidates received dispositions;
  it does not mean complete discovery coverage. `coverage.md` describes discovery
  reads separately. Read failures or deployment facts may leave source-grounded
  candidates unresolved; failure to produce a valid record is incomplete.
- JSON is authoritative. Files are individually atomically replaced, not a
  multi-file transaction; a crash or write failure can leave Markdown newer than
  JSON. Such errors propagate and no finalized findings event is published.
- Report-only CI remains non-blocking for scanner/verification errors. Ordinary
  CI fails on those errors; the generated workflow uploads verification artifacts
  even when the scan fails. Filesystem/setup errors still propagate in either mode.

## Implementation checks

Run Rust checks with an external target directory to avoid repository artifacts:

```powershell
$env:CARGO_TARGET_DIR = "$env:LOCALAPPDATA\Temp\opencode\zentra-verification-target"
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked
git diff --check
```

Results on Windows (2026-11-12):

- Full `cargo test --locked`: **1,042 passed**, zero failures; two existing tests
  ignored (live cargo-audit/advisory access and Docker/httpbin smoke test).
- All **14 verification integration tests** passed, including real headless CI
  orchestration, initial/final persistence failures, and candidate/session caps.
- `cargo clippy --locked --all-targets -- -D warnings`: passed.
- `cargo build --locked`: passed.
- `rustfmt --check --edition 2021 --config skip_children=true` on changed Rust
  files, plus `git diff --check`: passed. Formatting was scoped to changed files.
- Quint typechecking, eight scenarios, and the 1,000-trace simulation above were
  rerun successfully after implementation. This was not exhaustive model checking.
- The Unix-only symlink regression was added but was not executed on this Windows
  host. No live provider benchmark or runtime exploit reproduction was performed.

The external Cargo target directory was cleaned after the checks.
