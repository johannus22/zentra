# Changelog

## 0.16.0

### Independent finding verification

- Static candidates now receive a fresh read-only source review and a separate
  final-record review before becoming source-verified findings or CI severity
  gates. Source verification does not claim runtime reproduction.
- DAST confirmation now requires host-captured execution receipts and independent
  final-record review. Model-written evidence and exploit success flags alone
  cannot confirm vulnerabilities.
- Reports retain `needs_validation`, rejected, and incomplete dispositions;
  SARIF exports only independently verified findings. Dashboards distinguish
  unresolved leads from confirmed findings and operational failures.
- Changed evidence, invalid records, failed providers/tools, exhausted budgets,
  cancellation, and persistence failures cannot produce clean verification.
- A changed final record receives another fresh reviewer. Further disagreement
  leaves verification incomplete.

### Compatibility and operational notes

- Ordinary static CI blocks on source-verified severity and fails on incomplete
  verification. Report-only CI remains non-blocking for verification errors.
- Verification adds provider usage: normally two fresh conversations per
  candidate, at most three when a record is replaced. The same configured model
  may perform these reviews; separate conversations do not guarantee independent
  model errors.
- Static verification artifacts live under `.zentra/verification.{json,md}`;
  DAST artifacts live in the pentest output directory, with execution receipts
  under `evidence/runtime/`. Consumers should inspect run completeness even when
  the findings list is empty.
- The Rust DAST `ValidationOutcome` now uses typed verdicts and citations instead
  of `confirmed`/`evidence_path`; `VerificationCompleted` replaces the boolean
  `ValidationCompleted` event.

### Release hardening

- Update transitive `openssl` to 0.10.80 and `rustix` to 1.1.6 to address
  RUSTSEC-2026-0474, RUSTSEC-2026-0476, RUSTSEC-2026-0477, and
  RUSTSEC-2026-0486. Update the required `openssl-sys` binding to 0.9.118.
- Include third-party notices and licenses in platform archives and Docker images.

See [static verification](specs/finding-verification.md) and
[DAST verification](specs/dast-verification.md) for contracts, limits, and evidence.
