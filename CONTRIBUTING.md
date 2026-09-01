# Contributing to Zentra

Thanks for helping improve Zentra. Contributions should keep the interactive
`zentra` TUI approachable while preserving reliable headless operation for CI
and automation.

## Before You Start

- Search existing issues and pull requests before starting duplicate work.
- Open an issue or discussion before a large feature, architectural change, or
  user-visible behavior change.
- Do not disclose suspected vulnerabilities in a public issue. Use the
  repository's private vulnerability reporting channel or contact a maintainer
  privately.
- Never commit API keys, OAuth material, credentials, `.zentra/` scan state, or
  evidence from systems you do not have permission to test.

## Development Setup

You need the stable Rust toolchain and Git. Pentest development also requires a
running Docker Desktop or Docker Engine installation. Linux builds need the
development package for `libdbus` because the keyring backend links against it.

```bash
git clone https://github.com/johannus22/zentra.git
cd zentra
cargo build --locked
cargo run
```

Use `zentra` or `cargo run` to explore the primary interactive experience.
Direct commands such as `cargo run -- scan --full` and headless CI mode remain
important secondary paths.

## Branch Workflow

1. Start from the latest `develop` branch.
2. Create a focused branch such as `feat/<topic>`, `fix/<topic>`,
   `docs/<topic>`, `test/<topic>`, or `chore/<topic>`.
3. Open the pull request against `develop`, not `main`.
4. Address review comments and keep required checks green.
5. Maintainers promote `develop` to `main` through a separate pull request.

The `main` branch accepts merges only from this repository's `develop` branch.
Both branches require pull requests, signed commits, approval, resolved review
conversations, and required CI checks. Do not force-push shared branches.

## Code Conventions

- Use Rust 2021 idioms and follow the existing module structure.
- Prefer the smallest correct change. Avoid speculative compatibility layers,
  unnecessary abstractions, and unrelated cleanup.
- Format Rust code with `cargo fmt` and keep Clippy warning-free.
- Keep terminal behavior usable on Windows, macOS, Linux, and narrow terminals.
- Preserve exhaustive event handling. Update every match site when adding an
  event variant such as `ScanEvent` or `PentestEvent`.
- Route scanner tools through `ToolRegistry` and `SecurityGate`; never bypass
  authorization, scope, audit, prompt-guard, or response-binding controls.
- Keep provider retries and response-size limits on their centralized paths.
- Redact sensitive data before writing logs or persistent output.
- Add comments only when the reason for non-obvious code is not clear from the
  implementation itself.

## Tests

Run the checks that match CI before requesting review:

```bash
cargo fmt --all -- --check
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
cargo build --locked
```

Tests that change the process working directory must hold the shared
`CWD_LOCK`. Use `tempfile::TempDir` for filesystem isolation and
`wiremock::MockServer` for HTTP provider tests. Changes to platform-specific
code must account for the Linux, macOS, and Windows CI matrix.

For pentest changes, test only systems you own or are explicitly authorized to
assess. Keep live Docker tests opt-in and deterministic tests isolated from the
network where possible.

## Documentation

Update `README.md` and `architecture.mmd` when changing a user-visible command,
scanner, output format, workflow, or security control. Keep examples safe to
run and clearly label intentionally vulnerable test targets such as OWASP Juice
Shop.

## Commits and Pull Requests

- Use concise, imperative commit subjects with a conventional prefix, for
  example `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, or `chore:`.
- Sign commits so protected branches can accept them.
- Keep each pull request focused and explain the behavior changed and why.
- Include the commands used for validation and call out tests that could not be
  run.
- Include screenshots for meaningful TUI changes, with private paths, account
  names, tokens, and other identifying data removed.

By submitting a contribution, you agree that it is licensed under the
repository's Apache-2.0 license.
