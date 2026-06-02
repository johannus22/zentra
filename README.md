# Zentra CLI

Zentra is an AI-powered application security CLI for developers. It scans a codebase for security risks, runs specialized scanners for threat modeling, SAST, supply chain, API, infrastructure-as-code, secrets, and reporting, and can run either locally with an interactive terminal UI or headlessly in CI.

The binary is named `zentra`.

## Features

- Interactive local scan dashboard powered by `ratatui`.
- Headless CI mode for GitHub Actions and GitLab merge request pipelines.
- LLM-backed scanner orchestration with Anthropic and OpenAI-compatible providers.
- Focused PR/MR scanning with changed-file impact analysis.
- Dynamic browser pentest mode for authorized targets.
- Markdown and JSON output under `.zentra/`.
- OS keychain storage for API keys.

## Install from source

Prerequisites:

- Rust toolchain with Cargo.
- Git.
- A configured LLM provider key, unless using a keyless/local provider.

Build and run locally:

```bash
cargo build
cargo run -- --help
```

Install the binary from the repository checkout:

```bash
cargo install --path .
zentra --help
```

## Quick start

Configure a provider profile:

```bash
zentra config setup
```

Initialize Zentra in a project:

```bash
zentra init
```

Run the interactive local scanner:

```bash
zentra scan
```

Run only one scanner family:

```bash
zentra scan --only sast
zentra scan --only supply-chain
zentra scan --only api
zentra scan --only iac
```

Run the TUI menu:

```bash
zentra
```

## CI security scanning

Zentra includes a dedicated CI command:

```bash
zentra ci
```

`zentra ci` is not just an alias for `zentra scan`. It is a headless pull request / merge request scan path that:

1. Detects GitHub Actions or GitLab CI.
2. Confirms the job is running for a PR/MR pipeline.
3. Computes changed files from the base/head diff.
4. Expands those files into a pragmatic impact set.
5. Runs focused security scanners without launching the TUI.
6. Writes CI artifacts.
7. Attempts a best-effort sticky PR/MR comment when platform token metadata is available.
8. Fails only when Critical findings are present, or when scanner/system failures occur.

### Generate GitHub Actions workflow

From the project you want to scan:

```bash
zentra init --ci github
```

This creates:

```text
.github/workflows/zentra.yml
```

The generated workflow:

- Runs on pull requests.
- Uses `actions/checkout@v4` with `fetch-depth: 0`.
- Grants `contents: read` and `pull-requests: write`.
- Runs `zentra ci`.
- Uploads `.zentra/ci-report.md` and `.zentra/ci-report.json` as artifacts.

Set your provider key as a GitHub Actions secret, for example:

```text
ZENTRA_API_KEY
```

Use the environment variable expected by your provider/profile setup.

### Generate GitLab CI workflow

From the project you want to scan:

```bash
zentra init --ci gitlab
```

If no GitLab CI file exists, this creates:

```text
.gitlab-ci.yml
```

The generated job:

- Runs for merge request pipelines.
- Sets `GIT_DEPTH: "0"` so diff detection can compare base/head history.
- Runs `zentra ci`.
- Saves `.zentra/ci-report.md` and `.zentra/ci-report.json` as artifacts.

Set your provider key in GitLab CI/CD variables, for example:

```text
ZENTRA_API_KEY
```

For merge request comments, Zentra can use GitLab token metadata when available. `CI_JOB_TOKEN` is sent with the `JOB-TOKEN` header; `GITLAB_TOKEN` is sent as bearer auth.

### CI reports

CI mode writes:

```text
.zentra/ci-report.md
.zentra/ci-report.json
```

The reports include:

- Platform and PR/MR scope.
- Base and head refs.
- Changed and impacted file counts.
- Severity summary.
- Findings and recommendations.

### CI exit policy

Default CI policy:

| Result | Pipeline behavior |
| --- | --- |
| Critical findings | Fail |
| High findings | Warn/pass |
| Medium findings | Warn/pass |
| Low findings | Warn/pass |
| Scanner/system failure | Fail |

This keeps CI useful without blocking teams for every warning.

### Architecture context in CI

Zentra stores scan state under `.zentra/`, and `.zentra/` is normally gitignored.

That means CI usually will not start with a committed `.zentra/architecture.md`. This is expected. When `zentra ci` runs and the architecture file is missing, it runs `FrameworkAnalysis` first, writes `.zentra/architecture.md` inside the CI job, and then injects that context into the remaining scanner prompts.

If `.zentra/architecture.md` already exists in the CI workspace, Zentra reuses it.

## Dynamic pentest mode

Zentra includes an authorized dynamic pentest mode for live web targets:

```bash
zentra pentest --url https://target.example --authorized
```

Pentest mode is separate from static code scanning. It is designed for controlled, authorized testing of a running application and writes its own evidence and reports under `.zentra/pentest/`.

Only run this mode against systems you own or have explicit permission to test. The `--authorized` flag is required so accidental scans fail closed.

### What pentest mode does

A pentest run combines network reconnaissance, browser-driven exploration, scoped probing, evidence capture, and report generation:

1. Validates the target URL and explicit authorization.
2. Builds an in-scope target model from allowed hosts and paths.
3. Runs Stage 0 network reconnaissance with `nmap`.
4. Starts browser-capable agents for application reconnaissance and probing.
5. Captures evidence and findings as the run progresses.
6. Writes pentest reports and an executive summary under `.zentra/pentest/`.

Pentest mode may read previous static findings from `.zentra/detailed-findings.md` to prioritize dynamic validation, but it keeps dynamic pentest output separate from static scan output.

### Scope controls

By default, the target host and all paths are in scope. Use scope flags to constrain the run:

```bash
zentra pentest --url https://target.example --authorized \
  --allow-host target.example \
  --allow-host api.target.example \
  --allow-path /app \
  --exclude-path /logout
```

Scope behavior:

- `--allow-host` can be repeated for additional hosts.
- `--allow-path` can be repeated for allowed path prefixes.
- `--exclude-path` can be repeated for paths that must not be touched.
- Path matching respects segment boundaries, so `/app` does not accidentally include `/application`.

### Network reconnaissance

Pentest mode requires `nmap` for Stage 0 service discovery.

Default mode scans common/default ports:

```bash
zentra pentest --url https://target.example --authorized
```

Full TCP mode scans all TCP ports:

```bash
zentra pentest --url https://target.example --authorized --network-full-ports
```

If `nmap` is missing, Zentra reports install guidance instead of silently skipping network recon.

### Stealth mode

Use `--stealth` for lower-concurrency probing:

```bash
zentra pentest --url https://target.example --authorized --stealth
```

Stealth mode reduces request concurrency for directory brute force and probing. It does not make testing invisible; it is only a lower-noise mode.

### Authentication

Pentest setup can run through the interactive TUI flow when launching from `zentra`, or can run in blind/unauthenticated mode from the CLI. Supported auth data in the pentest engine includes browser login details, bearer tokens, basic auth credentials, and cookies. Sensitive values are redacted from logs and reports.

### Pentest output

Pentest output is written under:

```text
.zentra/pentest/
```

Typical artifacts include:

- Living log entries for stages and agent activity.
- Captured evidence metadata.
- Finding reports with severity, impact, reproduction steps, evidence paths, and remediation.
- Network reconnaissance artifacts and summary data.
- Executive summary markdown.

## Command reference

```bash
zentra                         # interactive TUI menu
zentra init                    # create .zentra/config.json
zentra init --ci github        # create GitHub Actions workflow
zentra init --ci gitlab        # create GitLab CI job
zentra config setup            # configure provider profile
zentra config list             # list provider profiles
zentra config use <name>       # set default provider profile
zentra config show             # show active provider profile
zentra config remove <name>    # remove provider profile
zentra scan                    # local interactive scan
zentra scan --only sast        # run one scanner family
zentra ci                      # headless PR/MR CI scan
zentra pentest --url <url> --authorized
```

## Output files

Zentra writes project-local output under `.zentra/`:

```text
.zentra/config.json
.zentra/detailed-findings.md
.zentra/architecture.md
.zentra/ci-report.md
.zentra/ci-report.json
.zentra/reports/
.zentra/pentest/
```

Do not commit secrets or scan state. The init command adds `.zentra/` to `.gitignore`.

## Development

Common development commands:

```bash
cargo build
cargo test
cargo run -- --help
cargo run
cargo run scan
cargo run -- pentest --url https://target.test --authorized
```

## Security notes

- API keys should be stored in the OS keychain or CI secret store, not in project files.
- PR/MR comments are best-effort; reports and logs are still generated if comments cannot be posted.
- File tools block path traversal and cap file reads.
- Git history and dependency audit tools degrade gracefully when the required binaries/history are unavailable.
