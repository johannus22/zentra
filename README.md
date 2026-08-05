# Zentra CLI

Zentra is an AI-powered application security CLI for developers. It scans a codebase for security risks. It runs specialized scanners for threat models, static analysis (SAST), supply chain risks, APIs, infrastructure as code, secrets, and reports. You can run Zentra locally, with an interactive terminal interface. You can also run Zentra in headless mode, in a CI pipeline.

The binary is named `zentra`.

## Features

- Interactive local scan dashboard powered by `ratatui`.
- Headless CI mode for GitHub Actions and GitLab merge request pipelines.
- LLM-backed scanner orchestration with Anthropic and OpenAI-compatible providers.
- Focused PR/MR scanning with changed-file impact analysis.
- Dynamic browser pentest mode for authorized targets.
- Markdown and JSON output under `.zentra/`.
- Encrypted-at-rest credential storage (DPAPI on Windows, `0600` files on Unix).

## Installation

### Quick install (recommended)

This method uses prebuilt binaries. You do not need the Rust toolchain, a repository clone, or a build step.

**Linux and macOS:**

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/johannus22/zentra-cli/releases/latest/download/zentra-cli-installer.sh | sh
```

**Windows (PowerShell):**

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://github.com/johannus22/zentra-cli/releases/latest/download/zentra-cli-installer.ps1 | iex"
```

The installer detects your operating system and CPU architecture. It downloads the matching release binary. It installs `zentra` and adds it to your `PATH`. Open a new terminal window afterward, or follow the on-screen instructions, so `zentra` is available. Then verify the install:

```bash
zentra --help
```

To install by hand, download a build from the [Releases page](https://github.com/johannus22/zentra-cli/releases). Extract the `zentra` binary.

> **Linux note:** The binary links to `libdbus` at runtime, for access to the OS keyring. Most desktop distributions already include it. On a minimal or headless image, install it first (`sudo apt-get install -y libdbus-1-3`, or the equivalent command for your distribution). Or set `ZENTRA_NO_OS_KEYCHAIN=1` to use the encrypted file-based credential store instead.

You still need a configured LLM provider key, unless you use a keyless or local provider. See [Quick start](#quick-start).

### Install from source

Prerequisites:

- Rust toolchain with Cargo.
- Git.
- A configured LLM provider key, unless you use a keyless or local provider.

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

Run the TUI (terminal interface) menu:

```bash
zentra
```

## CI security scanning

Zentra includes a dedicated CI command:

```bash
zentra ci
```

`zentra ci` is not an alias for `zentra scan`. It is a headless scan path for pull request and merge request pipelines. It does the following:

1. Detects GitHub Actions or GitLab CI.
2. Confirms that the job runs in a PR/MR pipeline.
3. Computes the changed files from the base/head diff.
4. Expands those files into a practical impact set.
5. Runs focused security scanners, with no TUI.
6. Writes CI artifacts.
7. Tries to post a sticky PR/MR comment, when platform token metadata is available. This step is best-effort.
8. Fails only for two reasons: findings at or above the fail threshold, or a scanner or system failure.

### Fail threshold (blocking severity)

By default, `zentra ci` blocks the PR/MR on any **Critical or High** finding. Medium, Low, and Info findings are reported but do not fail the job.

The threshold is configurable, in order of precedence:

1. `ZENTRA_CI_FAIL_THRESHOLD` environment variable — set this in the CI job or as a repo/group secret. Takes one of `critical`, `high`, `medium`, `low`, `info` (case-insensitive).
2. `fail_threshold` field in `.zentra/config.json` — commit this to persist the policy for every run, without touching pipeline config.
3. Default: `high` (blocks High and Critical).

Example — only block on Critical, in GitHub Actions:

```yaml
- name: Run Zentra CI
  env:
    ZENTRA_API_KEY: ${{ secrets.ZENTRA_API_KEY }}
    ZENTRA_PROVIDER_BASE_URL: ${{ secrets.ZENTRA_PROVIDER_BASE_URL }}
    ZENTRA_PROVIDER_MODEL: ${{ vars.ZENTRA_PROVIDER_MODEL }}
    ZENTRA_CI_FAIL_THRESHOLD: critical
  run: zentra ci
```

Example — persist the same policy in `.zentra/config.json` instead:

```json
{
  "target_path": ".",
  "stack": "rust",
  "exclusions": [],
  "fail_threshold": "critical"
}
```

Set `critical` to block on Critical findings only. This is more permissive than the default.

Set `medium`, `low`, or `info` to block on lower-severity findings too. This is stricter than the default.

### Generate GitHub Actions workflow

Run this command from the project you want to scan:

```bash
zentra init --ci github
```

This creates:

```text
.github/workflows/zentra.yml
```

The generated workflow does the following:

- Runs on pull requests.
- Uses `actions/checkout@v4` with `fetch-depth: 0`.
- Grants `contents: read` and `pull-requests: write`.
- Installs the `zentra` binary via the release installer script.
- Runs `zentra ci`.
- Uploads `.zentra/ci-report.md` and `.zentra/ci-report.json` as artifacts.

`zentra ci` reads provider credentials from the environment variables below. This lets it run on a fresh runner, with no `~/.zentra/config.toml` file and no keychain. Set these variables under **Settings → Secrets and variables → Actions**:

| Variable | Required | Notes |
|---|---|---|
| `ZENTRA_API_KEY` | yes | Secret — the LLM provider API key. |
| `ZENTRA_PROVIDER_BASE_URL` | yes | Secret or variable — for example `https://api.anthropic.com`, or your OpenAI-compatible endpoint. |
| `ZENTRA_PROVIDER_MODEL` | yes | Variable — for example `claude-sonnet-5` or `glm-4.6`. |
| `ZENTRA_PROVIDER_KIND` | no | Defaults to `openai_compat`. Set to `anthropic` to use the native Anthropic provider. |
| `ZENTRA_PROVIDER_REASONING_EFFORT` | no | Passes through to OpenAI-compatible providers. |
| `ZENTRA_PROVIDER_CONTEXT_WINDOW` | no | Overrides the provider's default context window. |
| `ZENTRA_CI_FAIL_THRESHOLD` | no | Minimum severity that blocks the PR. Defaults to `high`. See [Fail threshold](#fail-threshold-blocking-severity). |

If none of `ZENTRA_API_KEY`, `ZENTRA_PROVIDER_BASE_URL`, or `ZENTRA_PROVIDER_MODEL` are set, `zentra ci` falls back to the profile you configured with `zentra config setup`, in `~/.zentra/config.toml`.

### Generate GitLab CI workflow

Run this command from the project you want to scan:

```bash
zentra init --ci gitlab
```

If no GitLab CI file exists, this creates:

```text
.gitlab-ci.yml
```

The generated job does the following:

- Runs for merge request pipelines.
- Sets `GIT_DEPTH: "0"`, so diff detection can compare the base and head history.
- Runs `zentra ci`.
- Saves `.zentra/ci-report.md` and `.zentra/ci-report.json` as artifacts.

Set your provider key in a GitLab CI/CD variable, for example:

```text
ZENTRA_API_KEY
```

For merge request comments, Zentra can use GitLab token metadata when available. It sends `CI_JOB_TOKEN` with the `JOB-TOKEN` header. It sends `GITLAB_TOKEN` as bearer auth.

### CI reports

CI mode writes:

```text
.zentra/ci-report.md
.zentra/ci-report.json
```

The reports include:

- The platform and PR/MR scope.
- The base and head refs.
- The changed and impacted file counts.
- A severity summary.
- Findings and recommendations.

### CI exit policy

Default CI policy (no `ZENTRA_CI_FAIL_THRESHOLD` and no `fail_threshold` in `.zentra/config.json`):

| Result | Pipeline behavior |
| --- | --- |
| Critical findings | Fail |
| High findings | Fail |
| Medium findings | Warn/pass |
| Low findings | Warn/pass |
| Scanner/system failure | Fail |

This is the fail threshold, and it is configurable. See [Fail threshold](#fail-threshold-blocking-severity) above to change it, for example to fail only on Critical, or to also fail on Medium.

The default keeps CI useful without blocking teams on every Medium or Low warning, while still catching the two severities worth an automatic stop.

### Architecture context in CI

Zentra stores scan state under `.zentra/`. Projects normally add `.zentra/` to `.gitignore`.

So CI usually starts with no committed `.zentra/architecture.md` file. This is expected. When `zentra ci` runs and the architecture file is missing, it runs `FrameworkAnalysis` first. This step writes `.zentra/architecture.md` inside the CI job, then injects that context into the remaining scanner prompts.

If `.zentra/architecture.md` already exists in the CI workspace, Zentra reuses it.

## Dynamic pentest mode

Zentra includes an authorized dynamic pentest mode for live web targets:

```bash
zentra pentest --url https://target.example --authorized
```

Pentest mode is separate from static code scanning. Use it for controlled, authorized testing of a running application. It writes its own evidence and reports under `.zentra/pentest/`.

Only run this mode against systems you own, or have explicit permission to test. The `--authorized` flag is required, so an accidental scan fails closed.

### What pentest mode does

A pentest run combines network reconnaissance, browser-driven exploration, scoped probing, evidence capture, and report generation. It does the following:

1. Validates the target URL and explicit authorization.
2. Builds an in-scope target model, from the allowed hosts and paths.
3. Runs Stage 0 network reconnaissance with `nmap`.
4. Starts browser-capable agents, for application reconnaissance and probing.
5. Captures evidence and findings as the run progresses.
6. Writes pentest reports and an executive summary under `.zentra/pentest/`.

Pentest mode may read previous static findings from `.zentra/detailed-findings.md`, to prioritize dynamic validation. In project mode (with `.zentra/config.json`), pentest findings sit alongside scan output. In standalone mode, pentest output stays separate, in the configured base directory.

### Scope controls

By default, the target host and all its paths are in scope. Use scope flags to limit the run:

```bash
zentra pentest --url https://target.example --authorized \
  --allow-host target.example \
  --allow-host api.target.example \
  --allow-path /app \
  --exclude-path /logout
```

Scope behavior:

- Repeat `--allow-host` for each additional host.
- Repeat `--allow-path` for each allowed path prefix.
- Repeat `--exclude-path` for each path the run must not touch.
- Path matching respects segment boundaries. So `/app` does not match `/application` by accident.

### Network reconnaissance

Pentest mode requires `nmap`, for Stage 0 service discovery.

Default mode scans common and default ports:

```bash
zentra pentest --url https://target.example --authorized
```

Full TCP mode scans all TCP ports:

```bash
zentra pentest --url https://target.example --authorized --network-full-ports
```

If `nmap` is missing, Zentra reports install guidance. It does not silently skip network recon.

### Stealth mode

Use `--stealth` for lower-concurrency probing:

```bash
zentra pentest --url https://target.example --authorized --stealth
```

Stealth mode reduces request concurrency for directory brute force and probing. It does not make testing invisible. It is only a lower-noise mode.

### Authentication

Pentest setup can run through the interactive TUI flow, when you launch from `zentra`. It can also run in blind or unauthenticated mode from the CLI. The pentest engine supports browser login details, bearer tokens, basic auth credentials, and cookies. It redacts sensitive values from logs and reports.

### Pentest output

The pentest output location depends on where you run the command:

| Context | Output directory |
| --- | --- |
| Inside an initialized Zentra project with `.zentra/config.json` | `./.zentra/pentest/<host>/<run-id>/` |
| Outside an initialized project | `<Documents>/Zentra/pentest/<host>/<run-id>/` (or configured `output_dir`) |

Standalone pentest mode does not create `.zentra/config.json`. It does not edit `.gitignore` in the current directory. Zentra prints the resolved output directory when the run starts.

Typical artifacts include:

- Living log entries for stages and agent activity.
- Captured evidence metadata.
- Finding reports, with severity, impact, reproduction steps, evidence paths, and remediation.
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

Do not commit secrets or scan state. The `init` command adds `.zentra/` to `.gitignore`.

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

- Zentra stores API keys and OAuth tokens under `~/.zentra/keys/`. It encrypts them at rest, with DPAPI on Windows and `0600` permissions on Unix. Credentials saved by an older version keep working — this includes plaintext key files, and OAuth tokens in the OS keychain. Zentra migrates them the next time you save them. In automated environments, use a CI secret store, not project files.
- PR/MR comments are best-effort. Zentra still generates reports and logs if it cannot post a comment.
- File tools block path traversal and cap file reads.
- Git history and dependency audit tools degrade gracefully when the required binaries or history are unavailable.

### Dependency audit

CI checks dependency advisories with [`cargo-audit`](https://github.com/rustsec/rustsec) (`.github/workflows/audit.yml`). This workflow runs on pushes and PRs that touch `Cargo.toml` or `Cargo.lock`, and on a weekly schedule. To run it locally:

```bash
cargo install cargo-audit
cargo audit
```
