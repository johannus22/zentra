# CLAUDE.md

This file gives guidance to Claude Code (claude.ai/code), for work on code in this repository.

> This file is the Claude Code entry point. See the project vault notes (`projects/zentra-cli/architecture/`) for the extended architecture reference and vault links.

## Commands

```bash
cargo build
cargo test
cargo test <test_name>                                      # single test by name
cargo run                                                   # TUI menu (no args)
cargo run -- scan                                          # CLI scan with default profile
cargo run -- pentest --url https://target.test --authorized
cargo run -- init                                          # create .zentra/config.json
cargo run -- config setup                                  # interactive provider wizard
```

## Architecture

**zentra-cli** is a Rust CLI (`zentra`) that orchestrates LLM-powered security scans. It dispatches multiple `ScannerAgent` instances against a codebase. It writes findings to `.zentra/`, and renders a live `ratatui` TUI during the scan.

**Stack:** Rust 2021 · tokio · ratatui 0.29 · crossterm 0.28 · clap 4 (derive) · reqwest 0.12 · keyring 3

### Module Map

```
src/
├── main.rs              # no-arg → TUI menu loop; else → clap dispatch
├── cli/mod.rs           # Clap structs: Cli, Commands, ConfigAction
├── commands/            # scan.rs, clone.rs (clone external repo → scan → .zentra/audits/), pentest.rs, init.rs, config.rs
├── agent/
│   ├── orchestrator.rs  # OrchestratorAgent — 4-phase execution
│   └── scanner.rs       # ScannerAgent — LLM ReAct tool-use loop (SAST 50 rounds; others 30)
├── config/              # global.rs (TOML), project.rs (JSON), keychain.rs, custom_providers.rs
├── provider/            # LLMProvider trait + AnthropicProvider + OpenAICompatProvider
├── scanners/            # system_prompt() + allowed_tools() dispatch per ScannerType
├── state/               # StateWriter (writes to .zentra/), Finding, Severity
├── tools/               # ToolRegistry (10 tools): fs_tools, git_tools, audit
├── pentest/             # Docker sandbox chain, scope, output, and report
└── tui/                 # scan_ui, pentest_ui, pentest_setup, menu, results
```

### 4-Phase Orchestration (`agent/orchestrator.rs`)

```
Phase 0: FrameworkAnalysis  (sequential, writes .zentra/architecture.md for all phases)
Phase 1: ThreatModel        (sequential)
Phase 2: SAST + SupplyChain + ApiScan + IaCScan  (parallel tokio::spawn)
Phase 3: Report             (sequential)
```

### ReAct Loop (`agent/scanner.rs`)

1. Build the system prompt and tool definitions for the `ScannerType`.
2. Post to the provider with tools for up to 50 SAST ReAct rounds or 30 rounds
   for every other scanner. This loop cap is independent of token/context
   limits and provider retry behavior.
3. On a tool call, route it through `ToolRegistry::dispatch()`, then append the results to the conversation.
4. With no tool calls, the agent is done.
5. Every event is emitted via `mpsc::channel(128)`, to `UiState::apply_event()`. This function is pure, with no side effects.

### Provider Abstraction

The `LLMProvider` trait exposes `complete_with_tools()`. It has two implementations, behind `Arc<dyn LLMProvider>`:
- `AnthropicProvider` — uses native `tool_use` / `tool_result` content blocks.
- `OpenAICompatProvider` — uses OpenAI `function`-typed tool calls.

### Config Locations

| What | Where | Format |
|------|-------|--------|
| Global config | `~/.zentra/config.toml` | TOML |
| Project config | `.zentra/config.json` | JSON |
| Custom providers | `~/.zentra/providers.toml` | TOML |
| API keys / OAuth tokens | `~/.zentra/keys/<profile>.key` / `.oauth` (encrypted at rest, see `secret_store.rs`) | — |
| Scan output | `.zentra/detailed-findings.md`, `.zentra/reports/` | MD/JSON |

## Tests

Integration tests in `tests/` use `tempfile::TempDir` and `wiremock::MockServer`:

- `agent_test.rs` — StateWriter, ToolRegistry dispatch, ScannerAgent ReAct loop, orchestrator ordering
- `auth_test.rs` — OAuth PKCE, token refresh
- `config_test.rs` — GlobalConfig/ProjectConfig roundtrip, custom providers validation
- `provider_test.rs` — endpoint validation, tool call parsing
- `tui_test.rs` — `UiState::apply_event`, MenuState navigation, `PentestUiState`, sandbox chain state
- `pentest_test.rs` — `PentestConfig` validation, `PentestScope` matching, output resolution, sandbox tool scope/allowlist
- `sandbox_recon_test.rs`, `sandbox_exploit_test.rs`, `sandbox_validator_test.rs`, `sandbox_report_test.rs`, `sandbox_smoke_test.rs` — Docker-sandboxed pentest agents, tool registries, and report pipeline; use `FakeExecutor` so no Docker is required

## Gotchas

**Exhaustive `ScanEvent` and `PentestEvent` matches** — After you add a new variant, grep every `match` block on both enums. In `scan.rs` / `commands/pentest.rs`, add `ScanEvent::NewVariant { .. } => {}` or `PentestEvent::NewVariant { .. } => {}` as no-ops if that site does not need it. The pentest event enum carries variants from the deleted legacy pipeline (`StageStarted`/`StageCompleted`/`PlanReady`/`EscalationSpawned`/`BrowserAction`/`CliCall`) — they're still emitted nowhere; a future cleanup slice should remove them with the match-arm updates.

**Pentest requires Docker** — `zentra pentest` aborts with an actionable error if Docker is missing, unreachable, the image pull fails, or the sandbox health probe finds a missing tool. The abort happens before any target contact (no recon traffic).

**Sandbox tool scope gate runs BEFORE exec** — every URL-bearing tool (`http_probe`, `http_request`, `dir_brute`, `run_payload`) checks `PentestScope::allows` before any `docker exec`. Out-of-scope returns a string error result, never reaches the container. `shell_exec` extracts http(s) args and scope-checks each.

**Pentest executor abstraction** — `SandboxExecutor` is a `Send + Sync` async trait. `SandboxHandle` implements it (real `docker exec`). Tests construct a `FakeExecutor` via `with_executor(scope, executor, output_root, tx)` so the scope gate, allowlist, and dedup logic are unit-testable without Docker.

**CWD-dependent tests must be serialized** — Tests that call `std::env::set_current_dir()` must acquire the static `CWD_LOCK: Mutex<()>`, defined in `agent_test.rs`.

**Regex patterns use `OnceLock`** — Secret-pattern, logging, and report modules compile regex values once, via a `static RE: OnceLock<Regex>` per call site. Do not use bare `Regex::new()` in a hot path. Follow the existing `OnceLock` pattern instead.

**`context_window()` falls through on unknown models** — `LLMProvider::context_window()` matches on a model name substring. Unknown models hit a default. Override this via `ProviderProfile::context_window: Option<u32>`.

**Secrets are file-based, not OS-keychain** — `config/secret_store.rs` is the single source of at-rest protection for `~/.zentra/keys/`. Windows uses DPAPI. Unix uses AES-256-GCM envelope encryption, with the data key in the OS secret store (Secret Service or Keychain), falling back to `0o600` plaintext when that store is unavailable. `keyring` serves only as a backward-compatible read fallback in `keychain.rs`. **`keyring` 3.x is a no-op mock, unless a backend feature is enabled.** Backends are wired per-target in `Cargo.toml` (`sync-secret-service` and `crypto-rust` on Linux, `apple-native` on macOS). Windows stays featureless on purpose.
