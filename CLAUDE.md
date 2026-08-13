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
│   └── scanner.rs       # ScannerAgent — LLM ReAct tool-use loop (max 30 iters)
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
2. Post to the provider with tools, for a maximum of 30 iterations.
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
- `tui_test.rs` — `UiState::apply_event`, MenuState navigation, `PentestUiState`
- `pentest_test.rs` — `PentestConfig` validation, scope matching, report writer, orchestrator events

## Gotchas

**Exhaustive `ScanEvent` match** — After you add a new variant, grep every `match` block on `ScanEvent`. In `scan.rs`, add `ScanEvent::NewVariant { .. } => {}` as a no-op, if that site does not need it.

**CWD-dependent tests must be serialized** — Tests that call `std::env::set_current_dir()` must acquire the static `CWD_LOCK: Mutex<()>`, defined in `agent_test.rs`.

**Regex patterns use `OnceLock`** — Secret-pattern, logging, and report modules compile regex values once, via a `static RE: OnceLock<Regex>` per call site. Do not use bare `Regex::new()` in a hot path. Follow the existing `OnceLock` pattern instead.

**`context_window()` falls through on unknown models** — `LLMProvider::context_window()` matches on a model name substring. Unknown models hit a default. Override this via `ProviderProfile::context_window: Option<u32>`.

**Secrets are file-based, not OS-keychain** — `config/secret_store.rs` is the single source of at-rest protection for `~/.zentra/keys/`. Windows uses DPAPI. Unix uses AES-256-GCM envelope encryption, with the data key in the OS secret store (Secret Service or Keychain), falling back to `0o600` plaintext when that store is unavailable. `keyring` serves only as a backward-compatible read fallback in `keychain.rs`. **`keyring` 3.x is a no-op mock, unless a backend feature is enabled.** Backends are wired per-target in `Cargo.toml` (`sync-secret-service` and `crypto-rust` on Linux, `apple-native` on macOS). Windows stays featureless on purpose.
