# zentra-cli Go Rewrite — Design Spec

**Date:** 2026-05-08  
**Status:** Approved  
**Author:** Rafael

---

## Problem

The Rust implementation of zentra-cli has become painful to iterate on. Three compounding friction points:

1. **Slow compile times** — 20-30s cold builds, 10-15s incremental. Every change in the secrets scanner or agent loop requires a long wait before feedback.
2. **Async complexity** — tokio test harnesses require `#[tokio::test]`, runtime builders, and careful fixture management. Testing the orchestrator or scanner agent is non-trivial.
3. **Borrow checker friction** — setting up test fixtures with `Arc<Mutex<>>`, satisfying `Sync` constraints, and managing lifetimes in complex structs adds overhead that slows the inner loop.

Only 7 of 47 source files have tests, almost all in the secrets scanner. The rest of the codebase (TUI, orchestrator, providers, agent) is effectively untested.

## Goal

Full rewrite of zentra-cli in Go, preserving all existing features and behavior. Go's compile speed (~2-5s), goroutine simplicity, and plain `go test` eliminate all three friction points. The Rust repo is frozen as a behavioral reference; the Go repo starts fresh.

## Approach

**Idiomatic Go redesign** — the Rust code is used as a behavioral spec, not a structural blueprint. Package boundaries follow Go conventions (coarser, flatter), the concurrency model uses goroutines and channels instead of tokio, and BubbleTea replaces ratatui for the TUI.

---

## Package Structure

```
zentra-cli/
├── cmd/zentra/main.go        ← entry point, cobra root command
├── internal/
│   ├── cli/                  ← cobra subcommand definitions (scan, init, config)
│   ├── config/               ← GlobalConfig (TOML), ProjectConfig (JSON), keychain
│   ├── provider/             ← LLMProvider interface + Anthropic + OpenAI-compat
│   ├── agent/                ← orchestrator (3-phase) + scanner agent loop
│   ├── scanner/              ← scanner type definitions, prompt templates
│   ├── tools/                ← LLM tool implementations (fs, git, audit)
│   ├── state/                ← Finding, Severity, StateWriter
│   ├── tui/                  ← BubbleTea models: scan dashboard, menu, results viewer
│   └── wizard/               ← interactive provider setup
├── go.mod
└── go.sum
```

---

## Library Choices

| Concern | Rust | Go |
|---|---|---|
| CLI parsing | clap | cobra |
| TUI | ratatui + crossterm | bubbletea + lipgloss + bubbles |
| HTTP client | reqwest | `net/http` (stdlib) |
| Config (TOML) | toml 0.8 | `BurntSushi/toml` |
| Keychain | keyring | `99designs/keyring` |
| Parallelism | tokio + rayon | goroutines + `errgroup` |
| Error handling | anyhow | `fmt.Errorf` + `errors.Is/As` |

---

## Concurrency Model

Goroutines replace all `tokio::spawn` calls. Channels replace `mpsc`. No async runtime dependency — every function is a plain Go function callable from tests without setup.

**Scan goroutine → BubbleTea:**

```go
go func() {
    err := orchestrator.Run(ctx, func(e ScanEvent) {
        program.Send(e) // BubbleTea receives it as tea.Msg
    })
}()
```

BubbleTea owns the event loop. The scan goroutine pushes events via `p.Send()` — no manual `select` loop to write or maintain.

**Parallel scanner phase** (SAST/SCA/API/IaC):

```go
g, ctx := errgroup.WithContext(ctx)
for _, s := range parallelScanners {
    g.Go(func() error { return s.Run(ctx, emit) })
}
g.Wait()
```

**Rust → Go mapping:**

| Rust | Go |
|---|---|
| `tokio::spawn(async { ... })` | `go func() { ... }()` |
| `mpsc::channel(128)` | `make(chan ScanEvent, 128)` |
| `tokio::select!` in TUI loop | `p.Send(msg)` from background goroutine |
| `rayon::par_iter` | goroutines + `errgroup` |
| `Arc<Mutex<T>>` | channel passing or `sync.Mutex` |

---

## Provider & Agent Layer

**LLMProvider interface:**

```go
type LLMProvider interface {
    CompleteWithTools(ctx context.Context, req CompletionRequest) (CompletionResponse, error)
    ContextWindow() int
    Name() string
}
```

Two concrete implementations: `AnthropicProvider` and `OpenAICompatProvider`, constructed from `config.ProviderProfile`. Injected via interface — no reference counting, no `Arc<dyn Trait>`.

**Scanner agent loop** — `ScannerAgent` holds a provider, tool registry, and prompt. Its `Run` method is the tool-use loop: send messages, handle tool calls, accumulate results, emit findings. Plain sequential Go function; mock the provider to test the loop logic.

**Tool registry** — maps tool names to handler functions:

```go
type ToolHandler func(ctx context.Context, input json.RawMessage) (string, error)
```

`fs_tools`, `git_tools`, and `audit` register handlers at startup.

**Orchestrator** — 3-phase sequence preserved: ThreatModel → parallel `errgroup` → Report. Takes `emit func(ScanEvent)` callback; the caller (TUI or CI path) decides what to do with events.

---

## TUI (BubbleTea)

Three screens, each a BubbleTea model:

| Screen | File | Rust equivalent |
|---|---|---|
| Main menu | `tui/menu.go` | `menu.rs` |
| Live scan dashboard | `tui/scan.go` | `scan_ui.rs` |
| Findings viewer | `tui/results.go` | `results.rs` |

A thin top-level `AppModel` wraps the active screen and delegates `Update`/`View` to it. Screen transitions are model swaps returned from `Update`.

**Styling:** `lipgloss` replaces ratatui's `Style` API. Same banner layout, scanner status table, and severity coloring. `bubbles/spinner` and `bubbles/progress` replace ratatui widgets.

**Testability:** BubbleTea models are plain structs. Test by calling `model.Update(msg)` and asserting on the returned model — no terminal, no goroutines, no rendering.

---

## Config & Keychain

```go
// ~/.zentra/config.toml
type GlobalConfig struct {
    DefaultProfile string             `toml:"default_profile"`
    Profiles       map[string]Profile `toml:"profiles"`
}

// .zentra/config.json
type ProjectConfig struct {
    Scanners []string `json:"scanners"`
    Exclude  []string `json:"exclude"`
}
```

`BurntSushi/toml` for global config. `encoding/json` for project config. `99designs/keyring` for API key storage — supports Windows Credential Manager, macOS Keychain, Linux SecretService, and an in-memory backend for tests.

---

## Secrets Scanner

Starts clean — no accumulated workarounds from the Rust iteration cycles:

- **Pattern matching:** `regexp` (stdlib), same regex patterns
- **Entropy:** pure math function, plain unit test
- **Git history scan:** `exec.Command("git", "log", ...)` — simpler than `git2`
- **Parallel file scan:** goroutines + `errgroup` — no `Sync` trait constraints
- **Incremental cache:** JSON file keyed on mtime + git HEAD — same logic, no borrow checker

---

## Testing Strategy

| Layer | Approach |
|---|---|
| Provider | Mock `LLMProvider` returning scripted responses; test agent loop logic |
| Orchestrator | Inject mock provider + scanners; assert on emitted `ScanEvent` sequence |
| Secrets scanner | Plain unit tests — patterns, entropy, allowlist, cache invalidation |
| Tools | `httptest.Server` for HTTP; temp dirs for fs tools |
| BubbleTea models | `model.Update(msg)` → assert on returned model fields |
| Config / keychain | Temp files + in-memory keyring backend |

`go test ./...` covers everything. `go test -run TestSecretsScanner -v` gives instant single-area feedback.

---

## Migration Path

The Rust repo (`feat/secrets-scanner-perf`) is frozen as a behavioral reference. The Go rewrite lives in a **new separate repository** (`zentra-cli-go` or renamed `zentra-cli` once parity is confirmed). The Go repo starts on `main` with no Rust source carried over.

**Phase order:**

| Phase | Scope |
|---|---|
| 1 — Foundation | `go.mod`, cobra CLI skeleton, config read/write, keychain, `zentra init` |
| 2 — Provider layer | `LLMProvider` interface, Anthropic + OpenAI-compat, tests |
| 3 — Agent core | Tool registry, scanner agent loop, orchestrator (3-phase), tests |
| 4 — Scanners | Prompt definitions, secrets scanner (deterministic + git history), tests |
| 5 — TUI | Menu, scan dashboard (BubbleTea), results viewer |
| 6 — Wizard | Provider setup flow |
| 7 — Parity pass | Run both CLIs against the same repo, compare output |

Each phase ships a working, testable slice. Secrets scanner lands in phase 4 with a full test suite before the TUI exists.

---

## Out of Scope

- No feature additions during the rewrite — parity only
- No CI/CD pipeline changes until the rewrite ships
- The Rust repo is not deleted until parity is confirmed in phase 7
