# Interactive Scan Chat — Technical Design

## Status / decision summary

**Status:** agreed design; not implemented. Add a scan-local, read-only
`ChatAgent` and a persistent TUI Chat drawer. Chat answers questions from a
bounded live snapshot, and translates plain-language requests into typed action
proposals. Nothing changes a scan until a local operator explicitly confirms a
proposal.

V1 supports exactly two actions:

1. `FocusAndRerun { scanners, scope }`
2. `PrioritizeVulnerability { category }`

`category` is a closed typed vulnerability category, never an individual
finding reference. `agent::orchestrator::OrchestratorAgent` owns application;
neither the TUI nor `agent::scanner::ScannerAgent` applies actions. Application
is deterministic at phase boundaries with at most one coalesced rerun per
scanner. No Ory, web, or HTML design is relevant: this is a Rust/Crossterm/
Ratatui scan UI feature.

## Goals and non-goals

Goals:

- Keep interaction in `tui::scan_ui::run_loop` while the scan continues.
- Answer questions about phase, scanner status, results, coverage, and pending
  work immediately through a separate read-only agent.
- Present bounded, reviewable actions and apply them only at safe boundaries.
- Preserve the current final ordering: incremental reconciliation when active,
  correlation, screening, then report.
- Retain a limited, redacted, project-local chat record and security audit
  hashes.

Non-goals: autonomous execution; arbitrary tool calls; scanner creation, phase
skipping, report/finding edits, severity changes, or configuration changes;
changes to an active scanner prompt/history; parallel chat completions; and a
headless/CI chat surface (`commands::ci` remains unchanged).

## UX

Chat is **visible and expanded by default** as a docked right drawer on a
normal-width terminal; scanner and results panes remain visible. On narrow
terminals, the expanded drawer is the full-screen active pane. It contains a
phase/status line, redacted transcript, input, in-flight/queued count, and a
proposal card showing action, targets/category, canonical scope, and earliest
boundary.

Drawer state is `ExpandedUnfocused`, `ExpandedFocused`, or `Collapsed`.
`c` focuses an expanded drawer; `c` while it is focused collapses it; `c` from
collapsed expands and focuses it. `Enter` submits input or confirms the visible
proposal; `Esc` rejects a proposal or clears active input before it does
anything else. The keys/footer must describe these states.

Key precedence is: existing provider/scan popups first; then active chat
proposal/input; then expanded Chat (collapse it); only when Chat is collapsed
and has no active interaction may `Esc` fall through to existing scan-screen
handling (`q`/`Esc` returns to menu and cancels the scan). Thus Chat cannot
accidentally turn a proposal rejection into a scan abort.

`UiState` gains chat view state in `src/tui/mod.rs`; chat rendering/key handling
belongs in `src/tui/scan_ui.rs`. It is not part of `UiState::apply_event`.

## Project architecture

### Existing integration points

- `commands::scan::run_scan` creates the existing `mpsc::channel(128)` scan
  channel, `ToolRegistry`, `StateWriter`, `CancellationToken`, security context,
  and the `session_id` passed to `AuditLog::new`.
- `OrchestratorAgent::run` owns the phase order: framework, threat model,
  parallel SAST/SupplyChain/API/IaC, `incremental::reconcile`,
  `correlation::correlate`, `screening::screen`, and report.
- `ScannerAgent::run` owns mutable ReAct messages, `MAX_ITERATIONS`, scanner
  `SecurityGate`/`PromptGuard`, and mutation-capable tool dispatch.
- `ToolRegistry` owns the shared scanner coverage ledger. `ScanEvent` is
  exhaustively matched (notably in `tui::UiState::apply_event` and
  `commands::ci`), so it must not carry chat events.

### New components and channels

Add `agent::chat` for schemas, snapshot/redaction, JSONL store, read-only
`ChatAgent`, and `ChatCoordinator`. `commands::scan` creates two separate
bounded channels and passes UI ends to `run_scan_ui` and coordinator ends to the
orchestrator:

```text
TUI -- ChatCommand (16) --> ChatCoordinator / ChatAgent
TUI <-- ChatEvent   (32) -- ChatCoordinator / ChatAgent
                              |
                              +-- PendingChatActions --> Orchestrator phase loop
```

`try_send` makes command overflow visible without delaying the existing
128-capacity scan channel. One ChatAgent completion may run at a time; at most
15 extra asks wait FIFO, then new asks receive `Backpressure`. Select scan and
chat receivers independently in `run_loop`. Define a separate `ChatEvent`:
adding variants to exhaustive `ScanEvent` matches would couple this TUI feature
to CI and unrelated consumers.

`ChatAgent` receives an immutable `ChatSnapshot` and has its own compact
history. It never receives, borrows, appends to, or compacts the private
`messages` vector in `ScannerAgent::run`.

### Exact chat snapshot focus

Construct a snapshot at dequeuing time, not from raw repository state. It is
limited to: session ID; current boundary; selected scanner set and each
scanner's `NotStarted`/`Running`/`Completed`/`Failed` state; checkpoint
completion names; action eligibility and pending actions; a capped/redacted
summary of findings by scanner/severity/category; scanner-only coverage
summary; architecture-context presence plus content hash; incremental mode and
the canonical incremental focus summary; incremental impacted-path count plus a
capped normalized path list; current canonical Chat focus fragments; and the
last 12 redacted chat turns. It excludes raw scanner histories, raw tool output,
credentials, provider prompts/nonces, and unbounded source text. Repository
facts beyond that snapshot can be requested through the read-only tool path.

## Typed actions, scope, and boundary application

### Closed categories and structured scope

```rust
enum VulnerabilityCategory {
    AuthenticationAuthorization,
    Injection,
    SensitiveDataExposure,
    DependencySupplyChain,
    InfrastructureMisconfiguration,
}

enum FocusFragment {
    AuthBoundary,
    InputValidation,
    DataFlow,
    SecretsAndSensitiveData,
    DependencyManifest,
    NetworkExposure,
    IaCPrivilege,
}

struct FocusScope {
    fragments: BTreeSet<FocusFragment>, // max 4
    paths: Vec<NormalizedRepoPath>,     // max 20, optional
}

enum ChatAction {
    FocusAndRerun { scanners: Vec<ScannerType>, scope: FocusScope },
    PrioritizeVulnerability { category: VulnerabilityCategory },
}
```

The coordinator parses model output into only these values. It rejects unknown
variants, over-limit lists, duplicate/non-normalized paths, absolute/parent
paths, and scanner types outside the selected run. A guarded normalizer
canonicalizes separators, validates paths against project root and incremental
scope, sorts/deduplicates values, and renders them only through fixed prompt
templates. There is no free-form focus string in an action, checkpoint, or
prompt. `PrioritizeVulnerability` adds the category's fixed prompt fragment and
category ordering to eligible work; it neither changes stored severity nor
edits results.

`FocusAndRerun` may target only V1 phase-2 analyzers. Framework, threat model,
and report are never direct targets. SupplyChain requires the
`DependencyManifest` fragment or `DependencySupplyChain` category.

### Merge rules and scope preservation

At each boundary, process confirmed actions in confirmation sequence, union
target scanners, union canonical fragments, union validated paths, and retain
the first requested category of each enum value. This produces one canonical
focus plan per scanner and one rerun maximum per scanner for the whole run.

Prompt construction has fixed precedence:

1. `ScannerAgent` base system prompt and the existing architecture context stay
   unchanged (`ScannerAgent::run` lines 207–216).
2. Existing `focus_context` remains next, including its incremental explanation.
3. Rendered Chat category/scope templates append as a distinct **Chat Focus**
   section; they can narrow attention but cannot override (1) or (2).
4. Existing `incremental_scope` remains the filesystem authority used by
   `initial_prompt_for` and `check_incremental_scope`; Chat paths must be a
   subset and may only narrow it. Chat never widens an incremental scan.

`incremental_scope_for` deliberately returns `None` for SupplyChain. Preserve
that unscoped behavior: Chat may add a dependency analytical focus, but must not
create a filesystem scope for SupplyChain or change advisory coverage.

### Boundary behavior and checkpoint invalidation

Eligible boundaries are after framework, after threat model, and after the
initial phase-2 tasks join, before reconciliation. At a boundary:

- A `NotStarted` target receives the merged canonical focus as its **initial**
  `ScannerAgent` focus; it is not rerun.
- A `Running` or `Completed` target is not mutated or interrupted. It is marked
  for the one coalesced fresh-agent rerun after the applicable work joins.
- Before that rerun starts, remove `target.name()` **and** `Report.name()` from
  `Checkpoint::completed`, update `updated_at`, and save. This concretely
  invalidates stale completion/report state and guarantees the final report
  regenerates. The rerun's normal successful completion marks its scanner again.

After the final target work, execute incremental reconciliation when active,
then correlation, screening, and exactly one report. This preserves the
existing `OrchestratorAgent::run` ordering around lines 440–529. Confirmation
after the final mutable boundary is `Deferred`; it is recorded in chat history,
not executed later in a completed scan.

## Event schemas and lifecycle

```rust
enum ChatCommand {
    Ask { request_id: Uuid, text: String },
    Confirm { proposal_id: Uuid }, Reject { proposal_id: Uuid },
    Cancel { request_id: Uuid }, Close,
}
enum ChatEvent {
    RequestQueued { request_id: Uuid, position: usize },
    Answer { request_id: Uuid, text: String }, Proposal { proposal: ActionProposal },
    Applied { proposal_id: Uuid, boundary: PhaseBoundary },
    Deferred { proposal_id: Uuid, reason: String }, Cancelled { request_id: Uuid },
    Error { request_id: Option<Uuid>, kind: ChatError, message: String },
}
struct ActionProposal {
    proposal_id: Uuid, request_id: Uuid, action: ChatAction,
    created_at: DateTime<Utc>, expires_at: DateTime<Utc>,
    earliest_boundary: PhaseBoundary,
}
enum PhaseBoundary { AfterFramework, AfterThreatModel, AfterParallel, Finalized }
enum ChatError { Backpressure, Cancelled, Provider, Security, Budget, InvalidProposal, Persistence }
```

Request lifecycle: `Draft -> Queued -> Running -> Answered | Proposed |
Cancelled | Failed`. Proposal lifecycle: `Proposed -> Confirmed -> PendingBoundary
-> Applied | Deferred | Expired`; reject/cancel ends it. Expiry is five minutes.
Scan cancellation cancels the in-flight completion, drains queued asks and
proposals, and prevents pending application.

## Read-only execution, budgets, and security

ChatAgent uses the same guarded `Arc<dyn LLMProvider>`, `SecurityContext`,
`GuardedProvider`, and `PromptGuard` path as the scan. Its explicit read-only
ToolRegistry profile is **only** `list_files`, `read_file`, `grep_code`,
`git_log`, `git_diff`, `git_blame`, and `git_status`, and only when that tool is
registered in the current `ToolRegistry`. It explicitly excludes `run_audit`,
all writers (`write_finding`, `write_architecture`, and future writers), and
all process-execution tools. A missing registered tool is unavailable; Chat
must not bypass the registry with direct filesystem or git calls.

Introduce an explicit Chat tool profile rather than passing a scanner
`ScannerType` into `scanners::allowed_tools`. The profile uses a Chat-specific
read-only `SecurityGate` policy with argument validation/rate limits, records
`AuditEvent::ToolDispatched`/`ToolResult` hashes, and applies
`PromptGuard::scan_and_wrap` to every external result. Provider response binding
failures, blocked calls, malformed proposals, and prompt-guard failures become
chat errors only—never confirmation.

Chat reads are chat-scoped/no-op for coverage: do not call ToolRegistry's
scanner `record_read`, `record_listing`, or `record_search` paths and do not
emit `ScanEvent::FileRead`. Thus `coverage_snapshot`, `never_read_snapshot`,
the scanner UI counters, and `.zentra/coverage.md` measure ScannerAgent work
only.

Use an independent smaller budget: fixed Chat system prompt, one snapshot, last
12 turns, at most four tool results, 1,024 reserved output tokens, and 4 KiB
maximum user input. Apply `context_budget::estimate_tokens`, `input_budget`,
`bound_tool_result`, and oldest-first compaction. On irreducible budget, emit
`ChatError::Budget` and answer only from the bounded snapshot. Chat token
counters are separate from `UiState::total_tokens` and scanner progress.

Security invariants: only local `Confirm` produces pending work; model text,
tool calls, malformed JSON, or persisted records never execute actions; Chat
cannot mutate `StateWriter` or `Checkpoint` directly; and persisted chat text is
redacted while the tamper-evident audit stream stores hashes rather than prompts
or source results.

## Persistence and resume

Reuse the `session_id` already created by `commands::scan::run_scan` for the
security audit session. Store append-only redacted records at
`.zentra/chat/<session-id>.jsonl`. Each record has schema version, timestamp,
session ID, request/proposal ID, lifecycle event, redacted answer/request text
or typed action, and no prompt, tool result, credential, nonce, or raw source.
Keep the latest 20 session files and best-effort prune older files. Persistence
failure emits `ChatError::Persistence` and never blocks scanning.

Extend `agent::checkpoint::Checkpoint` compatibly with `#[serde(default)]
`session_id: String` and `confirmed_chat_actions: Vec<ConfirmedChatAction>`.
The action record contains proposal ID, confirmation sequence, typed action,
and required scanner set—never transcript content. At fresh-run checkpoint
creation, set and save `session_id`; after local confirmation, append the
validated action and save before reporting it pending. When an action is
coalesced/applied or deferred/cancelled/expired, remove it and save. Before a
rerun, perform the completion/report invalidation and save as described above.
On success, existing `Checkpoint::clear` removes this transient state; JSONL
history remains. On incomplete/cancelled runs, the checkpoint remains.

`--resume` retains strict missing/corrupt checkpoint rejection. Restore pending
actions only when checkpoint `session_id`, selected scanner set, and typed
scope/category validation match the resumed run; otherwise discard them as
`InvalidProposal` and record the outcome in JSONL. Old checkpoints deserialize
with empty new fields. Conversation history is never restored as instruction
context.

## Errors, backpressure, and compatibility

`Esc` behavior follows the UX precedence above. Provider/security/budget/
persistence errors render in Chat, never as `ScanEvent::Error` or scanner
failure. Terminal Chat events (`Answer`, `Proposal`, `Applied`, `Deferred`,
`Cancelled`, `Error`) are never dropped; only nonterminal progress can be
coalesced under event-channel pressure.

The drawer is present by default; no scan CLI syntax, CI behavior, provider
configuration, finding formats, or existing checkpoint fields change. Missing
`.zentra/chat` is normal. Schema-versioned JSONL permits future readers to
ignore unknown records safely.

## Phased implementation plan

1. Add pure `agent::chat` schemas, canonical scope/category validation,
   redactor/JSONL store, and backward-compatible checkpoint fields.
2. Add Chat-specific read-only registry/gate profile and ChatAgent provider,
   prompt-guard, audit-hash, budget, and no-op-coverage integration.
3. Wire separate channels, coordinator serialization, session-ID propagation,
   checkpoint lifecycle, and deterministic orchestrator boundary coalescing.
4. Add default-visible TUI drawer, focus/collapse keys, narrow view, proposal
   confirmation, and precise Escape routing.
5. Add integration/resume/security coverage; update public architecture/docs if
   the released UI surface requires it.

## Verification matrix and acceptance criteria

| Area | Evidence / acceptance criterion |
|---|---|
| Typed schema | serde round trips; reject unknown category/fragment/scanner, over-limit scope, invalid path, and malformed model output; no individual-result targeting exists. |
| Drawer/keys | Default is visible/expanded; `c` follows all three states; narrow view works; `Esc` rejects/clears/collapses before fall-through. An explicit test sends first `Esc` with expanded Chat and asserts scan remains active, then collapses Chat and sends second `Esc` to assert existing scan handling runs. |
| Q&A/channels | One Chat request runs with 15 FIFO extras; overflow is visible; scan events remain on capacity 128 and continue rendering while Chat answers. |
| Boundaries | Not-started target gets initial focus; running/completed target is not touched and gets one later coalesced rerun; target and Report checkpoint completions are removed/saved before rerun; final report regenerates. |
| Scope merge | Architecture and existing incremental focus remain ordered before Chat templates; Chat cannot widen incremental paths; SupplyChain remains unscoped in incremental mode. |
| Pipeline | Any rerun executes incremental reconciliation when applicable, then correlation, screening, and one final report. |
| Read-only/security | Exact allowlist succeeds only when registered; `run_audit`, every writer, and process execution are blocked; Gate/GuardedProvider/PromptGuard/audit hashes operate; strict binding failure creates no pending action. |
| Coverage | Chat reads do not change scanner coverage snapshots, UI file counts, or `.zentra/coverage.md`. |
| Persistence/resume | Session-ID JSONL, redaction, 20-file pruning, nonfatal write error, checkpoint save/remove lifecycle, matching resume restoration, and mismatched session/scanner rejection are covered. |
| Isolation/cancel | Chat cannot reach ScannerAgent history or mutation state; abort drains chat and prevents application; late events are ignored. |

Acceptance requires the matrix plus the repository's assigned Rust test suite.
**Validation owner: parent orchestrator.**

## Rejected alternatives

- **Chat variants in `ScanEvent`:** rejected because its exhaustive matches and
  non-TUI consumers create unrelated churn; use `ChatEvent`.
- **Append Chat input to active ReAct histories:** rejected for race,
  prompt-injection, budget, and reproducibility risks.
- **Model-initiated rerun/write calls:** rejected because model output is not
  local confirmation and violates least privilege.
- **Immediate application/interrupted phase-2 tasks:** rejected as
  nondeterministic and duplicate-prone.
- **Unbounded shared event bus or full prompt/tool persistence:** rejected for
  scan starvation, memory, secret retention, and source-data risk.
