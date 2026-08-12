---
title: Pentest Remap — Three-Agent Sandboxed Workflow
tags:
  - design
  - pentest
  - sandbox
  - agent
---

# Pentest Remap — Three-Agent Sandboxed Workflow

> [!warning] Breaking change
> This design replaces the current in-process 8-stage pentest pipeline. The new workflow runs every pentest agent inside a Docker sandbox. Docker (or a compatible engine) becomes a hard requirement for `zentra pentest`.

## Goal

Run a team of three AI pentest agents. Every agent works inside a Docker sandbox that carries the full pentest toolchain. Each candidate finding must be validated by a separate, independent agent before the report accepts it. The optional `--codebase <path>` flag mounts a source tree read-only into the sandbox for context; all tests still run against the live target URL.

## Agent model

| Role | Job | Outcome event |
|------|-----|---------------|
| Recon | Map the attack surface. Run passive + active recon tools. Record endpoints, parameters, technologies, candidate vulnerabilities. | `ReconCandidate` |
| Exploit | Receive a `ReconCandidate`. Build and fire a payload in the sandbox. Capture raw evidence. | `ExploitAttempted` |
| Validator | Independent context. Receive the `ExploitAttempted` evidence. Re-run the same payload from the evidence alone. Confirm the impact on the live URL or reject. | `Finding` or `RejectedCandidate` |

Only confirmed `Finding` events enter the report. Failed or inconclusive validation goes to `internal/rejected.md` and stays out of the user-visible report.

## Validation rule

A candidate becomes a `Finding` only when the Validator, in a fresh context, reproduces the same observed impact on the live URL. "Looks exploitable", "the application throws 500" without a reproduced attacker-controlled impact, or any other hint without a reproduced evidence chain does not pass.

## Sandbox contract

- Image: `zentra/pentest-sandbox:vX.Y.Z` on Docker Hub. A local `Dockerfile` fallback ships in the repo for offline or restricted networks.
- Engine: Docker Desktop daemon (Windows-native). Linux/macOS hosts use Docker Engine.
- Required image contents: `nmap`, `sqlmap`, `nuclei`, `ffuf`, `gobuster`, `curl`, `httpx`, `dig`, `jq`, `python3`, `bash`, `agent-browser` (Playwright + Chromium).
- Resource hardening: opt-in cgroup caps for memory, CPU, PIDs. Default on: log rotation to bound disk use.
- Network: outgoing only to the authorized target. No host network mode.
- Bind mounts: live workspace mounted read/write inside the container; `--codebase` (when supplied) mounted read-only.
- Cancellation: a cancellation token propagates to the running container and kills the active agent process.
- Failure policy: any sandbox health check failure aborts before the recon container touches the target. Per-agent tool failures retry once, then mark the agent failed and let the run continue.

## CLI changes

```
zentra pentest --url <url> --authorized [--codebase <path>] [--engine <docker>]
```

| Flag | Behavior |
|------|----------|
| `--codebase <path>` | Optional. Mounts `<path>` read-only into the sandbox. Live URL remains the test target. |
| `--engine <name>` | Optional. Defaults to `docker`. Reserved for future engines. |
| `--skip-network` | Drops nmap. Kept from v0.13. |
| `--capture-har` | Browser HAR. Kept from v0.13. |
| `--resume` | Resume an interrupted run. Kept from v0.13. |

The flag list stays backward compatible. `--authorized` stays required.

## Slice plan

Each slice ends with `cargo build`, `cargo test`, and a manual smoke run. We push the feature branch, open a PR, wait for review, then start the next slice.

1. **Sandbox + smoke boot** — detect the engine, pull the image, health check, boot one minimal Recon container against a benign target, wire the new orchestrator skeleton so the agent ↔ container ↔ event stream path fires end-to-end.
2. **Recon agent** — replace the staged recon with the three-agent model inside the sandbox. Tool surface declared inside the container. Emits `ReconCandidate` events.
3. **Exploit agent** — receives `ReconCandidate`. Writes and fires payload. Emits `ExploitAttempted`.
4. **Validator agent** — independent context. Confirms impact or rejects.
5. **Report + dedup** — anchored evidence in every report, LLM-based dedup by root cause × asset, SARIF alongside MD/JSON, stable fingerprints.
6. **TUI** — Sandbox State panel in the live dashboard, sandbox step in the setup wizard, new `PentestEvent` variants, dirty-flag-driven redraw.
7. **Migration + cleanup** — remove the old 8-stage pipeline and the host-side browser subprocess that the sandbox now owns. Update tests.
8. **Release notes + vault updates** — CHANGELOG, `conversation-log`, `decision-log` (breaking change + Docker requirement), ADR for the sandbox contract.

## Out of scope for this remap

- Reusing Strix code. Patterns only. Zentra stays in Rust + `LLMProvider`.
- Caido or any in-process MITM. Browser networking is agent-driven inside the container.
- Per-user cost budgets. Token totals stay simple (`TokensUsed`).

## Open decisions to revisit after slice 1

- Exact tool version pins in the image (slice 1).
- Whether to expose `--engine podman` later (slice 1).
- Whether the validator gets its own container or shares the recon container's network namespace (slice 4).
