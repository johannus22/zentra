# Agent Security Envelope

zentra-cli executes real actions, driven by LLM responses. These actions include file read/write, git commands, dependency audits, and, in pentest mode, `nmap` and a Playwright browser. An LLM response can become compromised: tampered in transit (a MITM, or machine-in-the-middle, attack), replayed, served by a rogue provider, or hijacked by prompt injection from a scanned file. In any of these cases, the agent would otherwise execute attacker-controlled tool calls. The security envelope wraps the LLM-to-tool pipeline with layered, independent defenses.

## Threats and Mitigations

| Threat | Mitigation | Module |
|--------|-----------|--------|
| MITM response tampering | A per-request nonce, which the model must echo; hardened TLS (minimum version 1.2, with certificate validation) | `response_binding`, `provider/anthropic` |
| Replay of an old response | The nonce changes per request. It is single-use, with a max-age window. | `response_binding` |
| Prompt injection from scanned files | External tool output is tagged as untrusted data, and scanned for injection patterns | `prompt_guard` |
| Rogue or compromised provider | Optional dual-provider consensus. Only tool calls that both providers agree on will execute. | `dual_provider` |
| Agent runaway or loops | Rate limits, plus identical-call-loop detection | `tool_gate` |
| Sensitive-path exfiltration | A denylist (`.env`, `.ssh`, `.aws`, credential files, and similar paths), plus a depth limit | `tool_gate` |
| Argument injection | Per-tool semantic validation (regex length, git ref character set, finding size) | `tool_gate` |
| Forensics and non-repudiation | A tamper-evident SHA-256 hash-chain audit log (hashes only — never secrets) | `audit_log` |

The tool gate also hard-enforces the **per-scanner allowlist**. A SAST (static analysis) scanner can never invoke pentest or browser tools, even if the LLM asks it to.

## Configuration

The `ZENTRA_SECURITY` environment variable controls the envelope:

| Value | Behavior |
|-------|----------|
| _(unset)_ | **Balanced default.** The audit log, tool gate, and prompt-guard tagging stay on. Nonce binding and abort-on-injection stay off; these are opt-in, since they add friction. |
| `hardened` | Turns everything on, at the strictest settings. Use this for untrusted networks or high-assurance work. |
| `off` | Turns everything off, for minimal overhead in trusted local development. |

```bash
ZENTRA_SECURITY=hardened zentra scan
```

Gate blocks are **non-fatal per call**. A blocked tool call returns an explanation to the LLM, and the scan continues. So a false positive degrades a single step, rather than killing the run.

## Audit Log

Each scan writes `.zentra/audit/<session-id>.jsonl`. Every entry chains to the previous entry's SHA-256 hash. So any retrospective edit breaks the chain. The log stores prompts, arguments, and results as hashes only. Secrets never land in the log.

Verify integrity after a run:

```bash
zentra security verify-audit                 # verify all sessions
zentra security verify-audit <session-id>    # verify one session
```

The output reads `OK — N entries verified`, or `TAMPERED at entry M`.

## A Note on Nonce Binding

Nonce binding works best against blind response substitution and replay. A full read-write MITM attack could read the plaintext request, then extract and echo the nonce. Against that threat, TLS hardening is the primary defense. In `hardened` mode, Zentra also requires the nonce on tool-call-only responses. Anthropic tool-use responses often contain no assistant text. For this reason, nonce binding stays opt-in by default, to avoid rejecting legitimate responses.

## Accepted Risks and Future Work

Zentra tracks the items below but does not change them in code, for now. Each is a deliberate trade-off, a public-by-design value, or a larger migration deferred until later.

| Item | Why it's accepted | Future direction |
|------|-------------------|------------------|
| **`ring` unmaintained** (RUSTSEC-2025-0029) | This is a transitive dependency, via `rustls` then `reqwest`. It is in maintenance mode, with no known CVE. The weekly `audit.yml` workflow monitors it, and `.cargo/audit.toml` waives it. | Migrate to `aws-lc-rs`, once the rustls stack supports it cleanly. Reviewed 2026-06-10. |
| **System OpenSSL via `native-tls`** | The real TLS posture depends on the host OpenSSL, which is an opaque surface. | Switch `reqwest` to `rustls-tls`, to drop the system-OpenSSL dependency. Deferred, since this is a broad-impact backend change. |
| **`keyring` v3 (not v4)** | Version 3.6 has no known CVE. Zentra uses it only as a read fallback in `keychain`, and to hold the Unix envelope data key. | Evaluate the v4 migration, which breaks the API. Test it on all three platforms. |
| **SHA-1 TOTP** (`pentest/auth.rs`) | Some services issue SHA-1 TOTP (time-based one-time password) secrets. This is the dominant case, so Zentra must interoperate with it. | Make the algorithm configurable (SHA-256 or SHA-512), with SHA-1 as a compatibility fallback. |
| **Hardcoded OAuth client ID** (`auth.rs`) | A client ID in an OAuth 2.0 PKCE (Proof Key for Code Exchange) flow is public by design. It is not a secret. | Make it configurable, for enterprise registrations and graceful rotation. |
| **Pentest credentials via environment variables** | Zentra passes `ZENTRA_USER` and `ZENTRA_PASS` to the Node Playwright child process through the environment. Only same-user processes can read them (through `/proc/<pid>/environ`). This fits the local-tool trust model. Zentra never writes these values to disk or logs. | Pass them via stdin, or an unlinked `0600` temp file, if the threat model tightens. |

### Credential storage at rest

API keys and OAuth tokens live under `~/.zentra/keys/`. On **Windows**, Zentra encrypts them with DPAPI (Data Protection API), at user scope. On **Unix**, it uses AES-256-GCM envelope encryption. The data key for this lives in the OS secret store (Secret Service or Keychain). If that store is unavailable, for example on headless systems, over SSH, or in CI, Zentra falls back to `0600` plaintext files.

Zentra creates these files atomically, at mode `0600`. There is no world-readable window during creation. In memory, Zentra wraps provider API keys and the pentest password in `zeroize::Zeroizing`. This wipes the process's own copies on drop. This is defense-in-depth, not a guarantee: transient copies, for example inside the HTTP client, may still linger.

Set `ZENTRA_NO_OS_KEYCHAIN=1` to skip the OS secret store entirely, and use the `0600`-plaintext fallback instead. Use this in headless or CI environments, where the keychain is unusable. macOS shows an interactive "allow access" prompt, which blocks with no GUI to answer it. Headless Linux has no secret-service daemon at all. CI sets this variable so the `secret_store` tests stay deterministic.
