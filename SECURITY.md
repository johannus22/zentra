# Agent Security Envelope

zentra-cli executes real actions (file read/write, git, dependency audits, and
in pentest mode `nmap` + a Playwright browser) driven by LLM responses. If an
LLM response is compromised — tampered in transit (MITM), replayed, served by a
rogue provider, or hijacked by prompt injection from a scanned file — the agent
would otherwise execute attacker-controlled tool calls. The security envelope
wraps the LLM → tool pipeline with layered, independent defenses.

## Threats and Mitigations

| Threat | Mitigation | Module |
|--------|-----------|--------|
| MITM response tampering | Per-request nonce the model must echo; hardened TLS (min 1.2, cert validation) | `response_binding`, `provider/anthropic` |
| Replay of an old response | Nonce changes per request, single-use, max-age window | `response_binding` |
| Prompt injection from scanned files | External tool output tagged as untrusted data + scanned for injection patterns | `prompt_guard` |
| Rogue / compromised provider | Optional dual-provider consensus — only tool calls both providers agree on execute | `dual_provider` |
| Agent runaway / loops | Rate limits + identical-call-loop detection | `tool_gate` |
| Sensitive-path exfiltration | Denylist (`.env`, `.ssh`, `.aws`, credentials files…) + depth limit | `tool_gate` |
| Argument injection | Per-tool semantic validation (regex length, git ref charset, finding size) | `tool_gate` |
| Forensics / non-repudiation | Tamper-evident SHA-256 hash-chain audit log (hashes only — never secrets) | `audit_log` |

The tool gate also hard-enforces the **per-scanner allowlist**: a SAST scanner
can never invoke pentest/browser tools, even if the LLM asks.

## Configuration

The envelope is controlled by the `ZENTRA_SECURITY` environment variable:

| Value | Behavior |
|-------|----------|
| _(unset)_ | **Balanced default**: audit log, tool gate, and prompt-guard tagging on. Nonce binding and abort-on-injection off (opt-in, since they add friction). |
| `hardened` | Everything on, strictest settings — for untrusted networks / high assurance. |
| `off` | Everything off — minimal overhead for trusted local development. |

```bash
ZENTRA_SECURITY=hardened zentra scan
```

Gate blocks are **non-fatal per call**: a blocked tool call returns an
explanation to the LLM and the scan continues, so a false positive degrades a
single step rather than killing the run.

## Audit Log

Each scan writes `.zentra/audit/<session-id>.jsonl`. Every entry chains the
previous entry's SHA-256, so any retrospective edit breaks the chain. Prompts,
arguments, and results are stored as hashes only — secrets never land in the log.

Verify integrity after a run:

```bash
zentra security verify-audit                 # verify all sessions
zentra security verify-audit <session-id>    # verify one session
```

Output is `OK — N entries verified` or `TAMPERED at entry M`.

## A Note on Nonce Binding

Nonce binding is most effective against blind response substitution and replay.
A full read-write MITM that can read the plaintext request could extract and
echo the nonce; TLS hardening (and, in `hardened` mode, the requirement that
even tool-call-only responses carry the nonce) is the primary defense there.
Because Anthropic tool-use responses frequently contain no assistant text, nonce
binding is opt-in by default to avoid rejecting legitimate responses.
