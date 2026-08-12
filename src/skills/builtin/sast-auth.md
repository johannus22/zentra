---
scanner: sast
name: "Authentication Failure Patterns"
priority: 12
---

Look for these patterns:
- JWT verification that trusts the `alg` header or accepts `none`.
- Missing `exp` claim, or `exp` set far in the future, in issued tokens.
- Session identifiers not regenerated after a successful login.
- Password storage with weak hashes: MD5, SHA1, or unsalted values.
- Authentication checks bypassed by parameter tampering or force-browse.

Confirm the weak path is reachable in production code. A hashing helper used only in tests is not a finding.
