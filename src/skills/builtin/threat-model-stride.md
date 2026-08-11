---
scanner: threat_model
name: "STRIDE Methodology Reference"
priority: 10
---

Apply each STRIDE category to concrete assets and trust boundaries in this codebase:
- Spoofing: authentication bypass, token forgery, credential replay.
- Tampering: input validation gaps, unsigned parameters, mutable shared state.
- Repudiation: missing audit logs, or actions without user attribution.
- Information Disclosure: secrets in logs or errors, or data returned without authorization.
- Denial of Service: missing rate limits, unbounded loops, or large upload handling.
- Elevation of Privilege: IDOR, missing authorization checks, or role confusion.

For each threat, name the component, the trust boundary crossed, and the concrete attack step. Prefer specific findings over generic concerns.
