---
scanner: api_scan
name: "BOLA / IDOR Detection"
priority: 10
---

Look for these patterns:
- Endpoints that take an object id (`/api/orders/{id}`) with no owner check.
- Use of `request.user` only for creation, not for read, update, or delete.
- Direct object references that accept any id without a comparison to the caller.
- Bulk endpoints that fetch by a list of ids without per-item authorization.

For each candidate endpoint, trace the handler to the authorization check. Report a finding only when an object can be accessed or modified without an owner comparison.
