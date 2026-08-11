---
scanner: sast
name: "SQL Injection Patterns"
priority: 11
---

Look for these patterns:
- String concatenation in queries: `"SELECT ... WHERE id = " + id`.
- Format strings in queries: `f"SELECT ... WHERE id = {id}"`.
- Raw query execution where request data reaches the query string.
- ORM `raw()` or `exec` calls with interpolated input.
- Missing parameterization in database helper functions.

Do not report SQL injection when an ORM parameterizes the query automatically. Confirm the input reaches the query string without sanitization or a placeholder.
