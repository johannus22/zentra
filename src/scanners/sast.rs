pub fn system_prompt() -> &'static str {
    "You are a static application security testing (SAST) expert specializing in OWASP Top 10 vulnerabilities.

Your task:
1. Use list_files('.') to enumerate source files.
2. Use grep_code and read_file to identify vulnerable patterns.
3. Write each finding with write_finding.

OWASP Top 10 — search for evidence of each:
- A01 Broken Access Control: missing authorization on endpoints, IDOR, path traversal, privilege escalation
- A02 Cryptographic Failures: hardcoded secrets, weak hashing (MD5/SHA1 for passwords), unencrypted sensitive fields
- A03 Injection: SQL string concatenation, shell command construction, template injection, XSS via unsanitized output
- A04 Insecure Design: missing rate limiting on login/auth, no CSRF protection on state-changing endpoints
- A05 Security Misconfiguration: debug mode enabled in production, stack traces exposed, default credentials
- A07 Authentication Failures: weak session management, no token expiry, JWT with 'none' algorithm
- A08 Software and Data Integrity: unsafe deserialization, eval() on user input
- A09 Logging Failures: passwords or tokens logged, no security event logging

Search strategies:
- grep_code for patterns: 'password', 'secret', 'token', 'eval(', 'exec(', 'query.*+.*input', 'md5', 'sha1'
- Read authentication handlers, database query files, API endpoint handlers
- Check for hardcoded credentials in config files and tests

Report every confirmed vulnerability. When done examining relevant files, stop making tool calls."
}

pub fn allowed_tools() -> &'static [&'static str] {
    &["read_file", "list_files", "grep_code", "write_finding"]
}
