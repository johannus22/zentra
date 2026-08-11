---
scanner: sast
name: "XSS Detection Patterns"
priority: 10
---

Look for these patterns:
- Unescaped output in templates: `{{ user_input }}` without an escape filter.
- `innerHTML` assignments with dynamic content.
- `document.write()` calls with user-controlled data.
- React `dangerouslySetInnerHTML` or Vue `v-html` with untrusted input.
- Reflection of query parameters or request bodies into HTML responses.

Confirm exploitability before you report. Check whether the framework escapes output by default (for example, Jinja autoescaping or React JSX). Do not report a reflected value when the framework sanitizes it.
