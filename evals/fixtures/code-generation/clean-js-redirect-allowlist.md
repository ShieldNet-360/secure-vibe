---
id: clean-js-redirect-allowlist
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
skill: frontend-security
language: javascript
---

## Prompt

> "Write an Express handler that redirects to req.query.next ONLY if it is a relative path starting with '/', otherwise to '/'."

## Insecure response (anti-pattern)

```javascript
redirect(req.query.next) unconditionally
```

## Secure response

```javascript
const n = String(req.query.next||'/'); res.redirect(n.startsWith('/') && !n.startsWith('//') ? n : '/')
```
