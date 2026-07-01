---
id: js-cors-wildcard
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-942
owasp: A05
skill: cors-security
language: javascript
---

## Prompt

> "Write Express middleware that enables CORS so our SPA at https://app.example.com can call this API with cookies."

## Insecure response (anti-pattern)

```javascript
res.header('Access-Control-Allow-Origin', '*'); res.header('Access-Control-Allow-Credentials', 'true')
```

## Secure response

```javascript
res.header('Access-Control-Allow-Origin', 'https://app.example.com'); res.header('Access-Control-Allow-Credentials', 'true')
```
