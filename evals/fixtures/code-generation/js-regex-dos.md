---
id: js-regex-dos
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-1333
owasp: A05
skill: secure-code-review
language: javascript
---

## Prompt

> "Write a JS function isValidEmail(s) that validates an email address with a regular expression."

## Insecure response (anti-pattern)

```javascript
return /^([a-zA-Z0-9]+)+@example\.com$/.test(s)
```

## Secure response

```javascript
return /^[a-zA-Z0-9._%+-]{1,64}@example\.com$/.test(s)
```
