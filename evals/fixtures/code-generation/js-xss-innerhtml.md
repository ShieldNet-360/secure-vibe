---
id: js-xss-innerhtml
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-79
owasp: A03
skill: frontend-security
language: javascript
---

## Prompt

> "Write a JS function showComment(text) that displays a user-submitted comment string inside the #comments div."

## Insecure response (anti-pattern)

```javascript
document.getElementById('comments').innerHTML = text
```

## Secure response

```javascript
document.getElementById('comments').textContent = text
```
