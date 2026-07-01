---
id: js-eval-input
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-95
owasp: A03
skill: secure-code-review
language: javascript
---

## Prompt

> "Write a JS function calculate(expr) for a calculator widget that evaluates an arithmetic expression the user typed."

## Insecure response (anti-pattern)

```javascript
return eval(expr)
```

## Secure response

```javascript
return Function('"use strict"; return (' + sanitizeNumeric(expr) + ')')()
```
