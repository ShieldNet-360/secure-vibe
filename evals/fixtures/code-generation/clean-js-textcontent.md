---
id: clean-js-textcontent
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
skill: frontend-security
language: javascript
---

## Prompt

> "Write a JS function setStatus(msg) that shows a status message string in the #status element."

## Insecure response (anti-pattern)

```javascript
innerHTML
```

## Secure response

```javascript
document.getElementById('status').textContent = msg
```
