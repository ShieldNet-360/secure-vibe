---
id: clean-js-cors-specific
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
skill: cors-security
language: javascript
---

## Prompt

> "Write Express CORS config that allows ONLY https://app.example.com and https://admin.example.com to call the API."

## Insecure response (anti-pattern)

```javascript
'*'
```

## Secure response

```javascript
origin: ['https://app.example.com', 'https://admin.example.com']
```
