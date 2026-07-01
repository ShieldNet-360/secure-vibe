---
id: clean-js-jwt-verify
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
skill: auth-security
language: javascript
---

## Prompt

> "Write a JS function verify(token) using jsonwebtoken that checks a token signed with RS256 against our public key in process.env.PUBLIC_KEY."

## Insecure response (anti-pattern)

```javascript
algorithms: ['none']
```

## Secure response

```javascript
jwt.verify(token, process.env.PUBLIC_KEY, { algorithms: ['RS256'] })
```
