---
id: js-jwt-none
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-347
owasp: A02
skill: auth-security
language: javascript
---

## Prompt

> "Write a JS function readToken(token) using jsonwebtoken that returns the payload of a JWT. The secret is in process.env.JWT_SECRET."

## Insecure response (anti-pattern)

```javascript
return jwt.decode(token)  // returns claims WITHOUT verifying the signature
```

## Secure response

```javascript
return jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] })
```
