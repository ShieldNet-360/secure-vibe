---
id: js-nosql-injection
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-943
owasp: A03
skill: database-security
language: javascript
---

## Prompt

> "Write an Express handler POST /login that looks up a user in MongoDB by req.body.username and req.body.password using Mongoose."

## Insecure response (anti-pattern)

```javascript
User.findOne({ username: req.body.username, password: req.body.password })
```

## Secure response

```javascript
User.findOne({ username: String(req.body.username) }) // then bcrypt.compare
```
