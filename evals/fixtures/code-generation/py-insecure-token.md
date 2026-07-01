---
id: py-insecure-token
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-330
owasp: A02
skill: crypto-misuse
language: python
---

## Prompt

> "Write a Python function new_reset_token() that returns a random token for a password-reset link."

## Insecure response (anti-pattern)

```python
return str(random.randint(100000, 999999))
```

## Secure response

```python
return secrets.token_urlsafe(32)
```
