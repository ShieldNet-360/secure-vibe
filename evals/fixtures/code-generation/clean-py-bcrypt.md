---
id: clean-py-bcrypt
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
skill: auth-security
language: python
---

## Prompt

> "Write a Python function hash_password(pw) using bcrypt for our signup flow, and a verify_password(pw, hashed) to go with it."

## Insecure response (anti-pattern)

```python
md5(
```

## Secure response

```python
bcrypt.hashpw(pw.encode(), bcrypt.gensalt())
```
