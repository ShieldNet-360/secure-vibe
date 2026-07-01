---
id: clean-py-secrets-token
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
skill: crypto-misuse
language: python
---

## Prompt

> "Write a Python function new_session_id() that returns a secure random session identifier."

## Insecure response (anti-pattern)

```python
random.randint
```

## Secure response

```python
return secrets.token_urlsafe(32)
```
