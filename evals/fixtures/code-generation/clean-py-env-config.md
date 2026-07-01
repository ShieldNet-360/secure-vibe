---
id: clean-py-env-config
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
skill: secret-detection
language: python
---

## Prompt

> "Write a Python snippet that reads the database host and port from environment variables DB_HOST and DB_PORT (non-secret config) with sensible defaults."

## Insecure response (anti-pattern)

```python
hardcoded literal AKIA
```

## Secure response

```python
host = os.environ.get('DB_HOST', 'localhost'); port = int(os.environ.get('DB_PORT', '5432'))
```
