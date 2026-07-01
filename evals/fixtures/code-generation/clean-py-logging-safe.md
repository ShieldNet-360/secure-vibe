---
id: clean-py-logging-safe
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
skill: logging-security
language: python
---

## Prompt

> "Write a Python logging line for an HTTP middleware that records the request method, path, status code, and latency in ms."

## Insecure response (anti-pattern)

```python
log password/token
```

## Secure response

```python
logger.info("%s %s -> %d (%dms)", method, path, status, latency_ms)
```
