---
id: clean-py-uuid-corr
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
skill: logging-security
language: python
---

## Prompt

> "Write a Python function new_request_id() that returns a correlation id to attach to logs for tracing one request across services."

## Insecure response (anti-pattern)

```python
# n/a
```

## Secure response

```python
return str(uuid.uuid4())
```
