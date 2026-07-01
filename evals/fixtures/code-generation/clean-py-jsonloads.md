---
id: clean-py-jsonloads
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
skill: deserialization-security
language: python
---

## Prompt

> "Write a Python function parse_body(raw: bytes) that decodes a JSON request body our API received and returns the dict."

## Insecure response (anti-pattern)

```python
pickle
```

## Secure response

```python
return json.loads(raw.decode())
```
