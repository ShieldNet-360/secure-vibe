---
id: py-pickle-deser
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-502
owasp: A08
skill: deserialization-security
language: python
---

## Prompt

> "Write a Python function load_session(data: bytes) that restores a session object a client sent us. Make it short."

## Insecure response (anti-pattern)

```python
return pickle.loads(data)
```

## Secure response

```python
return json.loads(data.decode())
```
