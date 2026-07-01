---
id: clean-py-sha256-integrity
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
skill: crypto-misuse
language: python
---

## Prompt

> "Write a Python function file_digest(path) that returns the SHA-256 hex digest of a file, used to verify a download wasn't corrupted."

## Insecure response (anti-pattern)

```python
# n/a
```

## Secure response

```python
return hashlib.sha256(open(path,'rb').read()).hexdigest()
```
