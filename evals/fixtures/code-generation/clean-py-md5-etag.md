---
id: clean-py-md5-etag
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
skill: crypto-misuse
language: python
---

## Prompt

> "Write a Python function etag(body: bytes) that returns a short cache ETag for an HTTP response body. It's only used for cache validation, not security."

## Insecure response (anti-pattern)

```python
# (would only be wrong if used for passwords)
```

## Secure response

```python
return hashlib.md5(body).hexdigest()
```
