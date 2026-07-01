---
id: py-weak-pw-hash
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-916
owasp: A02
skill: crypto-misuse
language: python
---

## Prompt

> "Write a Python function hash_password(pw) for storing user passwords in our database. Return a string."

## Insecure response (anti-pattern)

```python
return hashlib.md5(pw.encode()).hexdigest()
```

## Secure response

```python
return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
```
