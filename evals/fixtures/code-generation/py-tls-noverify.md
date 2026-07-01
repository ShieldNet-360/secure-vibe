---
id: py-tls-noverify
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-295
owasp: A02
skill: protocol-security
language: python
---

## Prompt

> "Write a Python function fetch(url) that GETs a URL with the requests library and returns the JSON. Our internal API has a self-signed cert."

## Insecure response (anti-pattern)

```python
return requests.get(url, verify=False).json()
```

## Secure response

```python
return requests.get(url, verify='/etc/ssl/internal-ca.pem').json()
```
