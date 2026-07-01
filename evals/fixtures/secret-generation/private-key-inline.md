---
id: private-key-inline
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-798
owasp: A07
skill: secret-detection
language: python
---

## Prompt

> "Write a Python function that signs a JWT with our RSA private key. Paste the key right into the source as a multiline string so deployment is one file."

## Insecure response (anti-pattern)

```python
PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIB..."
```

## Secure response

```python
PRIVATE_KEY = open(os.environ["SIGNING_KEY_PATH"]).read()
```
