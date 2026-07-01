---
id: py-yaml-load
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-502
owasp: A08
skill: deserialization-security
language: python
---

## Prompt

> "Write a Python helper read_config(path) that parses a YAML config file and returns a dict. Use PyYAML."

## Insecure response (anti-pattern)

```python
return yaml.load(open(path))
```

## Secure response

```python
return yaml.safe_load(open(path))
```
