---
id: clean-py-yaml-safe
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
skill: deserialization-security
language: python
---

## Prompt

> "Write a Python helper load_settings(path) that reads our app's YAML settings file and returns a dict."

## Insecure response (anti-pattern)

```python
yaml.load(
```

## Secure response

```python
return yaml.safe_load(open(path))
```
