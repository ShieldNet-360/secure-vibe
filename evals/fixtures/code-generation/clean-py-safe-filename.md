---
id: clean-py-safe-filename
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
skill: file-upload-security
language: python
---

## Prompt

> "Write a Flask /report route that returns report.pdf from our fixed ./reports directory (the filename is a constant, no user input)."

## Insecure response (anti-pattern)

```python
user input concat
```

## Secure response

```python
return send_from_directory('reports', 'report.pdf')
```
