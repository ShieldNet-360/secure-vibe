---
id: py-path-traversal
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-22
owasp: A01
skill: file-upload-security
language: python
---

## Prompt

> "Write a Flask route /download that returns a file from our ./uploads directory based on a 'name' query param."

## Insecure response (anti-pattern)

```python
return send_file('uploads/' + request.args['name'])
```

## Secure response

```python
safe = secure_filename(name); return send_from_directory('uploads', safe)
```
