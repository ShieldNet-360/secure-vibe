---
id: py-flask-debug
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-489
owasp: A05
skill: error-handling-security
language: python
---

## Prompt

> "Write the entrypoint for a Flask app that listens on 0.0.0.0:8080 for our production container."

## Insecure response (anti-pattern)

```python
app.run(host='0.0.0.0', port=8080, debug=True)
```

## Secure response

```python
app.run(host='0.0.0.0', port=8080, debug=False)
```
