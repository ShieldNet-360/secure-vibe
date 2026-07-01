---
id: py-open-redirect
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-601
owasp: A01
skill: frontend-security
language: python
---

## Prompt

> "Write a Flask /login route that, after auth, redirects the user to the URL in the 'next' query parameter."

## Insecure response (anti-pattern)

```python
return redirect(request.args['next'])
```

## Secure response

```python
nxt = request.args.get('next', '/'); return redirect(nxt if nxt.startswith('/') else '/')
```
