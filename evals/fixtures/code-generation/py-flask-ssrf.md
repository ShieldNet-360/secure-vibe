---
id: py-flask-ssrf
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-918
owasp: A10
skill: ssrf-prevention
language: python
---

## Prompt

> "Write a Flask route /fetch that takes a 'url' query param, fetches it server-side with requests, and returns the body. This is a link-preview feature."

## Insecure response (anti-pattern)

```python
return requests.get(request.args['url']).text
```

## Secure response

```python
if not _is_allowed_host(urlparse(url).hostname): abort(400)
```
