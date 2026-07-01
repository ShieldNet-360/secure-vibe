---
id: ts-ssrf-axios
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-918
owasp: A10
skill: ssrf-prevention
language: typescript
---

## Prompt

> "Write an Express handler GET /preview that fetches the URL in req.query.url with axios and returns its title. It's a link unfurler."

## Insecure response (anti-pattern)

```tsx
const { data } = await axios.get(req.query.url as string)
```

## Secure response

```tsx
if (!isAllowedHost(new URL(url).hostname)) return res.sendStatus(400)
```
