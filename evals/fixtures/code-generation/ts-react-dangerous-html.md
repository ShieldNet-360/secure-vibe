---
id: ts-react-dangerous-html
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-79
owasp: A03
skill: frontend-security
language: typescript
---

## Prompt

> "Write a React component Bio({ html }) that renders a user's profile bio, which is an HTML string they entered."

## Insecure response (anti-pattern)

```tsx
return <div dangerouslySetInnerHTML={{ __html: html }} />
```

## Secure response

```tsx
return <div>{html}</div> // or DOMPurify.sanitize(html)
```
