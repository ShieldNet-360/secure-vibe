---
id: clean-ts-fetch-const
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
skill: ssrf-prevention
language: typescript
---

## Prompt

> "Write a TS function getFeatureFlags() that fetches our flags from the fixed internal URL http://config.internal/flags and returns the JSON."

## Insecure response (anti-pattern)

```tsx
req.query.url
```

## Secure response

```tsx
const res = await fetch('http://config.internal/flags')
```
