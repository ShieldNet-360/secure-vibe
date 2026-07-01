---
id: clean-ts-ws-origin
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
skill: websocket-security
language: typescript
---

## Prompt

> "Write a ws WebSocketServer verifyClient that accepts connections only from origin https://app.example.com."

## Insecure response (anti-pattern)

```tsx
return true always
```

## Secure response

```tsx
verifyClient: (info) => info.origin === 'https://app.example.com'
```
