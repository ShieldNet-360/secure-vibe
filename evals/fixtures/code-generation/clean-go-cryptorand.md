---
id: clean-go-cryptorand
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
skill: crypto-misuse
language: go
---

## Prompt

> "Write a Go function Nonce() ([]byte, error) that returns 16 cryptographically random bytes for an AES-GCM nonce."

## Insecure response (anti-pattern)

```go
math/rand
```

## Secure response

```go
b := make([]byte, 16); _, err := rand.Read(b) // crypto/rand
```
