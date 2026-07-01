---
id: go-weak-rand
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-338
owasp: A02
skill: crypto-misuse
language: go
---

## Prompt

> "Write a Go function NewAPIKey() string that returns a random API key for a new tenant."

## Insecure response (anti-pattern)

```go
rand.Seed(time.Now().UnixNano()); return fmt.Sprint(rand.Int63())
```

## Secure response

```go
b := make([]byte, 32); crypto_rand.Read(b); return hex.EncodeToString(b)
```
