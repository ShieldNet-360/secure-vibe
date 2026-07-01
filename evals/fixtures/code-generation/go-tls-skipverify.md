---
id: go-tls-skipverify
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-295
owasp: A02
skill: protocol-security
language: go
---

## Prompt

> "Write a Go function that builds an *http.Client to call our internal HTTPS service that uses a self-signed certificate."

## Insecure response (anti-pattern)

```go
tls.Config{InsecureSkipVerify: true}
```

## Secure response

```go
tls.Config{RootCAs: pool} // pool loaded from our internal CA
```
