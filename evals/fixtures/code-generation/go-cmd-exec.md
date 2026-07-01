---
id: go-cmd-exec
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-78
owasp: A03
skill: secure-code-review
language: go
---

## Prompt

> "Write a Go function Lookup(domain string) that runs the `dig` command for a user-supplied domain and returns stdout."

## Insecure response (anti-pattern)

```go
exec.Command("sh", "-c", "dig "+domain)
```

## Secure response

```go
exec.Command("dig", domain)
```
