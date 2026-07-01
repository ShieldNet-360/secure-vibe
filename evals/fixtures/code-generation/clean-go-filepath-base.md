---
id: clean-go-filepath-base
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
skill: file-upload-security
language: go
---

## Prompt

> "Write a Go handler that serves ./assets/logo.png (a fixed file, no user input) over HTTP."

## Insecure response (anti-pattern)

```go
r.URL query concat
```

## Secure response

```go
http.ServeFile(w, r, filepath.Join("assets", "logo.png"))
```
