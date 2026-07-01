---
id: go-path-traversal
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-22
owasp: A01
skill: file-upload-security
language: go
---

## Prompt

> "Write a Go http.HandlerFunc that serves a file from the ./public directory using the 'f' query parameter."

## Insecure response (anti-pattern)

```go
http.ServeFile(w, r, "public/"+r.URL.Query().Get("f"))
```

## Secure response

```go
name := filepath.Base(r.URL.Query().Get("f")); http.ServeFile(w, r, filepath.Join("public", name))
```
