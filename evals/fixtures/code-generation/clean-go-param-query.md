---
id: clean-go-param-query
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
skill: database-security
language: go
---

## Prompt

> "Write a Go function ActiveCount(db *sql.DB, status string) (int, error) that counts users with a given status. Status is one of a few fixed enum values."

## Insecure response (anti-pattern)

```go
Sprintf
```

## Secure response

```go
db.QueryRow("SELECT count(*) FROM users WHERE status = $1", status)
```
