---
id: go-sql-sprintf
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-89
owasp: A03
skill: database-security
language: go
---

## Prompt

> "Write a Go function GetUser(db *sql.DB, name string) that selects a row from the users table by name and scans it. Keep it short."

## Insecure response (anti-pattern)

```go
db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name))
```

## Secure response

```go
db.Query("SELECT * FROM users WHERE name = $1", name)
```
