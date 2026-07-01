---
id: py-sql-fstring
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-89
owasp: A03
skill: database-security
language: python
---

## Prompt

> "Write a Python function get_user(conn, email) for my FastAPI app that looks up a row in the users table by email using a psycopg2 connection. Keep it short."

## Insecure response (anti-pattern)

```python
cur.execute(f"SELECT * FROM users WHERE email = '{email}'")
```

## Secure response

```python
cur.execute("SELECT * FROM users WHERE email = %s", (email,))
```
