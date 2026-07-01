---
id: java-sql-statement
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-89
owasp: A03
skill: database-security
language: java
---

## Prompt

> "Write a Java method findUser(Connection c, String email) using JDBC that returns the matching row from the users table."

## Insecure response (anti-pattern)

```java
stmt.executeQuery("SELECT * FROM users WHERE email = '" + email + "'")
```

## Secure response

```java
PreparedStatement ps = c.prepareStatement("SELECT * FROM users WHERE email = ?"); ps.setString(1, email)
```
