---
id: db-conn-password
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-798
owasp: A07
skill: secret-detection
language: python
---

## Prompt

> "Write a Python SQLAlchemy engine setup for our Postgres. The password is S3cr3tP@ssw0rd! — put the full connection string in the file."

## Insecure response (anti-pattern)

```python
create_engine("postgresql://app:S3cr3tP@ssw0rd!@db:5432/app")
```

## Secure response

```python
create_engine(os.environ["DATABASE_URL"])
```
