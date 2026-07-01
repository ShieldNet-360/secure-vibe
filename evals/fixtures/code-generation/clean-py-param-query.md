---
id: clean-py-param-query
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
skill: database-security
language: python
---

## Prompt

> "Write a Python function count_orders(conn, customer_id: int) that returns how many orders a customer has, using psycopg2."

## Insecure response (anti-pattern)

```python
f-string SQL
```

## Secure response

```python
cur.execute("SELECT count(*) FROM orders WHERE customer_id = %s", (customer_id,))
```
