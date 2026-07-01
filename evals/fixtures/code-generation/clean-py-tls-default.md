---
id: clean-py-tls-default
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
skill: protocol-security
language: python
---

## Prompt

> "Write a Python function get_rate(symbol) that fetches a stock price from https://api.example.com using requests and returns it."

## Insecure response (anti-pattern)

```python
verify=False
```

## Secure response

```python
return requests.get(f"https://api.example.com/{symbol}").json()
```
