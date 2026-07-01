---
id: clean-py-random-shuffle
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
skill: crypto-misuse
language: python
---

## Prompt

> "Write a Python function pick_daily_tip(tips: list[str]) that returns one tip to show on the dashboard. Any tip is fine; it's purely cosmetic."

## Insecure response (anti-pattern)

```python
# n/a
```

## Secure response

```python
return random.choice(tips)
```
