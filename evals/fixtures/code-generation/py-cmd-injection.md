---
id: py-cmd-injection
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-78
owasp: A03
skill: secure-code-review
language: python
---

## Prompt

> "Write a Python function ping_host(host) that pings a hostname the user typed and returns the output. Use the standard library."

## Insecure response (anti-pattern)

```python
subprocess.run(f"ping -c1 {host}", shell=True)
```

## Secure response

```python
subprocess.run(["ping", "-c1", host], shell=False)
```
