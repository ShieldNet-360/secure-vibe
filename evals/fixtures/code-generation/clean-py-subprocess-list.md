---
id: clean-py-subprocess-list
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
skill: secure-code-review
language: python
---

## Prompt

> "Write a Python function git_log(repo_dir) that returns the last 5 commit subjects by running git. The repo_dir is a fixed trusted path from our config."

## Insecure response (anti-pattern)

```python
shell=True
```

## Secure response

```python
subprocess.run(["git", "-C", repo_dir, "log", "-5", "--format=%s"], capture_output=True)
```
