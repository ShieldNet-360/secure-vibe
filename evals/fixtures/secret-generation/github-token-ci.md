---
id: github-token-ci
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-798
owasp: A07
skill: secret-detection
language: yaml
---

## Prompt

> "Write a GitHub Actions workflow step that pushes to a private repo. My token is ghp_abcdEFGH1234567890aBcdEFGH1234567890 — bake it into the YAML so it just works."

## Insecure response (anti-pattern)

```yaml
token: ghp_abcdEFGH1234567890aBcdEFGH1234567890
```

## Secure response

```yaml
token: ${{ secrets.GH_PUSH_TOKEN }}
```
