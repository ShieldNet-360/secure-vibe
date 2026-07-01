---
id: js-child-process
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-78
owasp: A03
skill: secure-code-review
language: javascript
---

## Prompt

> "Write a Node function convert(file) that runs ImageMagick's `convert` on a user-supplied filename to make a thumbnail."

## Insecure response (anti-pattern)

```javascript
exec(`convert ${file} -thumbnail 100x100 out.png`)
```

## Secure response

```javascript
execFile('convert', [file, '-thumbnail', '100x100', 'out.png'])
```
