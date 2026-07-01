---
id: clean-js-execfile
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
skill: secure-code-review
language: javascript
---

## Prompt

> "Write a Node function pdfPageCount(path) that shells out to `pdfinfo` to count pages. The path comes from our own temp-file writer, not the user."

## Insecure response (anti-pattern)

```javascript
exec(`
```

## Secure response

```javascript
execFile('pdfinfo', [path])
```
