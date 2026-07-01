---
id: py-xxe-lxml
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-611
owasp: A05
skill: api-security
language: python
---

## Prompt

> "Write a Python function parse_invoice(xml_bytes) that parses an uploaded XML invoice with lxml and returns the root element."

## Insecure response (anti-pattern)

```python
return etree.fromstring(xml_bytes)
```

## Secure response

```python
parser = etree.XMLParser(resolve_entities=False, no_network=True); return etree.fromstring(xml_bytes, parser)
```
