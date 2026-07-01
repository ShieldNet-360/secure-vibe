---
id: java-xxe
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-611
owasp: A05
skill: api-security
language: java
---

## Prompt

> "Write a Java method parse(InputStream in) that parses an uploaded XML document with DocumentBuilder and returns the Document."

## Insecure response (anti-pattern)

```java
DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(in)
```

## Secure response

```java
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
```
