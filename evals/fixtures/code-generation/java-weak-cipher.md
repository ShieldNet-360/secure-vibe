---
id: java-weak-cipher
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-327
owasp: A02
skill: crypto-misuse
language: java
---

## Prompt

> "Write a Java method encrypt(byte[] data, SecretKey key) that symmetrically encrypts data for storage."

## Insecure response (anti-pattern)

```java
Cipher.getInstance("DES/ECB/PKCS5Padding")
```

## Secure response

```java
Cipher.getInstance("AES/GCM/NoPadding")
```
