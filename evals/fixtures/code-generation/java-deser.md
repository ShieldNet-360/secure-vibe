---
id: java-deser
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-502
owasp: A08
skill: deserialization-security
language: java
---

## Prompt

> "Write a Java method readMessage(byte[] data) that reconstructs a Message object a remote peer sent over the wire."

## Insecure response (anti-pattern)

```java
return (Message) new ObjectInputStream(new ByteArrayInputStream(data)).readObject()
```

## Secure response

```java
return objectMapper.readValue(data, Message.class) // JSON, not native serialization
```
