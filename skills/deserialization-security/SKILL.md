---
id: deserialization-security
version: "1.0.0"
title: "Deserialization Security"
description: "Block unsafe deserialization across Java, Python, .NET, PHP, Ruby, Node.js — gadget chains, type allowlisting, safer alternatives"
category: prevention
severity: critical
applies_to:
  - "when generating code that deserializes data from any untrusted source"
  - "when wiring cookies, sessions, message queues, or RPC payloads"
  - "when reviewing pickle / unserialize / Marshal / ObjectInputStream / BinaryFormatter usage"
languages: ["java", "python", "csharp", "php", "ruby", "javascript", "typescript"]
token_budget:
  minimal: 1200
  compact: 1500
  full: 2200
rules_path: "rules/"
related_skills: ["api-security", "crypto-misuse", "supply-chain-security"]
last_updated: "2026-06-20"
sources:
  - "OWASP Deserialization Cheat Sheet"
  - "CWE-502: Deserialization of Untrusted Data"
  - "CVE-2017-9805 (Struts2 XStream)"
  - "CVE-2016-4437 (Shiro RememberMe)"
  - "CVE-2019-2725 (WebLogic XMLDecoder)"
---

# Deserialization Security

## Rules (for AI agents)

### ALWAYS
- Prefer **structural, schema-validated** formats (JSON with a JSON Schema
  validator, Protobuf, FlatBuffers, MessagePack with an explicit type map)
  over polymorphic native serializers. The trade-off "save 10 lines of
  mapping code" is never worth the RCE primitive.
- When a polymorphic deserializer is unavoidable, configure a **strict
  type allowlist** at the framework level (Jackson `PolymorphicTypeValidator`,
  fastjson safeMode, .NET `KnownTypeAttribute`, XStream `Whitelist`). The
  default of "any class" is the source of every modern Java deserialization
  CVE.
- Sign and authenticate any cookie or token that carries serialized data
  with a fresh random key (HMAC-SHA-256, minimum). Never deserialize before
  HMAC verification.
- Run deserialization code paths under the minimum capabilities the format
  needs (no filesystem, no network, no subprocess, no reflection) — e.g.
  Java `ObjectInputFilter` patterns; Python in a constrained namespace.
- Treat any of the following functions as "untrusted-input deserialization
  primitives": Java `ObjectInputStream.readObject`, Jackson with
  `enableDefaultTyping`, SnakeYAML `Yaml.load()`, XStream `fromXML`,
  Python `pickle.load(s)` / `cPickle` / `dill` / `joblib.load`,
  `yaml.load` (default Loader), `numpy.load(allow_pickle=True)`,
  `torch.load`, PHP `unserialize`, .NET `BinaryFormatter` /
  `ObjectStateFormatter` / `NetDataContractSerializer` / `LosFormatter`,
  Ruby `Marshal.load` / `YAML.load` (Psych ≤ 3.0). Adding one of these
  to a request-handling code path requires explicit security review.

### NEVER
- Pass untrusted bytes to any of the primitives above without an
  HMAC-authenticated wrapper. Even with a wrapper, prefer a non-polymorphic
  format.
- Use Java `Jackson` with `objectMapper.enableDefaultTyping()` or
  `@JsonTypeInfo(use = Id.CLASS)`. The default of `LAMINAR_INTERNAL_DEFAULT`
  produces a class-id gadget chain (ysoserial / marshalsec).
- Use `SnakeYAML new Yaml()` without explicitly specifying a `SafeConstructor`
  (or `Constructor` with an allowlist). The default constructor is the
  source of common Java YAML RCE CVEs.
- Use Python `pickle.loads` on data from a network socket, a database
  column, a Redis cache key, or anywhere that crosses a trust boundary.
  No amount of validation makes pickle safe.
- Use Python `yaml.load(data)` (without `Loader=yaml.SafeLoader`). PyYAML
  changed the default in 6.0 to fail loudly — older code paths still ship
  the unsafe default.
- Use Python `torch.load(path)` on a downloaded checkpoint without
  `weights_only=True` (PyTorch ≥ 2.6 defaults to True; older versions
  reach pickle and execute arbitrary code).
- Use PHP `unserialize()` on cookie / POST / GET data. PHP serialized
  format has a long history of magic-method gadget chains (`__wakeup`,
  `__destruct`, `__toString`).
- Use .NET `BinaryFormatter`, `NetDataContractSerializer`,
  `ObjectStateFormatter`, `LosFormatter` for any input crossing a trust
  boundary. Microsoft marks `BinaryFormatter` as obsolete and unsafe.
- Trust the contents of a Ruby `Marshal.load` from anywhere outside the
  same process. Same restriction for `YAML.load` on older Psych.

### KNOWN FALSE POSITIVES
- Internal RPC where both sides are operator-controlled, the data is
  authenticated end-to-end (mTLS + HMAC), and the format choice is
  pragmatic (e.g. Java services using ObjectInputStream over a
  TLS+mTLS-only socket may be acceptable in some legacy stacks).
- Build-time / configuration-time deserialization of files that ship in
  the repository (pickle test fixtures, etc.) — but mark them clearly
  and never load them from a download.
- Cryptographically-authenticated session formats like Rails' default
  signed-cookie sessions are intended use of Marshal, but only because
  the HMAC gates the deserialization.

## Context (for humans)

Deserialization vulnerabilities are the single most reliable RCE
primitive in modern enterprise stacks. The economics are simple: when
the serializer allows arbitrary class instantiation, the codebase has
already imported thousands of classes — many of which have side-effects
in their `readObject`, `__reduce__`, `__wakeup`, `Read*` callbacks. A
gadget chain combines these side-effects into RCE.

ysoserial (Java), ysoserial.net (.NET), marshalsec (Java), and the
Python pickle gadget catalogs are mature tooling. Every "is this
exploitable?" question is "yes, with the gadgets already on your
classpath."

The fix is not to filter — it is to use a format that doesn't permit
arbitrary class instantiation in the first place. Most modern services
ship signed JWTs / JSON over mTLS. Where a polymorphic format is
unavoidable, type-allowlist + HMAC are non-negotiable.


### Verify & lock (triaging a finding)

A scanner/review hit is a *candidate*, not a confirmed bug. Confirm it, fix it,
then lock it so it can't come back.

1. **Confirm it's real (probe the suspect input).** Feed the deserializer a crafted
   payload whose gadget fires a *benign canary* — e.g. a pickle/PHP object whose
   `__reduce__`/`__wakeup`/`__destruct` (or a Java `readObject` / SnakeYAML
   `!!javax...` / .NET gadget) touches a marker file or sleeps a fixed interval.
   Send it through the actual sink (`pickle.loads`, `yaml.load`, `ObjectInputStream`,
   `unserialize`, `BinaryFormatter`, `Marshal.load`). **Real** if the canary fires
   (file appears, request hangs) — arbitrary class instantiation is reachable.
   **False positive** if the path is HMAC-gated before deserialize, uses a
   SafeLoader/`weights_only=True`/strict type-allowlist, or only loads repo-shipped
   build fixtures (per KNOWN FALSE POSITIVES).
2. **Fix, then lock with a regression test** (unit *or* integration — dev's call):
   swap to a non-polymorphic/schema-validated format, or a safe loader plus type
   allowlist (`SafeConstructor`, `PolymorphicTypeValidator`, `weights_only=True`) and
   HMAC-verify before any decode. Assert the **canary payload is rejected** (raises /
   returns no object, canary never fires) **and** a **legitimate payload still loads**
   into the expected type. Commit it to CI so the guard can't be silently dropped in a
   later refactor.

## References

- `rules/unsafe_deserializers.json`
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html).
- [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
- [ysoserial](https://github.com/frohoff/ysoserial).
- [ysoserial.net](https://github.com/pwntester/ysoserial.net).
- [marshalsec](https://github.com/frohoff/marshalsec).
