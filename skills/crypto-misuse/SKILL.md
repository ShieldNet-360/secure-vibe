---
id: crypto-misuse
version: "1.0.0"
title: "Cryptographic Misuse"
description: "Block weak ciphers, predictable RNG, undersized keys, slow-hash misuse, and non-constant-time comparisons"
category: prevention
severity: critical
applies_to:
  - "when generating code that hashes / encrypts / signs"
  - "when generating code that compares secrets / MACs / tokens"
  - "when wiring TLS settings, key sizes, or RNG"
languages: ["*"]
token_budget:
  minimal: 1000
  compact: 1200
  full: 2500
rules_path: "rules/"
related_skills: ["secret-detection", "auth-security", "protocol-security"]
last_updated: "2026-06-20"
sources:
  - "NIST SP 800-131A Rev. 2"
  - "NIST SP 800-57 Part 1 Rev. 5"
  - "OWASP Cryptographic Storage Cheat Sheet"
  - "CWE-327, CWE-338, CWE-916, CWE-208"
---

# Cryptographic Misuse

## Rules (for AI agents)

### ALWAYS
- Use the language / platform's cryptographic library. Python: `cryptography`,
  `secrets`. JavaScript: Web Crypto, `crypto.webcrypto`, Node `crypto`. Go:
  `crypto/*`, `golang.org/x/crypto`. Java: JCE/Bouncy Castle. .NET:
  `System.Security.Cryptography`.
- Use a cryptographically secure RNG: Python `secrets.token_bytes` /
  `secrets.token_urlsafe`, JS `crypto.getRandomValues` / `crypto.randomBytes`,
  Go `crypto/rand.Read`, Java `SecureRandom`.
- Hash passwords with a slow KDF tuned for ~100 ms on production hardware:
  **argon2id** (preferred, RFC 9106 parameters: m=64 MiB, t=3, p=1), **scrypt**
  (N=2^17, r=8, p=1), or **bcrypt** (cost ≥ 12). Always with a per-user random
  salt.
- Encrypt with AEAD (authenticated encryption): AES-256-GCM, ChaCha20-Poly1305,
  or AES-256-GCM-SIV. Generate a fresh random nonce per encryption.
- Use TLS 1.2+ (TLS 1.3 strongly preferred). Disable TLS 1.0/1.1, SSLv3,
  RC4, 3DES, and export ciphers.
- Compare MACs / signatures / tokens with constant-time helpers:
  `hmac.compare_digest`, `crypto.subtle.timingSafeEqual`,
  `subtle.ConstantTimeCompare`, `MessageDigest.isEqual`,
  `CryptographicOperations.FixedTimeEquals`.
- For asymmetric keys: RSA ≥ 3072 bits, ECDSA P-256 or P-384, Ed25519, X25519.

### NEVER
- Use MD5 or SHA-1 for signatures, certificates, password storage, or message
  authentication. (They remain valid for incidental non-security uses like
  ETag / file deduplication if explicitly documented.)
- Use DES, 3DES, RC4, or Blowfish for new code.
- Use ECB mode. Use CBC without HMAC over the ciphertext. Use CTR/GCM with a
  reused nonce.
- Use unsalted hashes for passwords. Use `sha256(password)` for password
  storage — it's a fast hash; brute force is trivial.
- Use `Math.random()`, Python `random`, `rand()` in C / Go for tokens, IDs,
  nonces, or passwords. They are predictable.
- Hardcode IVs/nonces, salts, or keys. Never reuse a GCM/Poly1305 nonce under
  the same key.
- Compare secrets with `==`, `===`, `strcmp`, `bytes.Equal` — these are
  timing-leaky.
- Roll your own crypto (custom XOR, custom HMAC, custom Diffie–Hellman, custom
  signature schemes). Use audited primitives.

### KNOWN FALSE POSITIVES
- MD5 / SHA-1 in non-security contexts: HTTP ETag computation, content
  deduplication, cache keying for non-sensitive data, fixture fingerprinting.
  Annotate these uses with a `// non-security use: ...` comment.
- Test vectors and KAT (Known Answer Test) values intentionally hardcode IVs,
  keys, and plaintexts — they belong in `tests/` not production.
- Legacy interop: some industry / government protocols still require specific
  legacy ciphers. Document the exception and isolate behind a feature flag.

## Context (for humans)

NIST SP 800-131A Rev. 2 is the authoritative US-government deprecation roadmap
for algorithms; OWASP's storage cheat sheet is the practical "do these things"
companion. The recurring failure modes are: fast hash for passwords (CWE-916),
predictable RNG for tokens (CWE-338), broken cipher choice (CWE-327), and
non-constant-time comparison of secrets (CWE-208).

AI assistants tend to mirror whatever crypto example was popular on Stack
Overflow circa 2014, which means lots of `sha256(password)` and `AES-CBC` with
manual padding. This skill is the counterweight.


### Verify & lock (triaging a finding)

A scanner/review hit is a *candidate*, not a confirmed bug. Confirm it, fix it,
then lock it so it can't come back.

1. **Confirm it's real (inspect the behavior/values, not a browser).** Read the
   primitive at the call site and prove the weakness: encrypt repeated plaintext
   and show ECB yields identical ciphertext blocks; show the IV/nonce/salt is
   static, hardcoded, or reused across calls; confirm the digest is MD5/SHA-1 or
   that passwords go through a fast hash (`sha256(pw)`) instead of a salted KDF;
   trace the key/RNG source — a literal key, `Math.random`/`random`/`rand()`, or
   an undersized RSA/EC key is the bug; for compares, confirm `==`/`strcmp`/
   `bytes.Equal` over a secret instead of a constant-time helper. Rule out the
   known FPs first (MD5/SHA-1 ETag/dedup, test KAT vectors, flagged legacy interop).
2. **Fix, then lock with a regression test** (unit *or* integration — dev's call):
   assert encrypting the same plaintext twice gives different ciphertext (fresh
   random IV/nonce); the algorithm/mode resolves from an allowlist (AEAD, no
   ECB/DES/RC4); password verify uses the slow KDF with a per-user salt; keys load
   from a secret store (not a literal) and meet the size floor; secret comparison
   routes through the constant-time helper — plus a benign positive case (correct
   key/password/MAC still verifies). Commit it to CI so the guard can't be silently
   dropped in a later refactor.

## References

- `rules/algorithm_blocklist.json`
- `rules/key_size_minimums.json`
- [NIST SP 800-131A Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final).
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html).
- [CWE-327](https://cwe.mitre.org/data/definitions/327.html) — Broken or risky crypto.
- [CWE-916](https://cwe.mitre.org/data/definitions/916.html) — Insufficient computational effort for password hash.
