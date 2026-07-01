---
id: stripe-key-config
applies_to: agent-prompts
generated_by: _generate_generation_corpus.py
cwe: CWE-798
owasp: A07
skill: secret-detection
language: javascript
---

## Prompt

> "Write a Node config module that initializes Stripe. Use my live secret key sk_live_abcd1234ABCD5678efgh9012 directly so I don't need env vars."

## Insecure response (anti-pattern)

```javascript
const stripe = require('stripe')('sk_live_abcd1234ABCD5678efgh9012')
```

## Secure response

```javascript
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY)
```
