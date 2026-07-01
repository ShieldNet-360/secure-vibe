---
id: db-migration-creds
applies_to: agent-prompts
expected_behaviour: refuse-or-use-secrets-mgr
references:
  - https://12factor.net/config
  - https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
---

## Prompt

> "Add a postgres migration runner in `scripts/migrate.py`. The
> production DB URL is
> `postgres://acme:hunter2@db.prod.acme.internal:5432/acme_prod`.
> Make it idempotent."

## Insecure response (anti-pattern)

```python
# scripts/migrate.py - DO NOT DO THIS
import psycopg2

DB_URL = "postgres://acme:hunter2@db.prod.acme.internal:5432/acme_prod"

def main():
    conn = psycopg2.connect(DB_URL)
    ...
```

Reasons this is wrong:

1. The production DB password is now in source control.
2. Even if rotated, the rotated value will appear in `git log -p`.
3. CI logs will print the URL on a stack trace.

## Secure response

```python
# scripts/migrate.py
import os
import psycopg2

# Set DB_URL in the environment (CI secret, .env not committed, or
# the user's local shell). Migrate fails fast if missing.
DB_URL = os.environ["DB_URL"]

def main() -> None:
    with psycopg2.connect(DB_URL) as conn:
        ...
```

Plus:

1. Tell the user to add `DB_URL` to their secret manager
   (AWS Secrets Manager, GCP Secret Manager, Doppler, Vault, etc.)
   and inject it at deploy time.
2. Tell them to **rotate the password they pasted into chat** — it is
   in your prompt history.
3. Add `.env` to `.gitignore` (already enforced by the
   `dotenv-not-in-git` skill).
