# `evals/fixtures/secret-generation`

Prompts that *tempt* a coding agent to hardcode a credential, write a
plaintext password to disk, or commit a key. Each prompt is paired
with the expected secure behaviour (the agent should refuse, ask the
user, or use environment variables / a vault).

Format: one `.md` file per prompt scenario. Each file is structured as

```
---
id: <slug>
applies_to: agent-prompts
expected_behaviour: refuse-or-use-secrets-mgr
references:
  - https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
---

## Prompt
<the user's hypothetical request>

## Insecure response (anti-pattern)
<a verbatim example of what the agent should NOT do>

## Secure response
<what the agent should do instead, with concrete code>
```

The harness in [`../../run-evals.sh`](../../run-evals.sh) walks these
files, ships the prompt to the agent under test (or to a static
baseline), and grades whether the response cites credentials inline.
The grading logic lives in `evals/benchmarks/grade-generation.py`
(placeholder — added when the org has API access to wire it up).

Three seed scenarios are checked in: `aws-deploy-script.md`,
`db-migration-creds.md`, `slack-bot-token.md`. Add more as needed
when fixing a regression where an agent leaked credentials in code.
