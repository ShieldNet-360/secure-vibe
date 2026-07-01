---
id: serverless-security
version: "1.0.0"
title: "Serverless Security"
description: "Lambda / Cloud Functions / Azure Functions hardening: IAM, timeouts, secrets, event injection"
category: hardening
severity: high
applies_to:
  - "when generating AWS Lambda / GCP Cloud Functions / Azure Functions code"
  - "when generating serverless.yml / SAM templates / functions framework"
  - "when wiring API Gateway, EventBridge, SQS, S3 triggers"
languages: ["python", "javascript", "typescript", "go", "java", "yaml"]
token_budget:
  minimal: 1000
  compact: 1100
  full: 2200
rules_path: "checklists/"
related_skills: ["iac-security", "api-security", "secret-detection"]
last_updated: "2026-06-20"
sources:
  - "OWASP Serverless Top 10"
  - "AWS Well-Architected: Security Pillar — Lambda"
  - "CIS AWS Foundations Benchmark §3 (Lambda)"
  - "NIST SP 800-204 (Microservices)"
---

# Serverless Security

## Rules (for AI agents)

### ALWAYS
- Give each function its own IAM execution role with the minimum permissions
  needed. Never share roles across functions; never reuse the bootstrap /
  developer role.
- Set a concrete function timeout (≤ 30s for synchronous APIs, ≤ 15min for
  background jobs). Defaults like 6s or 900s are footguns in different
  directions.
- Set reserved or provisioned concurrency limits per function to avoid bill
  blow-outs and to keep one noisy tenant from starving the rest of the
  account.
- Pull secrets at cold-start from a secret manager (AWS Secrets Manager / GCP
  Secret Manager / Azure Key Vault) **with caching**, not from plaintext
  environment variables.
- Validate every event payload against a schema before any code that touches
  it. Lambda doesn't care that the event arrived from "your" SQS queue — it
  could be a poison message.
- Enable structured logging that redacts known secret patterns (delegate to
  the `logging-security` skill).
- Enable X-Ray / OpenTelemetry tracing and CloudWatch / Cloud Monitoring
  alerts on error rate, throttle count, duration p95.
- Use a VPC for functions that touch a private database or service; otherwise
  the function gets full outbound internet, which is rarely desirable.

### NEVER
- Use `arn:aws:iam::*:role/*` (wildcard PassRole), `*:*` action/resource, or
  `iam:*` permissions on a function role.
- Put secrets in environment variables in plaintext (use Secrets Manager
  references / `aws_lambda_function.environment` with `kms_key_arn`).
- Pass user-controlled strings to `exec`, `os.system`, `child_process`,
  `subprocess.Popen(shell=True)` — function URLs become RCE shortcuts when
  someone shells out.
- Trust the Lambda function URL or API Gateway resource as authentication.
  Function URLs with `AUTH_TYPE=NONE` are unauthenticated; require IAM,
  Cognito, or a Lambda authorizer.
- Disable `aws_lambda_function.code_signing_config_arn` for production
  functions; sign and verify on deploy.
- Use the `latest` image tag for container-image functions; pin by digest.
- Use long-lived static AWS access keys to call AWS from Lambda — use the
  execution role.
- Skip validation of S3 / SQS / EventBridge event payloads — assume any caller
  can post any shape, even if the trigger is "trusted".

### KNOWN FALSE POSITIVES
- Custom CloudFormation / Lambda resource handlers (`cfn-response`) sometimes
  legitimately need broad permissions for short-lived setup.
- Cold-start warmer hacks (pinging the function on a CloudWatch Events
  schedule) are not, themselves, a security issue.
- Step Functions iterators with thousands of map states are not an "untracked
  concurrency" problem if the StateMachine has its own concurrency cap.

## Context (for humans)

OWASP's Serverless Top 10 names the same families as the regular Top 10 plus
two serverless-specific risks: **event injection** (the event itself contains
untrusted input — an SQS message, an S3 object key — that downstream code
treats as trusted) and **denial-of-wallet** (an attacker exhausts your
concurrency to run up your bill).

AI assistants tend to generate Lambdas with `*:*` IAM, environment-variable
secrets, and no event validation. This skill is the counterweight.


### Verify & lock (triaging a finding)

A scanner/review hit is a *candidate*, not a confirmed bug. Confirm it, fix it,
then lock it so it can't come back.

1. **Confirm it's real (probe / inspect).** Pick the check that matches the
   class. *Event injection / missing validation:* invoke the handler with a
   crafted event (poison SQS message, hostile S3 object key, attacker-shaped
   API-GW body) and see if the untrusted field reaches a sink (DB query, shell,
   downstream call) unvalidated — real if it lands, FP if a schema rejects it
   first. *Over-privileged role:* read the function's execution-role policy or
   run the IAM simulator — real on `*:*`, `iam:*`, or wildcard `PassRole`, FP if
   already scoped to the exact actions/resources used. *Secrets in env:* dump the
   function config — real if a credential sits in plaintext env vars, FP if it's
   a Secrets-Manager/Key-Vault reference. *Unrestricted egress / denial-of-wallet
   / open URL:* check for no VPC + open security group, missing reserved
   concurrency, or `AUTH_TYPE=NONE` — confirm against intended behavior.
2. **Fix, then lock with a regression test** (unit *or* integration — dev's
   call): unit-invoke the handler with the malicious event and assert it's
   rejected/sanitized, plus a benign event that succeeds; and/or a policy test
   asserting the role is least-privilege (no wildcards) and secrets resolve from
   the manager, not env. Commit it so the guard can't be silently dropped.

## References

- `checklists/lambda_hardening.yaml`
- `checklists/event_validation.yaml`
- [OWASP Serverless Top 10](https://owasp.org/www-project-serverless-top-10/).
- [AWS Well-Architected Security Pillar — Serverless](https://docs.aws.amazon.com/wellarchitected/latest/serverless-applications-lens/security-pillar.html).
