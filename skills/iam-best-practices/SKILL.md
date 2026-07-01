---
id: iam-best-practices
version: "1.1.0"
title: "Identity & Access Management Best Practices"
description: "Least-privilege IAM design, key rotation, MFA enforcement, role assumption, and cross-account access patterns for AWS / GCP / Azure / Kubernetes"
category: prevention
severity: critical
applies_to:
  - "when generating IAM policies, roles, or trust documents"
  - "when wiring CI/CD service accounts or workload identities"
  - "when reviewing access-key creation, rotation, or revocation"
  - "when designing cross-account or cross-tenant access"
languages: ["hcl", "yaml", "json", "python", "go", "typescript"]
token_budget:
  minimal: 1100
  compact: 1500
  full: 2400
rules_path: "rules/"
related_skills: ["auth-security", "iac-security", "secret-detection"]
last_updated: "2026-06-20"
sources:
  - "NIST SP 800-53 Rev. 5 (AC-2, AC-3, AC-6, AC-17, IA-2, IA-5)"
  - "NIST SP 800-63B (Authenticator Assurance)"
  - "CIS Controls v8 (Controls 5 and 6)"
  - "AWS IAM Best Practices"
  - "Google Cloud IAM Recommender"
  - "Microsoft Azure RBAC Best Practices"
  - "CNCF Kubernetes RBAC Good Practices"
  - "OWASP Cloud Security Top 10"
external_tools:
  - name: prowler
    purpose: "live cloud account IAM/security posture assessment (AWS/Azure/GCP)"
    command: "prowler aws"
---

# Identity & Access Management Best Practices

## Rules (for AI agents)

### ALWAYS
- Grant the **minimum** permissions required for the workload's stated job
  (NIST AC-6). Start with a deny-by-default policy and add concrete actions
  with explicit `Resource` ARNs; never `Action: "*"` combined with
  `Resource: "*"`.
- Prefer **workload identity** (IAM roles for service accounts on EKS,
  GKE Workload Identity, Azure Managed Identity) over long-lived access
  keys. Static access keys are the exception, not the default.
- Require **MFA** for every human IAM user, especially any principal that
  can assume a privileged role. Enforce MFA via an IAM policy condition
  (`aws:MultiFactorAuthPresent: true`), not just a directory-level setting.
- Rotate access keys, service-account keys, and signing keys on a documented
  schedule (≤ 90 days). Detect inactive credentials (≥ 90 days unused) and
  disable them automatically.
- Use **role assumption with `sts:AssumeRole` + ExternalId** for cross-account
  trust. The ExternalId must be unique per consumer and stored as a secret
  in both accounts.
- Issue **session-scoped** credentials with `MaxSessionDuration ≤ 1h` for
  human roles and ≤ 12h for break-glass roles. Long-lived sessions defeat
  rotation.
- Separate **deploy** and **runtime** identities. The CI/CD pipeline gets a
  deploy role; the running service gets a distinct runtime role with no
  IAM-mutating permissions.
- For Kubernetes RBAC, scope `Role` / `RoleBinding` to a single namespace;
  use `ClusterRole` only for true cluster-wide objects. Audit
  `cluster-admin` bindings on every PR.
- Log every IAM-mutating call (CloudTrail / Cloud Audit Logs / Azure
  Activity Log) to a tamper-evident sink. Alert on policy changes,
  `iam:PassRole`, `iam:CreateAccessKey`, and `sts:AssumeRole` from
  unexpected principals.
- For **break-glass** access (root, owner, cluster-admin), require an
  out-of-band approval (e.g., PagerDuty incident + ticket) and emit an
  immediate alert on every use.
- Tag every IAM principal with `owner`, `environment`, and `purpose`. Use
  these tags in SCPs / org policies to constrain blast radius.

### NEVER
- Use the **root account** for day-to-day operations. Root credentials get a
  hardware MFA device, are stored offline, and are used only for the small
  set of root-only tasks (e.g., closing the account, changing the support
  plan).
- Embed long-lived access keys in source, container images, AMIs, or
  CI environment variables when a workload identity is available.
- Grant `iam:PassRole` with `Resource: "*"`. Always pin the role ARNs the
  caller may pass to downstream services.
- Grant `iam:*` or `sts:*` to a runtime workload — these are deploy-time
  permissions only.
- Share a single IAM user across multiple humans or services. One principal
  per identity is the audit invariant.
- Use `AdministratorAccess` (or any `*:*`) managed policy on a routine basis;
  treat it as a break-glass-only attachment.
- Trust any cross-account assume-role without an `ExternalId` condition for
  third-party integrations (Confused Deputy: AWS Security Bulletin 2021).
- Hard-code AWS / GCP / Azure ARNs / resource IDs in policy documents
  without a corresponding tag-based or organization-path scope (when the
  number of resources can grow).
- Disable MFA for a principal to "fix" a login problem — rotate the device,
  do not remove the requirement.
- Persist OIDC / SAML assertion tokens beyond their stated TTL. Refresh by
  re-assertion, not by storing the original token.

### KNOWN FALSE POSITIVES
- `Resource: "*"` is acceptable for inherently account-scoped read
  operations like `ec2:DescribeRegions` or `sts:GetCallerIdentity` — those
  APIs do not accept a resource ARN.
- Service-linked roles (e.g., `AWSServiceRoleForAutoScaling`) ship with
  broader permissions than your custom roles; that is by design and
  managed by the provider.
- One-time bootstrap operators (Terraform-runners in a fresh account) often
  need elevated permissions; gate by tag / SCP and revoke after the
  bootstrap is complete.
- Local-development emulators (LocalStack, GCS emulator) may accept any
  credentials; that is a property of the emulator, not a real grant.

## Context (for humans)

Identity & access management is the foundation of every cloud security
control. The recurring failure modes are: over-permissive policies
(`*:*`), long-lived access keys checked into git, missing MFA on
privileged accounts, and `AssumeRole` trust policies without an
`ExternalId`. These are the same root causes documented in the Capital
One (2019), Verkada (2021), and Uber (2022) breaches.

The high-leverage controls are:

1. **Workload identity over access keys.** A pod in EKS that assumes a
   role via IRSA never needs a credential to leak.
2. **MFA on every human, enforced by policy.** A leaked password alone
   is no longer sufficient to act.
3. **Least-privilege grants reviewed at PR time.** The cheapest moment
   to constrain a permission is when it's being added — not when an
   auditor asks six months later.
4. **Mandatory key rotation.** Static credentials silently age into
   liabilities; automate the rotation so it is not skipped.
5. **Cross-account trust with ExternalId.** The Confused Deputy class
   of attacks is fully mitigated by an ExternalId convention.

This skill enforces those controls when AI assistants generate IAM
policies, trust documents, or CI/CD identities.


### Verify & lock (triaging a finding)

A scanner/review hit is a *candidate*, not a confirmed bug. Confirm it, fix it,
then lock it so it can't come back.

1. **Confirm it's real (simulate, don't eyeball).** A wildcard in JSON isn't
   proof — what the *effective* policy resolves to is. Run the provider's policy
   evaluator: `aws iam simulate-principal-policy` (or GCP Policy Troubleshooter,
   Azure `az role assignment list`) for the flagged action against a concrete
   resource — `iam:PassRole`, `iam:CreateAccessKey`/`AttachUserPolicy` (priv-esc),
   `*:*`, `s3:*` on `*`, or a cross-account `sts:AssumeRole`. Or, in a sandbox,
   assume the role and attempt the dangerous action. Real if the result is
   ALLOWED; FP if a permission boundary, SCP, or `Condition` already denies it
   (or it's an account-scoped read like `ec2:DescribeRegions` that ignores ARNs).
   For credentials/MFA, check the live fact: key age & last-used
   (`aws iam get-access-key-last-used`), and whether `aws:MultiFactorAuthPresent`
   is actually enforced — not just toggled in the directory.
2. **Fix, then lock with a regression test** (unit *or* integration — dev's call):
   pin the action and `Resource` ARN, add the missing `ExternalId`/MFA/expiry
   condition, or swap the long-lived key for a workload identity. Then add a
   policy unit test (or CI check on the policy JSON) asserting the simulator
   DENIES the dangerous action *and* ALLOWS the workload's legitimate one, plus a
   lint that fails on `Action:"*"`+`Resource:"*"`, `PassRole` on `*`, or trust
   without `ExternalId`. Commit it so the guard can't be silently dropped.

## References

- `rules/iam_policy_invariants.json`
- `rules/key_rotation_policy.json`
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html).
- [Google Cloud IAM recommender](https://cloud.google.com/iam/docs/recommender-overview).
- [NIST SP 800-53 Rev. 5](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf).
- [CIS Controls v8](https://www.cisecurity.org/controls/v8).
- [CNCF Kubernetes RBAC Good Practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/).
