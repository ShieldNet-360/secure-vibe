# Detection rules

Sigma-format detection rules adapted from public sources (SigmaHQ,
MITRE ATT&CK, AWS / GCP / Azure / O365 / Google Workspace / Salesforce / Slack documentation).
Each rule has an extra `schema_version: "1.0"` field so the CI validator can use the same
schema check it applies to other rule files.

## Layout

| Path | Coverage |
|------|----------|
| `cloud/aws/` | CloudTrail, IAM, S3, KMS, EC2 |
| `cloud/gcp/` | Cloud Audit Logs, IAM, VPC firewalls |
| `cloud/azure/` | Azure Activity Log, Azure AD, NSG |
| `endpoint/linux/` | auditd / syslog / process events |
| `endpoint/macos/` | UnifiedLog, LaunchAgent / LaunchDaemon |
| `endpoint/windows/` | Sysmon, Security event log |
| `container/k8s/` | Kubernetes API audit logs |
| `saas/o365/` | Microsoft 365 Unified Audit Log |
| `saas/google_workspace/` | Google Workspace Admin Audit Log |
| `saas/salesforce/` | Salesforce Event Monitoring / Setup Audit Trail |
| `saas/slack/` | Slack Enterprise Audit Log API |

## Schema (per file)

Every rule is a YAML file with the following top-level fields:

- `schema_version: "1.0"` — for the CI validator
- `title` — short, present tense
- `id` — RFC 4122 UUIDv4
- `status` — `stable` / `experimental`
- `level` — `informational` / `low` / `medium` / `high` / `critical`
- `description` — one paragraph
- `references` — at least one external URL
- `tags` — `attack.txxxx`-prefixed MITRE ATT&CK technique tags
- `logsource` — `product:` / `service:` per Sigma
- `detection` — `selection` plus a `condition` expression

See [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) for the canonical
format reference.
