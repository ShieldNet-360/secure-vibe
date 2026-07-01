---
id: saas-security
version: "1.0.0"
title: "SaaS Application Security"
description: "Detect tokens, misconfigurations, and admin red flags for major SaaS platforms (GWS, Atlassian, Notion, HubSpot, Salesforce, BambooHR, Workday, Odoo, chat platforms, Zoom, Calendly, NetSuite)"
category: prevention
severity: critical
applies_to:
  - "when wiring a SaaS API key or OAuth token into code"
  - "when reviewing a SaaS connector / webhook / SCIM bridge"
  - "when triaging suspicious SaaS admin activity"
  - "when authoring infrastructure that proxies SaaS traffic"
  - "when answering a SaaS-related security question"
languages: ["*"]
token_budget:
  minimal: 1800
  compact: 2500
  full: 3600
rules_path: "rules/"
related_skills: ["secret-detection", "iam-best-practices", "auth-security", "supply-chain-security"]
last_updated: "2026-06-20"
sources:
  - "Google Workspace Admin SDK security guidance"
  - "Atlassian Cloud Security Best Practices"
  - "Salesforce Security Implementation Guide"
  - "HubSpot Private App authentication docs"
  - "Slack OAuth & token type reference"
  - "Microsoft Teams app permission model"
  - "Zoom App Marketplace security review"
  - "BambooHR API & Single Sign-On hardening"
  - "Workday Integration System Security framework"
  - "NetSuite Token-Based Authentication (TBA) guide"
  - "Notion API integration token model"
  - "Lark/Feishu Open Platform security guidelines"
  - "Calendly Webhook V2 signature spec"
  - "CWE-798: Use of Hard-coded Credentials"
  - "CWE-284: Improper Access Control"
  - "CWE-1392: Use of Default Credentials"
---

# SaaS Application Security

## Rules (for AI agents)

### ALWAYS
- Store SaaS API tokens, OAuth secrets, webhook signing keys, and
  service-account JSON files in a **secrets manager** (Vault, AWS
  Secrets Manager, GCP Secret Manager, Doppler, 1Password Connect) —
  never inline, never `os.Setenv`-from-source, never in CI repo
  variables (only `secrets.*`).
- For **OAuth-based** SaaS integrations (Google Workspace, Microsoft
  365, Slack, Atlassian Cloud, HubSpot, Zoom, Notion, Lark, Calendly,
  NetSuite OAuth 2.0, Salesforce Connected Apps): persist `refresh_token`
  encrypted-at-rest, refresh access tokens before expiry, and store the
  client secret in a server-only path (never in JS/mobile bundles).
- For **HMAC webhook callbacks** (Slack `X-Slack-Signature`, Calendly
  V2 `Calendly-Webhook-Signature`, HubSpot v3 `X-HubSpot-Signature-v3`,
  Stripe-style platforms, Zoom verification token, Teams outgoing
  webhook HMAC, Lark `X-Lark-Signature`, Notion verification token):
  validate the signature and the timestamp window (default 5 min) on
  every inbound request **before** parsing the body or trusting any
  field.
- Pin SaaS API base URLs to the vendor's production hostnames
  (`api.atlassian.com`, `api.hubapi.com`, `api.calendly.com`, `*.zoom.us`,
  `slack.com/api`, `graph.microsoft.com`, `api.bamboohr.com`,
  `wd*.myworkday.com`, `*.salesforce.com`/`*.force.com`,
  `api.notion.com`, `open.larksuite.com`/`open.feishu.cn`,
  `*.netsuite.com`). Reject responses from unexpected hostnames — this
  catches DNS-takeover and account-takeover proxy attempts.
- Treat **SCIM** and **directory-sync** endpoints as security-sensitive:
  require mutual TLS or signed JWT bearer, rate-limit, and log every
  user/group write to a tamper-evident sink.
- Use **least-privilege scopes** on every SaaS app you create. Salesforce
  Connected Apps: avoid `full`/`refresh_token` unless required. Slack
  bot tokens: list only the scopes you call. Google Workspace OAuth:
  request `.../auth/admin.directory.user.readonly` instead of
  `admin.directory.user` if you don't write. HubSpot Private Apps: tick
  only the scope checkboxes you actually call.
- Enforce **2-step verification (2SV / MFA)** on every SaaS admin
  console, **including** super-admin / org-owner / billing-owner
  accounts. Tie SSO to your IdP and disable password fallback for
  admins.
- Require **dedicated, non-shared service accounts** for system-to-system
  SaaS integrations. Service account names should encode purpose
  (`jira-ingestion-sa`, not `api-user-3`). Disable interactive login on
  these accounts where the platform allows.
- For Google Workspace specifically: rotate domain-wide delegation
  service-account keys ≤ 90 days, prefer Workload Identity Federation
  where supported, and audit `Admin SDK` calls in Admin Console >
  Reports.
- For Atlassian (Jira/Confluence) specifically: prefer **OAuth 2.0 (3LO)
  / Atlassian Connect** with `actAsAccountId`; only fall back to
  user-bound API tokens when scripting personal automation. Rotate the
  per-user API tokens ≤ 90 days.
- For NetSuite specifically: prefer **OAuth 2.0** or **TBA (Token-Based
  Authentication)** with a dedicated integration record; never use the
  user/password login flow for system integrations.
- For BambooHR / Workday / NetSuite (HRIS/ERP class): treat every bulk
  employee/PII export as a **DLP boundary** — log the request, the
  authenticated principal, the row count, and the destination. Alert on
  unusual volume.

### NEVER
- Hard-code a SaaS API token, OAuth client secret, webhook signing key,
  or service-account JSON in source, container images, mobile app
  binaries, or client-side JS. The vendor token formats this rule file
  detects (e.g. `xoxb-`, `xapp-`, `jira_pat_`, `pat-na`,
  `ya29.`, `1//`, `sk_live_`) are mass-scanned by attackers on public
  GitHub, npm, PyPI, and Docker Hub within minutes of push.
- Disable webhook signature verification "for testing." Every Slack /
  HubSpot / Zoom / Calendly / Teams / Lark / Notion compromise via
  spoofed webhook in the public record exploited an integration that
  shipped to prod with signature checks off.
- Issue a Google Workspace **super admin** OAuth scope (`https://www.googleapis.com/auth/admin`)
  to anything other than a tightly-controlled IT-owned automation. Most
  use cases need only the narrower `admin.directory.*.readonly`.
- Share a single **personal API token** across services for Jira,
  Confluence, BambooHR, Workday, NetSuite, or Notion. Person-bound
  tokens inherit the human's privileges and leak through that human's
  laptop / SaaS account.
- Configure a Slack / Teams / Lark / Google Chat **incoming webhook URL**
  that posts into a channel of higher trust than its consumers. If a
  CI bot can post into `#secops`, a CI compromise = direct phishing of
  secops. Use signed apps + per-channel posting permissions instead.
- Leave **link sharing** on Google Drive / Notion / Confluence /
  Atlassian Cloud / SharePoint at "Anyone with the link" for documents
  containing customer data, secrets, or non-public roadmaps. Default
  the org sharing policy to **domain-restricted**.
- Trust the **`From` / `email` field** of a Calendly / HubSpot / Zoom
  webhook payload as authoritative identity. The signature proves the
  *vendor* sent the payload; the body fields can still be attacker-
  supplied (spoofed invitee, attacker-set custom field). Look up the
  user by canonical ID server-side.
- Forward SaaS **OAuth refresh tokens** between environments
  (dev↔staging↔prod) — each environment must have its own connected
  app / OAuth client, otherwise prod credentials live in dev's
  blast-radius.
- Trust **Salesforce Apex / NetSuite SuiteScript / Workday Studio /
  Jira ScriptRunner** code installed by a third party without a
  security review. These run with elevated privileges and are a
  recurring vector for SaaS supply-chain incidents (e.g. the
  Salesforce-via-AppExchange ATO patterns documented by Salesforce
  Security 2024).

### KNOWN FALSE POSITIVES
- Vendor-provided **sandbox / example tokens** in official docs (e.g.
  Slack `xoxb-XXXXXXX-XXXXXXXX`, Stripe `sk_test_…`,
  Calendly `eyJ…example…`) — match the regexes but contain literal
  `EXAMPLE` / `XXX` / `test` markers in the surrounding context.
- `ghp_…` / `gho_…` in third-party SaaS docs explaining how to wire
  GitHub into them — these are GitHub tokens, not SaaS-platform
  tokens, and are covered by `secret-detection`.
- Public **service-account email** of a published Google Marketplace
  app (`*@gserviceaccount.com`) — the email is public; only the JSON
  key is sensitive.
- **OAuth client IDs** for public mobile / web SPAs — they are
  designed to be public. The matching **client secret** must still be
  private; signal only on the secret.

## Context (for humans)

SaaS is now the dominant data-egress vector. The 2023-2025 incident
record (Snowflake / OAuth-token theft, Okta / HAR-file leakage,
GitHub-to-Slack token replay, Salesforce-via-Atlassian movement,
calendar/scheduling phish via Calendly-style links) shows three
recurring failure modes:

1. **Token sprawl.** Personal-bound tokens and OAuth refresh tokens
   accumulate across vendors. Every one of them is a credential.
   Centralise them; expire them on cadence.
2. **Misconfigured sharing.** SaaS platforms default to convenience
   ("anyone with the link"). Customer data, deal pipelines, M&A docs,
   and internal IAM diagrams leak through these defaults more often
   than through code bugs.
3. **Admin-action blindspots.** Bulk exports, mass permission grants,
   API-key rotations, and SCIM user-write spikes are diagnostic of
   account-takeover or insider misuse — but only if you are watching.

This skill's per-platform JSON rule files give an AI reviewer:

- **Token formats** — regex patterns for detecting hard-coded SaaS
  secrets at PR time.
- **Misconfigurations** — concrete settings to assert (or refuse) when
  generating SaaS-integration code.
- **Admin red flags** — log query shapes that an SIEM / SOAR /
  detection rule should already be looking for.

The rule files are deliberately specific to each vendor so AI agents
do not generate "generic" SaaS detection logic that misses real
attacks. They are also small enough that the compiled
`SECURITY-SKILLS.md` distribution can carry them in the `full` tier
without blowing the token budget.


### Verify & lock (triaging a finding)

A scanner/review hit is a *candidate*, not a confirmed bug. Confirm it, fix it,
then lock it so it can't come back.

1. **Confirm it's real (probe).** Pick the probe that matches the class:
   *Cross-tenant IDOR* — authenticate as tenant A and request tenant B's resource id
   (real if you get B's data back = broken tenant isolation; FP if scoped to the
   caller's tenant). *Unverified webhook* — replay a forged Slack/HubSpot/Calendly
   payload with a bad/absent signature or a stale timestamp (real if accepted; FP if
   it's rejected before the body is parsed). *Over-broad OAuth/API-key scope* — diff
   the granted scopes against the calls the code actually makes (real if it holds
   `admin.directory.*` write / Salesforce `full` but only reads). *Trusted body
   identity* — see if the handler trusts a payload `email`/`From` field instead of the
   canonical server-side id. *Hard-coded token* — confirm the matched secret is live,
   not a docs `EXAMPLE`/`sk_test_` placeholder.
2. **Fix, then lock with a regression test** (unit *or* integration — dev's call):
   tenant A requesting tenant B's id → assert 403/404 and zero leaked rows, plus a
   same-tenant request that still succeeds; forged/stale-signature webhook → rejected,
   valid one → accepted; assert the integration requests only least-privilege scopes;
   assert identity is resolved by canonical id, not body field; and that the secret
   loads from the secrets manager, not source. Commit it so the guard can't be silently
   dropped, and log the privileged action (bulk export, SCIM write) to an audit sink.

## References

- `rules/google_workspace.json` — GWS OAuth, service-account, Admin SDK
- `rules/google_chat.json` — Google Chat webhooks and bot tokens
- `rules/atlassian.json` — Jira & Confluence Cloud, OAuth 2.0 / API tokens
- `rules/notion.json` — Notion integration tokens, workspace sharing
- `rules/hubspot.json` — HubSpot Private Apps, OAuth, webhook v3 HMAC
- `rules/salesforce.json` — Connected Apps, session tokens, Apex/Flow
- `rules/bamboohr.json` — BambooHR API key, SSO, employee export
- `rules/workday.json` — Workday ISU, OAuth, report-as-a-service
- `rules/odoo.json` — Odoo XML-RPC / JSON-RPC, master password
- `rules/microsoft_teams.json` — Teams app + bot creds, outgoing webhook HMAC
- `rules/slack.json` — Slack bot/user/app/config tokens, webhook URLs
- `rules/larksuite.json` — Lark/Feishu tenant access tokens, webhook
- `rules/zoom.json` — Zoom JWT (legacy), Server-to-Server OAuth, webhook
- `rules/calendly.json` — Calendly PAT, OAuth, V2 webhook signature
- `rules/netsuite.json` — NetSuite TBA, OAuth 2.0, SuiteScript red flags
- CWE-798, CWE-284, CWE-1392
- OWASP API Security Top 10 (2023) — API2 (auth), API8 (security misconfig)
