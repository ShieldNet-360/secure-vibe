# Evaluator guide

If you just found SecureVibe and want to understand it and prove it works in about 5 minutes, start here.

## What SecureVibe is in 60 seconds

SecureVibe is **prevention-first security for AI-written code** — it works "left of the cursor." Instead of waiting to scan code after an AI assistant has already written something insecure, SecureVibe feeds your AI coding assistant signed security **skills** so it writes secure code at *generation time*, then backs that up with deterministic scanners and a CI `gate` that blocks insecure diffs.

The skills are the product; the scanners are the backstop.

The lifecycle has four stages:

| Stage | What it does | How |
|-------|--------------|-----|
| **PREVENT** | Stop insecure code from being written at all | 30 signed security skills fed to 8 AI assistants at generation time |
| **DETECT** | Catch known issues that slip through | 4 deterministic scanners (secrets, dependencies, Dockerfile, GitHub Actions) |
| **ENFORCE** | Block insecure diffs before merge | `gate` command, exits non-zero above a severity floor, emits SARIF |
| **LEARN** | Grow coverage from real findings | Signed contribution overlays shared you → team → org |

```mermaid
flowchart LR
    P[PREVENT<br/>signed skills at<br/>generation time] --> D[DETECT<br/>4 deterministic<br/>scanners]
    D --> E[ENFORCE<br/>gate blocks<br/>insecure diffs]
    E --> L[LEARN<br/>signed contribution<br/>overlays]
    L -.->|new patterns feed back| D
```

!!! note "Scope, stated plainly"
    Detection is **narrow by design** — 4 scanners, not a general-purpose SAST. SecureVibe catches *known* patterns (malicious/typosquat packages, secrets, Dockerfile and GitHub Actions misconfigurations) and deliberately does **not** try to find every novel or semantic bug. That trade-off is the point: deterministic, offline, zero-false-positive on exact matches.

It is a Go CLI (`secure-vibe`) plus an MCP server (`secure-vibe mcp`). MIT licensed, fully offline, no telemetry, no API key, Ed25519-signed releases.

## Prove it in 5 minutes

Three quick demos: catch a malicious dependency, catch a planted secret, then watch the LEARN loop teach the gate a brand-new package to block.

### 1. Install

```bash
# bundles the library data — turnkey; run on demand:
npx -y @shieldnet360/secure-vibe version
# …or install globally:
npm install -g @shieldnet360/secure-vibe
```

??? info "From source (Go)"
    ```bash
    go install github.com/shieldnet-360/secure-vibe/cmd/secure-vibe@latest
    # builds only the binary; point it at library data via --path / $SECURE_VIBE_LIBRARY_PATH
    ```

### 2. Catch a malicious / typosquat dependency

The dependency scanner checks against a curated malicious-package database of **3,623 web-cited entries across 10 ecosystems**. Exact-match lookups produce zero false positives — that is the data moat.

Create a `package.json` that references a known-bad package:

```json
{
  "name": "demo-app",
  "dependencies": {
    "event-stream": "3.3.6"
  }
}
```

Then scan its directory:

```bash
secure-vibe scan .
```

```text
Scanning dependencies in .
  package.json

[HIGH] malicious package: event-stream@3.3.6 (npm)
  reason: known supply-chain compromise (cited)
  ecosystem: npm

1 issue found (1 high)
```

### 3. Catch a planted secret

Drop a hard-coded credential into a file:

```bash
printf 'aws_secret_access_key = AKIAIOSFODNN7EXAMPLE\n' > config.env
secure-vibe scan config.env
```

```text
Scanning secrets in config.env

[HIGH] AWS access key id detected
  file: config.env:1
  pattern: aws-access-key-id

1 issue found (1 high)
```

The secret scanner ships **83 secret-detection patterns**.

!!! tip "Tested edge"
    On SecureVibe's own tuned corpus, the secret scanner measured **100% precision / 100% recall** versus gitleaks at **92.4% / 65.9%** (76.9 F1) — **on the shapes we tested**. The honest signal there is gitleaks' *recall* gap on those shapes, not a universal claim that SecureVibe beats gitleaks everywhere.

### 4. The LEARN loop — teach the gate a new package

Suppose you discover a malicious package that isn't in the database yet. Add it to a signed local overlay, and the gate blocks it on the very next run.

```bash
# add evil-pkg (npm) to a signed local overlay (.secure-vibe/overlay.json)
secure-vibe contribute add -p evil-pkg -e npm
```

```text
Added evil-pkg (npm) to .secure-vibe/overlay.json
Overlay signed.
```

Now reference `evil-pkg` in a `package.json` and rescan — it is flagged where it was clean a moment ago:

```bash
secure-vibe scan .
```

```text
[HIGH] malicious package: evil-pkg (npm)
  reason: local overlay entry
  ecosystem: npm

1 issue found (1 high)
```

That's the flywheel. Overlays scope outward without ever leaving your control:

| Scope | Mechanism |
|-------|-----------|
| **You** | `.secure-vibe/overlay.json` (signed, local) |
| **Team** | Commit the overlay file — git is the fan-out |
| **Org** | `$SECURE_VIBE_OVERLAY` env var with a path-list |

To share peer-to-peer, run `secure-vibe contribute submit --sign`; a maintainer runs `contribute verify` then `contribute import`. Import is signature-gated (`--allow-unsigned` is an explicit opt-in). Generate keys with `contribute keygen`.

!!! example "Enforce it in CI"
    The same data drives the gate, which auto-picks the right scanner per file:
    ```bash
    secure-vibe gate . --severity-floor high --sarif results.sarif
    ```
    It exits non-zero above the severity floor and emits SARIF for GitHub Code Scanning.

## When to use it / when NOT to

!!! success "Good fit"
    - You use an AI coding assistant (Claude Code, Cursor, Copilot, Codex, Windsurf, Cline/OpenCode, Antigravity, or Devin) and want it to write more secure code from the start.
    - You want a deterministic, offline, zero-false-positive check for **known** malicious/typosquat dependencies, leaked secrets, and Dockerfile / GitHub Actions misconfigurations.
    - You want a CI gate that blocks those specific issue classes and emits SARIF, with no cloud dependency and no API key.
    - You want to grow detection coverage from your own findings via signed overlays.

!!! warning "Not a fit (be honest with yourself)"
    - **Not a general SAST.** Detection is narrow by design — 4 scanners, not comprehensive coverage. It will not replace a full static-analysis tool.
    - **Known patterns only.** The keyless tool catches known patterns and *misses* novel and semantic bugs. That's the accepted trade-off, not a gap to be embarrassed about.
    - **No production users yet.** SecureVibe is brand new — there is no track record of production deployments to point to. Evaluate it on its mechanics, not on social proof.
    - The gitleaks comparison above is **"on the shapes we tested,"** not a universal benchmark. Run it against your own corpus before drawing conclusions.

The honest edge is the *generation-time* lane (skills that incumbents can't structurally occupy) plus exact-match dependency lookups that are zero-false-positive by construction — not a claim of catching everything.

## Where to go next

- [Developer guide](developer.md) — wire SecureVibe into your editor and daily workflow.
- [DevOps guide](devops.md) — run the gate in CI and emit SARIF.
- [Security guide](security.md) — the trust model, signing, and self-update verification.
- [Contributor guide](contributor.md) — the LEARN loop, overlays, and signature-gated sharing in depth.
- [Why SecureVibe](../concepts/why.md) — the prevention-first thesis and the moat.
