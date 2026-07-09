# Contribute a finding (the LEARN loop)

When you discover a bad package — one that beacons out in CI, exfiltrates
environment variables in a `postinstall`, or is an obvious typosquat the
curated database doesn't know yet — you shouldn't have to wait for anyone to
review it before your own builds are protected. `secure-vibe contribute`
records the finding into a **local overlay** so the gate blocks it on the very
next run. The rule never leaves your machine unless you explicitly choose to
share it.

This is the "left of the cursor, and now left of the *database*" half of
SecureVibe: prevention that you can extend the moment you learn something,
without a round trip.

## The model

```mermaid
flowchart LR
    A[You spot a bad package] --> B[contribute add]
    B --> C[.secure-vibe/overlay.json]
    C --> D[gate blocks immediately]
    C -. commit to repo .-> E[whole team protected]
    B -. opt-in .-> F[contribute submit]
    F --> G[signed candidate file]
    G --> H[reviewer runs contribute verify]
    H --> I[promoted into the central, centrally-signed DB]
    I --> J[signed-delta update reaches everyone]
```

- **Private by default.** `contribute add` writes only to
  `.secure-vibe/overlay.json` in your project. Nothing is uploaded.
- **Team-wide with one commit.** Commit that file and every teammate (and your
  CI) enforces the same block — herd immunity within a repo.
- **Upstream only on `submit`.** The *only* artifact that ever leaves the
  machine is the candidate file you produce with `contribute submit`, and only
  when you run it. Sign it so a reviewer can verify provenance before promoting
  a rule into the canonical database.
- **Canon stays central.** Candidates are untrusted input. A rule becomes
  canonical only after review and a signature from the central release key —
  the same key that signs every `update`. You crowdsource *candidates*, never
  *canon*.

## Block a package locally

```bash
# Block a package you saw misbehave — everywhere, immediately:
secure-vibe contribute add -p evil-pkg -e npm \
  --reason "exfiltrates AWS creds in a postinstall script"

# The next gate run fails on it:
secure-vibe audit package.json --fail-on high   # exit 1
```

By default the block applies to **all versions** at **high** severity (so it
fails the default gate floor). Narrow it when you know more:

```bash
secure-vibe contribute add -p left-pad -e npm \
  --versions 1.0.0,1.1.0 --severity critical \
  --references https://example.com/advisory
```

Manage the overlay:

```bash
secure-vibe contribute list                 # show every local rule
secure-vibe contribute remove -p evil-pkg -e npm
```

Findings sourced from the overlay are labelled with confidence **high** and
`source: local-overlay`, so they are honestly distinguished from
centrally-reviewed canon in every report.

## Sign and share a candidate

Signing needs an Ed25519 key. You don't need `openssl` — generate one:

```bash
secure-vibe contribute keygen --out ~/.secure-vibe-contrib.pem
# Wrote private key (0600) + public key; prints the Key ID.
```

Then sign as you record, and export a portable candidate:

```bash
secure-vibe contribute add -p evil-pkg -e npm \
  --reason "..." --key ~/.secure-vibe-contrib.pem

secure-vibe contribute submit \
  --key ~/.secure-vibe-contrib.pem --out candidate.json
```

`candidate.json` carries each rule, a per-rule signature, and the embedded
public key. A reviewer (or the central pipeline) verifies it before promoting
anything:

```bash
secure-vibe contribute verify candidate.json
#   ✓ evil-pkg (npm): signature valid
#   All 1 rule(s) verified against key secure-vibe-contrib-...
```

The signature binds the package coordinates, severity, and description, so any
tampering with the candidate fails verification.

## Adopt a candidate someone shared with you

The receiving end of the loop: merge a candidate into your own overlay so your
gate enforces it. A signed candidate must verify before any rule is adopted; an
unsigned one is refused unless you opt in, so provenance is the default.

```bash
secure-vibe contribute import candidate.json
#   Imported 1 rule(s) (1 new, 0 updated, verified, key secure-vibe-contrib-…)

# An unsigned candidate is refused unless you explicitly accept the risk:
secure-vibe contribute import candidate.json --allow-unsigned
```

That is the full peer-to-peer path — `submit` on one machine, `verify` to
review, `import` to adopt — letting a finding travel from one developer's gate
to another's without waiting on the central pipeline.

## Propose a skill fix (the knowledge LEARN loop)

The overlay above teaches SecureVibe about a bad *artifact*. When the gap is
*knowledge* instead — a skill is missing a fact, or gives guidance that turned
out to be wrong — your assistant records an **inert local proposal** through the
`propose_skill_update` MCP tool. Nothing is applied automatically: the proposal
just sits in a queue on your machine. A human reviews the queue with

```bash
secure-vibe contribute skill
```

and, if the fix is sound, folds it into the skill and **re-signs** it. Same
discipline as package canon — crowdsource the proposal, keep the signing central.

## What is free, and what is not

The personal and candidate halves above are fully open source — a single team
gets a complete, self-contained workflow with no paywall, ever, on a security
fix. The central verification pipeline (sandbox auto-reproduction, OSV
cross-corroboration, dedup, and signing candidates into canon) and fleet-scale
features (private registries, org policy, SLAs) are where SecureVibe Cloud
begins. The boundary is deliberate: crowdsource candidates, centralize trust.
