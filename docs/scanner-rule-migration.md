# Scanner rule migration — single source of truth in SKILL.md

**Status: DONE for dockerfile + GitHub Actions** (the two config/IaC
scanners). The end design differs from the YAML-centric plan sketched
below: rather than move rules *into* a checklist YAML, the scanner
contract now lives in **SKILL.md `<!-- pattern: { id, check } -->`
markers** (check = `deterministic` → a Go check enforces it, or `llm` →
the agent reasons it), the rule logic stays in Go, and the
`dockerfile_hardening.yaml` / `github_actions_hardening.yaml` checklists
were **deleted**. Guarded by `TestDockerfileRuleIDsTraceToSkill` +
`TestGitHubActionsRuleIDsTraceToSkill`; surfaced by `secure-vibe
coverage`. The GHA AST/regex double-fire was removed (the redundant
regex versions dropped; the AST checks renamed to the canonical ids per
the table below). Only `secret_detection.yaml` keeps a runtime rule
YAML. The YAML-centric notes below are retained as historical context.

## Goal

Every machine-detectable rule the gate emits should live in **one place**: the
skill's checklist YAML (`skills/<id>/checklists/*.yaml`), which the scanner reads
at runtime. The result:

- **No drift.** The scanner can't check something the skill doesn't document,
  and a finding's `rule_id` always resolves to a skill entry (so `explain_finding`
  and audits join cleanly).
- **No Go release to tune a rule.** The security review edits the YAML.
- **SKILL.md stays prose.** Human-readable guidance the model loads at
  generation time; the regexes live in the YAML, not in the prose.

The precedent already exists: **`scan_secrets` is fully YAML-driven**
(`secret_detection.yaml`, hand-curated `type: secret_pattern` entries with a
`pattern:` regex — `loadSecretRules` reads them). This plan brings the other two
file scanners toward that shape, as far as each can go.

## Current state (per scanner)

| Scanner | Rule source at runtime | Drift |
|---|---|---|
| `scan_secrets` | reads `secret_detection.yaml` (regex in YAML) | none — the model |
| `scan_github_actions` | reads `github_actions_hardening.yaml` regexes **+** Go AST checks (`gha-ast-*`) | YAML regex + AST **double-fire**; `gha-ast-*` ids not in the YAML |
| `scan_dockerfile` | **hardcoded Go slice** `dockerfileChecks`; the derived YAML is not read | IDs reconciled + guarded (this PR); rules still duplicated in Go |

## Key constraint: not everything is a regex

Some checks need stateful logic a single YAML regex can't express. These **stay
in Go** by design; the YAML still documents them (prose entry, no `pattern:`),
and the guard test ties the Go id to that entry.

**Dockerfile classification:**

- **Pure regex → move to YAML** (`type: dockerfile_check`, with `pattern:`):
  `dkr-explicit-latest-tag`, `dkr-no-curl-pipe-sh`, `dkr-no-secrets-in-env`,
  `dkr-no-add-remote`, `dkr-apt-version-pin`.
- **Stateful → stay in Go** (YAML keeps a prose entry only):
  `dkr-pinned-base-digest` (must reason "no tag **and** no digest" across the
  final `FROM`), `dkr-non-root-user` (must find the **final** `USER`).

## The delicate one: GitHub Actions

`scan_github_actions` already reads YAML regexes, **and** runs three Go AST
checks that overlap the same concepts at higher precision:

| Go AST id | YAML id (same concept, has a firing `pattern:`) |
|---|---|
| `gha-ast-unpinned-action` | `gha-pin-actions-by-sha` |
| `gha-ast-pwn-request` | `gha-pr-target-no-untrusted-checkout` |
| `gha-ast-expression-injection` | `gha-no-untrusted-script-injection` |

Observed today: a `pull_request_target` + checkout workflow reports **both**
`gha-pr-target-no-untrusted-checkout` (YAML regex) **and** `gha-ast-pwn-request`
(AST) — the same issue twice, with two ids. And the AST caught an `@main`
unpinned action the YAML regex missed (AST ⊇ regex there).

**Proposed fix (coverage-sensitive — verify before shipping):**

1. For each of the three concepts, **drop the `pattern:`** from the YAML entry
   (it becomes a prose entry; the precise AST is the sole detector). The gha
   YAML is hand-curated (no `generated_from:`; derive-checklists reports "0
   tagged bullets"), so this is a direct edit — safe from clobbering.
2. **Rename** the Go AST id to the YAML id (`gha-ast-pwn-request` →
   `gha-pr-target-no-untrusted-checkout`, etc.) → one finding per issue, with a
   traceable id.
3. Before/after, run a corpus of real-and-clean workflows to confirm the AST
   covers **≥** what the regex did (no detection regression). This is the gate
   on the change.
4. Make the three AST ids an enumerable `var` so the guard test can cover gha
   the way it covers dockerfile.

## Target schema (machine-rule entry in the checklist YAML)

Mirror `secret_detection.yaml`. Hand-curated, coexists with derived prose:

```yaml
checks:                       # or `patterns:` for dockerfile
  - id: dkr-no-curl-pipe-sh
    type: dockerfile_check    # loader keys off type; derived prose entries ignored
    severity: high
    title: RUN pipes a remote script straight into a shell
    pattern: '(?im)^\s*RUN\b.*\bcurl\b.*\|\s*(?:ba)?sh\b'
    fix: Download, verify a known SHA-256, then execute.
```

**derive-checklists coexistence:** it only touches bullets carrying an HTML
marker and writes prose entries; hand-added entries with `type:`/`pattern:` are
preserved (exactly how `secret_detection.yaml` keeps its secret-detection patterns alongside
derive output). The `generated_from` files (e.g. `dockerfile_hardening.yaml`)
already report "N from skill, M preserved" — the preserved set is where the
machine rules live.

## Migration steps (incremental, one scanner at a time)

1. **Schema + loader (1 PR):** add a generic `type: <scanner>_check` loader in
   `internal/tools` returning `{id, severity, title, pattern, require, fix}`,
   reusing the gha pattern. Unit-test the loader.
2. **Dockerfile (1 PR):** add the 5 pure-regex rules as `dockerfile_check`
   entries (with the regexes currently in `dockerfileChecks`); have
   `ScanDockerfile` load them and keep only the 2 stateful checks in Go. Corpus
   test: identical findings before/after on the container-security corpus.
3. **GitHub Actions (1 PR):** the dedup above (drop 3 YAML patterns, rename 3
   AST ids, enumerable id list, extend the guard). Corpus test gates it.
4. **Guard everywhere:** extend `TestDockerfileRuleIDsTraceToSkill` into a
   table over all file scanners (dockerfile, gha) asserting emitted ids ⊆ skill
   YAML ids. secret_detection already satisfies this.

## Risks & mitigations

- **Coverage regression** when removing a YAML regex or moving logic →
  every step is gated by a before/after corpus diff (`secure-vibe dev test` +
  the per-skill corpora). No step ships on "looks right".
- **Stateful checks can't be data-driven** → accepted; they stay in Go with a
  documenting prose entry + the guard. The win is "most rules are data + every
  finding is traceable", not "100% data-driven".
- **derive-checklists clobbering hand rules** → covered by the `type:` /
  preserved-set mechanism already proven in `secret_detection.yaml`.
