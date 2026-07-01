# Contributing to SecureVibe

Thanks for your interest in contributing to **SecureVibe**. This document
describes the kinds of changes we welcome, the local workflow, and the rules
that keep the project's data and tooling trustworthy.

SecureVibe is released under the [MIT license](./LICENSE) and maintained by
[ShieldNet360](https://www.shieldnet360.com).

> [!IMPORTANT]
> **AI-assisted contributions:** this project does *not* accept pull
> requests that are fully or predominantly AI-generated. AI tools may
> be used solely in an assistive capacity, and all AI usage must be
> disclosed in the PR description. Please read
> [AGENTS.md](./AGENTS.md) before submitting any PR.

## Where to contribute

| Kind of change | Where it lives | Notes |
|----------------|----------------|-------|
| **New skill** | `skills/<id>/SKILL.md` plus rule files in `skills/<id>/rules/` or `checklists/` | Use [`skills/secret-detection/`](./skills/secret-detection) as the reference implementation. Add a `tests/corpus.json` if the rules are regex-driven. |
| **Vulnerability entry** | `vulnerabilities/supply-chain/malicious-packages/<ecosystem>.json`, `typosquat-db/known_typosquats.json`, `cve/code-relevant/cve_patterns.json` | Every entry needs at least one external reference (CVE ID, vendor advisory URL, or a reputable disclosure write-up). No anonymous "trust me" entries. |
| **secret pattern** | `skills/secret-detection/checklists/secret_detection.yaml` (`checks:` block, `type: secret_pattern`) and matching test in `skills/secret-detection/tests/corpus.json` | Provide a regex, severity, hotwords, and at least one valid + one invalid (false-positive) test fixture. PR-B1 unified the legacy `rules/dlp_patterns.json` + `rules/dlp_exclusions.json` into this single YAML; the i18n locale sidecar was dropped. |
| **False-positive fix** | The relevant `*_exclusions.json` or a skill-specific exclusion file | These PRs are merged quickly. |
| **Detection rule** | `rules/{cloud,endpoint,container,saas}/<platform>/<name>.yml` | Follow the Sigma format. Include `schema_version: "1.0"` so the validator picks it up. |
| **Compliance mapping** | `skills/compliance-awareness/frameworks/{cwe,owasp}_mapping.yaml` or `compliance/*_mapping.yaml` | Every skill ID must be present in both `cwe_mapping.yaml` and `owasp_mapping.yaml`. |
| **CLI / SDK / compiler code** | `cmd/secure-vibe/`, `cmd/secure-vibe/`, `internal/`, `sdk/{go,python,typescript}/` | Add or update Go tests (`*_test.go`) for behaviour changes. |
| **Docs** | `*.md` files at the repo root, in `docs/`, in `skills/*/`, or in `packaging/*/` | Prose changes are welcome — keep the brand SecureVibe and preserve technical identifiers (`secure-vibe`, the Go module path). |

## Local setup

```bash
# Clone
git clone https://github.com/shieldnet-360/secure-vibe.git
cd secure-vibe

# Build the CLI (Go 1.22+)
go build -trimpath -ldflags "-s -w" -o secure-vibe ./cmd/secure-vibe
go build -trimpath -ldflags "-s -w" -o secure-vibe ./cmd/secure-vibe

# Validate every skill + rule file
./secure-vibe dev validate

# Run the full Go test suite
go test ./...

# Rebuild dist/ files (every PR must commit the regenerated files)
./secure-vibe dev regenerate
```

## PR checklist

Before opening a pull request, please run these in order:

1. `./secure-vibe dev validate` — passes on every committed `SKILL.md`, rule file,
   and checklist.
2. `go test ./...` — every package green, no skipped tests.
3. `./secure-vibe dev regenerate` — `dist/` re-rendered with no uncommitted drift.
4. `./secure-vibe dev derive-checklists <skill-id>` for any skill whose `SKILL.md`
   you changed and whose bullets carry pattern markers (see "Pattern markers"
   below). CI re-runs the command with `--check` and rejects drift.
5. `./secure-vibe dev manifest compute --path . --write` — manifest checksums are
   in sync. CI re-runs `./secure-vibe dev manifest verify --checksums-only` and
   rejects drift.
6. `last_updated` bumped on any modified `SKILL.md`. CI enforces this.
7. New / updated entries include at least one external reference URL.
8. `go run honnef.co/go/tools/cmd/staticcheck@latest ./...` — clean. The tree is
   kept staticcheck-clean; run it under a recent Go toolchain (the latest
   release needs Go newer than the CI build floor, so this is a local check
   rather than a CI gate).
9. Commit messages follow the convention used in `git log` (no force-pushing to
   `main`; do not amend other contributors' commits).

CI runs the same checks plus `go vet`, `gofmt`, the markdown link checker, and
the token-budget enforcer. (`staticcheck` is a recommended local check — see
step 8 — not a CI gate, to avoid pinning it across the CI/dev Go-version gap.)

## Pattern markers (linking SKILL.md to `checklists/*.yaml`)

Bullets in a `SKILL.md` ALWAYS / NEVER / KNOWN FALSE POSITIVES section may
declare themselves as a structured rule by appending an HTML comment marker:

```markdown
### NEVER
- Use end-of-life base images. As of mid-2026 this includes ...
  <!-- pattern: { id: dkr-eol-base-image, severity: critical, cwe: 1104, framework: dockerfile_hardening } -->
```

`secure-vibe dev derive-checklists <skill-id>` reads every tagged bullet and
**merges** it into the matching `checklists/<framework>.yaml`. Existing
YAML entries whose `id` is not in a marker are preserved verbatim — the
human maintainer still owns those rows. CI runs the same command with
`--check` and fails when SKILL.md and YAML are out of sync, so the two
files stay in lock-step without any manual diffing.

Marker payload (YAML flow style):

| field       | required? | meaning |
|-------------|-----------|---------|
| `id`        | yes       | kebab-case identifier; unique within the skill |
| `severity`  | no        | `critical` / `high` / `medium` / `low` / `info`. Defaults: ALWAYS → `high`, NEVER → `critical`, KFP → `info` |
| `cwe`       | no        | CWE identifier (integer) |
| `framework` | no\*      | YAML file basename under `checklists/`. Required when the skill has more than one checklist file; inferred from the single file otherwise |

Bullets without a marker are ignored — they remain prose-only knowledge that
the AI assistant consults at code-generation time, deliberately not promoted
to an automated rule.

## External tools (`external_tools` frontmatter)

A skill can recommend industry-standard external CLIs — tools the agent
should run via the shell for deeper coverage than the built-in scanners
(e.g. `gitleaks` for whole-repo / git-history secret scanning, `hadolint`
for Dockerfile linting). Declare them in the SKILL.md frontmatter:

```yaml
external_tools:
  - name: gitleaks          # also the binary looked up on PATH
    purpose: "secrets, whole-repo + git history"
    command: "gitleaks dir | gitleaks git"
```

The skill frontmatter is the single source of truth. Two consumers read it:

1. `secure-vibe dev regenerate` lifts a one-line nudge into the generated
   pointer files (CLAUDE.md, …) so the agent learns the tools exist every
   session without fetching the skill body.
2. The `list_external_tools` MCP tool reports each declared tool plus
   whether its binary resolves on the host's PATH (`installed: true/false`).

SecureVibe only *discovers* these tools — it never executes them. The agent
runs the chosen tool itself via the shell. There is no marker schema, no
registry, and no in-process execution to maintain.

## Token budgets

Every `SKILL.md` declares `token_budget: { minimal, compact, full }`. The
`compiler` rebuilds each tier and fails the build if the rendered output
exceeds the declared budget. When you grow a skill's prose:

- Keep `minimal` strictly within 500 tokens (bullets only — ALWAYS / NEVER /
  KFP).
- Keep `compact` within 2000 tokens (full Rules + KFP + References, no
  examples or rationale).
- `full` may grow to 5000 tokens; use it for examples, rationale, and CWE
  links.

If you find yourself bumping the budget, consider splitting the skill rather
than enlarging the existing tier.

## Style

- **Brand:** the project is **SecureVibe**. The Go module path remains
  `github.com/shieldnet-360/secure-vibe` and the CLI binary remains
  `secure-vibe` — these are stable technical identifiers. Use the brand name
  in prose, the technical identifiers in code/import paths.
- **Voice:** direct, neutral, factual. No marketing language in `SKILL.md` or
  vulnerability data. Authoritative sources are linked, not paraphrased.
- **No PII:** no researcher names, no reporter contact info, no internal
  ticket IDs — public advisory references only.

## Reporting a security issue

Please **do not** open a public issue for a security vulnerability in
SecureVibe itself. Follow the process in [SECURITY.md](./SECURITY.md).

## Code of conduct

Contributors are expected to interact professionally and respectfully. We
follow the [Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
Report unacceptable behaviour to the maintainers listed in
[SECURITY.md](./SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the
MIT License — the same license that covers the rest of the project.
