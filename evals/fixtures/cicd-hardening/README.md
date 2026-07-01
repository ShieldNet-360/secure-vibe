# `evals/fixtures/cicd-hardening`

GitHub Actions workflow files with known anti-patterns. The P3 MCP
tool `scan_github_actions` is run against each file and the SARIF
output is compared to `expected.json`.

Anti-patterns covered, with citation:

| Fixture | Anti-pattern | Rules expected to fire |
| --- | --- | --- |
| `unpinned-action.yml` | `uses: actions/checkout@v4` (tag, not SHA) | `gha-default-permissions-read`, `gha-pin-actions-by-sha` |
| `pull-request-target-checkout.yml` | `pull_request_target` + checkout of PR head | `gha-default-permissions-read`, `gha-pr-target-no-untrusted-checkout` |
| `curl-pipe-sh.yml` | `curl … \| sh` in a `run:` step | `gha-default-permissions-read`, `gha-no-curl-pipe-bash` |
| `expression-injection.yml` | `${{ github.event.* }}` interpolated into `run:` | `gha-default-permissions-read`, `gha-no-untrusted-script-injection` |
| `stored-credentials.yml` | `secrets.AWS_SECRET_ACCESS_KEY` instead of OIDC | `gha-default-permissions-read`, `gha-oidc-cloud-credentials` |
| `multiple-issues.yml` | four anti-patterns stacked in one workflow | four findings (one per concept, no double-fire): `gha-default-permissions-read`, `gha-pin-actions-by-sha`, `gha-no-curl-pipe-bash`, `gha-no-untrusted-script-injection` |
| `pinned-clean.yml` | control (every rule must clear) | zero findings |
| `self-hosted-runner.yml` | baseline for future self-hosted-runner rule | zero findings (no rule yet) |

Every rule above is defined in Go (`internal/tools/library_scanners.go`):
the pure-regex checks in `gitHubActionsChecks` and the structure-aware
checks (`gha-pin-actions-by-sha`, `gha-pr-target-no-untrusted-checkout`,
`gha-no-untrusted-script-injection`) in `appendAstWorkflowFindings`. The
contract traces to the `<!-- pattern: { check } -->` markers in
`skills/cicd-security/SKILL.md` — there is no checklist YAML.

Layout: one `.yml` per fixture + an `expected.json` per file.
