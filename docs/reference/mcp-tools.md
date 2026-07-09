# MCP tools reference

The `secure-vibe mcp` server exposes SecureVibe's security data and scanners to an AI coding assistant over the Model Context Protocol (MCP), so the model can check dependencies, scan for secrets, and ground its answers in curated skills *while it writes code*.

`secure-vibe mcp` speaks JSON-RPC 2.0 over **stdio** (one message per line). It is fully offline, keyless, and never executes the external tools it tells you about — it only reads the local Skills Library data and runs the deterministic scanners.

## Running the server

The server reads from stdin and writes to stdout, so you normally let your MCP client launch it rather than running it by hand.

```bash
secure-vibe mcp
```

Add it to Claude Code with:

```bash
claude mcp add secure-vibe -- npx -y @shieldnet360/secure-vibe mcp
```

Once registered, the assistant sees the tools below on `tools/list` and calls them through `tools/call`.

!!! note "Library root resolution"
    The server locates the Skills Library data, in order, via `--path <dir>`, then `$SECURE_VIBE_LIBRARY_PATH`, then the directory of the running binary. The `npx @shieldnet360/secure-vibe` package bundles the data, so no extra configuration is required.

### File-access safety

The file-reading tools (`scan_secrets`, `scan_dependencies`, `scan_github_actions`, `scan_dockerfile`, and `gate`) are sandboxed by an allow-list:

| Flag | Effect |
| --- | --- |
| *(none)* | Defaults to the **current working directory** as the only allowed root — fail-safe. |
| `--allowed-roots <dir1,dir2,...>` | Restrict file reads to exactly these absolute directories. |
| `--allow-any-path` | Accept any path the process can `stat` (local debugging only). Mutually exclusive with `--allowed-roots`. |
| `--vuln-source <local\|external\|hybrid>` | Where `lookup_vulnerability` / `check_dependency` read OSV advisories. `local` (default, no network), `external` (api.osv.dev only), or `hybrid`. |

!!! warning "Sensitive directories are always denied"
    Regardless of the allow-list, sensitive locations such as `~/.ssh`, `~/.aws`, `~/.gnupg`, and `/etc/shadow` are **always** refused, and files larger than 10 MiB are rejected.

## Tool catalogue

The server exposes 20 tools; `policy_check` is additionally accepted as a back-compat alias of `gate`.

| Tool | Purpose |
| --- | --- |
| `scan_dependencies` | Parse a lockfile/manifest and check every dependency against the malicious-package, typosquat, and CVE-pattern databases. |
| `check_dependency` | Check one package (and optional version) in one ecosystem before importing it. |
| `check_typosquat` | Check whether a package name is a known typosquat or a squatted target. |
| `lookup_vulnerability` | Look up a package in the supply-chain vulnerability database (malicious entries + typosquats). |
| `scan_secrets` | Scan inline text or a local file for secrets. |
| `check_secret_pattern` | Run the secret-detection rules against a string and return matches. |
| `scan_dockerfile` | Run a hardening pass over a Dockerfile. |
| `scan_github_actions` | Run the CI/CD hardening checklist over a GitHub Actions workflow. |
| `gate` | Auto-pick the right scanner for a file and return a CI-friendly pass/fail. |
| `audit` | Whole-tree audit: fan every scanner across a directory, then dedup, rank by severity, and triage likely fixtures. The DETECT layer above `gate`; deterministic, respects the allowed-roots sandbox. |
| `http_probe` | Send one crafted HTTP request to an operator-authorized target and read status/headers/body/timing — the dynamic-verify primitive. Scope-gated: dry-run unless the target is in scope. |
| `oob_listener` | Allocate an out-of-band callback URL + poll for blind hits (SSRF/XXE/blind command injection). |
| `map_compliance_control` | Map a skill / category / term to SOC 2, HIPAA, or PCI DSS controls. |
| `explain_finding` | Map a CWE/CVE/finding description to relevant skills and CVE patterns. |
| `get_skill` | Return a skill at a chosen token tier (minimal / compact / full). |
| `search_skills` | Search skills by substring across title, description, ID, and category. |
| `get_sigma_rule` | Return Sigma-format detection rules by ID or query. |
| `list_external_tools` | List recommended external CLIs and whether each is on `PATH`. |
| `version_status` | Report the data version, release timestamp, and signature/trust state. |
| `propose_skill_update` | Record an inert proposal that a skill is missing/wrong/outdated knowledge (the knowledge LEARN loop). Appends to a local, unsigned review log; never edits or signs a skill. Reviewed with `secure-vibe contribute skill`. |

## Dependency & supply-chain tools

These are the gen-time core: call them *before* an import or install lands, when the model is weakest and the cost of a bad dependency is highest.

### `scan_dependencies`

Parses a project lockfile or manifest and runs every dependency against the malicious-package database, the typosquat database, and the CVE-pattern list.

| Parameter | Required | Description |
| --- | --- | --- |
| `file_path` | yes | Absolute path to a lockfile on the host running the server. |
| `format` | no | `""`/`"json"` (native shape) or `"sarif"` (SARIF 2.1.0 log for CI / GitHub Advanced Security). |

Recognised inputs include `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `go.sum`, `Cargo.lock`, `pom.xml`, `gradle.lockfile` / `build.gradle.lockfile`, `packages.lock.json`, `*.csproj` / `*.fsproj` / `*.vbproj`, `Gemfile.lock`, `composer.lock`, `Package.resolved`, and `pubspec.lock`.

!!! tip "When to call it"
    After installing or before committing a lockfile change — to audit the whole dependency set in one pass.

### `check_dependency`

Checks a single package (and optional version) against the malicious-package, typosquat, and CVE-pattern data for **one** ecosystem. Version matching is semver-aware (handles `all`, `*`, `pre-X.Y.Z`, `>=X.Y.Z`, `<X.Y.Z`, and inclusive `X.Y.Z - A.B.C` ranges).

| Parameter | Required | Description |
| --- | --- | --- |
| `package` | yes | Package name. |
| `ecosystem` | yes | One of `npm`, `pypi`, `crates`, `go`, `rubygems`, `maven`, `nuget`, `github-actions`, `docker`. |
| `version` | no | Version pin. Empty matches all affected versions. |
| `format` | no | `""`/`"json"` or `"sarif"`. |

!!! tip "When to call it"
    Right before the model writes an `import`, `require`, or `pip install` line for a package it hasn't used in this project — the single highest-leverage gen-time check.

### `check_typosquat`

Checks a package name against the typosquat database, returning entries where the name appears as the **target** (a legitimate package being squatted) or as a **known typosquat**.

| Parameter | Required | Description |
| --- | --- | --- |
| `package` | yes | Package name to check. |
| `ecosystem` | no | Optional ecosystem filter. |

!!! tip "When to call it"
    To catch dependency-confusion / typosquat attempts before an install lands — e.g. when a name looks suspiciously close to a popular package.

### `lookup_vulnerability`

Looks up a package in the supply-chain vulnerability database, returning malicious-package entries and known typosquats that match the name.

| Parameter | Required | Description |
| --- | --- | --- |
| `package` | yes | Package name to look up. |
| `ecosystem` | no | Optional ecosystem; defaults to all ecosystems. |
| `version` | no | Optional version pin. Empty matches all affected versions. |

!!! note "Exact-match lookups are zero-false-positive"
    The curated malicious-package data is the moat: a hit is a known, web-cited bad package, not a heuristic guess.

## Secret-scanning tools

### `scan_secrets`

Scans text or a local file for secrets and returns structured matches with severity, location, score, entropy, and whether each match is a known false positive.

| Parameter | Required | Description |
| --- | --- | --- |
| `text` | one of | Inline text to scan. Mutually exclusive with `file_path`. |
| `file_path` | one of | Absolute path to a local file (subject to `--allowed-roots` and the sensitive-directory deny-list; files over 10 MiB rejected). |
| `format` | no | `""`/`"json"` or `"sarif"` (SARIF 2.1.0 log). |

!!! tip "When to call it"
    Before committing config or code the model just generated, to confirm it didn't bake in a credential.

### `check_secret_pattern`

Runs the secret-detection rules against a supplied string and returns matches with severity, name, and known-false-positive status. A lightweight, text-only variant of `scan_secrets` (no file access, no SARIF).

| Parameter | Required | Description |
| --- | --- | --- |
| `text` | yes | Text to scan for secrets. |

## Configuration-file scanners

These run narrow, deterministic hardening passes — by design they target known misconfiguration patterns, not arbitrary code.

### `scan_dockerfile`

Runs a hardening pass over a Dockerfile, detecting untagged or `:latest` base images, `USER root`, secrets baked into `ENV`/`ARG`, `ADD` from a remote URL, `curl | sh` install patterns, and unpinned `apt-get install` lines.

| Parameter | Required | Description |
| --- | --- | --- |
| `file_path` | yes | Absolute path to a Dockerfile. |
| `format` | no | `""`/`"json"` or `"sarif"`. |

### `scan_github_actions`

Runs the CI/CD hardening checklist over a `.github/workflows/*.yml` (or `.yaml`) file, detecting unpinned actions, missing `permissions:` defaults, `pull_request_target` checking out untrusted code, untrusted-input script injection, `curl | sh` patterns, and stored cloud credentials.

| Parameter | Required | Description |
| --- | --- | --- |
| `file_path` | yes | Absolute path to a workflow YAML file. |
| `format` | no | `""`/`"json"` or `"sarif"`. |

## The gate

### `gate`

Picks the right scanner for `file_path` and returns a CI-friendly pass/fail with a per-severity count. It dispatches to `scan_dependencies` for lockfiles, `scan_github_actions` for workflow files, and `scan_dockerfile` for Dockerfiles, falling back to `scan_secrets` for anything else.

| Parameter | Required | Description |
| --- | --- | --- |
| `file_path` | yes | Absolute path to the artifact to scan. |
| `severity_floor` | no | Findings at or above this severity fail the check. One of `critical`, `high`, `medium`, `low`, `info`. Default: `high`. |

The response includes `pass` and `exit_code` (`0` on pass, `1` on fail) so a CI wrapper can branch on it.

!!! note "`policy_check` alias"
    `gate` was formerly named `policy_check`; that name is still accepted as a back-compat alias and dispatches to the same logic.

### `audit`

Where `gate` checks one file, `audit` checks a whole tree: it fans every scanner across every file under `path`, then **deduplicates**, **ranks by severity**, and **triages likely fixtures** (test/example/sample paths are reported but demoted) into one result. It is the DETECT orchestration layer above `gate` — the multi-file coordination lives in the server, so any MCP client gets it without needing its own orchestration.

| Parameter | Required | Description |
| --- | --- | --- |
| `path` | yes | Directory to audit. Must be within the server's allowed roots. |
| `severity_floor` | no | Only collect findings at or above this severity. Default: `low`. |

The tool is **deterministic and offline** — the calling agent is the reasoning (and dynamic-verification) layer, so no LLM or attack-traffic lane is exposed here. It respects the [allowed-roots sandbox](#file-access-safety); a `path` outside the sandbox yields no findings.

## Compliance & finding tools

### `map_compliance_control`

Maps a skill ID, category, or free-text term to the SOC 2 / HIPAA / PCI DSS controls that cover it, grouped by framework, so the assistant can cite the right control alongside a fix.

| Parameter | Required | Description |
| --- | --- | --- |
| `skill_id` | one of | A Skills Library skill ID (e.g. `secret-detection`). Either `skill_id` or `query` is required. |
| `query` | one of | Free-text query matched case-insensitively against control title and description. |
| `framework` | no | Optional filter: `soc2`, `hipaa`, or `pci-dss`. |

### `explain_finding`

Maps a CWE ID, CVE ID, or free-text finding description to relevant skills and CVE-pattern entries — returning matching skills (id, title, category, severity, body excerpt) plus CVE rows that mention the query.

| Parameter | Required | Description |
| --- | --- | --- |
| `query` | yes | A CWE ID (e.g. `CWE-77`), a CVE ID (e.g. `CVE-2024-12345`), or a finding description. |

!!! tip "When to call it"
    To attach grounded remediation guidance to a finding surfaced by another SAST / SCA scanner.

## Skill & rule retrieval

### `get_skill`

Returns the requested tier of a skill, so the assistant can pull in only as much context as it needs.

| Parameter | Required | Description |
| --- | --- | --- |
| `skill_id` | yes | Skill ID, e.g. `secret-detection`. |
| `budget` | no | Token tier: `minimal`, `compact`, or `full`. Default: `compact`. |

Every result also carries a `feedback_hint`: a standing reminder that a skill is
curated but not infallible, so if the agent finds a rule wrong/missing/outdated —
while reading it or after a finding it produced fails verification — it records a
correction via [`propose_skill_update`](#propose_skill_update). This closes the
knowledge LEARN loop without a special prompt.

### `search_skills`

Searches the Skills Library by substring match against title, description, ID, and category, returning matching skill metadata.

| Parameter | Required | Description |
| --- | --- | --- |
| `query` | yes | Substring query. |

### `get_sigma_rule`

Returns one or more Sigma-format detection rules from the rules directory.

| Parameter | Required | Description |
| --- | --- | --- |
| `rule_id` | one of | Exact Sigma rule UUID. |
| `query` | one of | Substring search against title, id, and tags. |
| `category` | no | Optional filter: `cloud`, `container`, `endpoint`, or `saas`. |

## Discovery & trust

### `list_external_tools`

Lists the industry-standard external CLIs that SecureVibe skills recommend (from each skill's `external_tools` frontmatter), each marked with whether its binary is installed on the current host's `PATH`.

This is **discovery only** — the server never runs these tools. Use it to decide which external scanner to run (e.g. `gitleaks dir` for whole-repo / git-history secret scanning, `hadolint <file>` for Dockerfile linting), then run the chosen one yourself. The built-in MCP scanners remain the offline default. No parameters.

### `version_status`

Returns the Skills Library data version, release timestamp, signature status, and a summary of how many files the root manifest tracks. No parameters.

!!! tip "Call this first"
    Use `version_status` before relying on results from the other tools, so the assistant can disclose data freshness and trust state. (See the [trust model](../concepts/why.md) for how releases are Ed25519-signed.)

## Knowledge LEARN loop

### `propose_skill_update`

Record a proposal that a skill is **missing** a fact, states something **wrong**,
or has gone **outdated** — the feedback loop for knowledge, complementing the
vuln-data overlay (`contribute add`). Use it when you discovered better security
knowledge than the skill carries (a new bypass, a corrected control, a fresh
CVE/spec).

| Parameter | Required | Description |
|-----------|----------|-------------|
| `skill_id` | yes | The skill this is about (e.g. `xss-prevention`). Find it with `search_skills` / `get_skill`. |
| `kind` | yes | `missing` \| `wrong` \| `outdated`. |
| `claim` | yes | The new or corrected knowledge, stated plainly. |
| `evidence` | yes | Why the claim holds — a source, repro, CVE, or spec link. |
| `suggested_text` | no | Optional drop-in wording for the `SKILL.md`. |

It is **inert and safe**: it only appends to a local, unsigned review log
(`.secure-vibe/skill-proposals.jsonl`). It never edits the signed skill, signs
anything, or opens a PR — a human reviews it with `secure-vibe contribute skill`
and, if it holds up, edits the skill and re-signs. Re-recording the same claim is
idempotent. This human review + re-sign is the trust gate that keeps a
prompt-injectable model from mutating signed knowledge.

## Honest scope

The scanners behind these tools are **narrow by design** — four deterministic scanners (secrets, dependencies, Dockerfile, GitHub Actions), not a general SAST. They catch known patterns and exact-match known-bad packages with zero false positives on the data moat, but they miss novel or semantic bugs. That is the accepted trade-off: a fast, offline prevention layer that grounds an AI assistant at generation time, backed by a deterministic gate — not a replacement for human review or a claim to find every vulnerability.

## See also

- [Developer guide](../guides/developer.md) — wiring SecureVibe into your editor and workflow.
- [DevOps guide](../guides/devops.md) — `audit --fail-on` in CI with SARIF.
- [Quick start](../quickstart.md) — install and first audit.
