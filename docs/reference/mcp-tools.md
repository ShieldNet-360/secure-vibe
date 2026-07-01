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
claude mcp add secure-vibe -- npx -y @shieldnet360/secure-code-mcp
```

Once registered, the assistant sees the tools below on `tools/list` and calls them through `tools/call`.

!!! note "Library root resolution"
    The server locates the Skills Library data, in order, via `--path <dir>`, then `$SECURE_VIBE_LIBRARY_PATH`, then the directory of the running binary. The `npx @shieldnet360/secure-code-mcp` package bundles the data, so no extra configuration is required.

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

The server exposes 16 named tools, plus `policy_check` as a back-compat alias of `gate` (17 callable names in total).

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
| `verify_finding` | Actively confirm a finding against a live target by sending a probe and checking a deterministic oracle (the dynamic "verify" lane). Gated: dry-run unless an operator scope is configured. |
| `map_compliance_control` | Map a skill / category / term to SOC 2, HIPAA, or PCI DSS controls. |
| `explain_finding` | Map a CWE/CVE/finding description to relevant skills and CVE patterns. |
| `get_skill` | Return a skill at a chosen token tier (minimal / compact / full). |
| `search_skills` | Search skills by substring across title, description, ID, and category. |
| `get_sigma_rule` | Return Sigma-format detection rules by ID or query. |
| `list_external_tools` | List recommended external CLIs and whether each is on `PATH`. |
| `version_status` | Report the data version, release timestamp, and signature/trust state. |

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

## Active verification (the verify lane)

Static and LLM detection produce a *candidate*. The verify lane turns a candidate into a verdict — **confirmed** or **refuted** — by sending a real probe at a live target and checking a deterministic oracle (build payload → fire → oracle → result). It is the only tool that sends attack traffic, so it is gated by two safety rails described below.

### `verify_finding`

Actively verifies one finding against a live endpoint.

| Parameter | Required | Description |
| --- | --- | --- |
| `type` | yes | Vulnerability class: `ssrf`, `sqli`, `xss`, `redirect`, `path-traversal`, `command-injection`, `ssti`, `xxe`. |
| `target` | yes | URL of the endpoint to probe, e.g. `http://localhost:4000/research`. |
| `param` | yes | The parameter believed injectable, e.g. `url`. Ignored for `xxe` (which sends an XML body). |
| `method` | no | `GET` (default) or `POST`. |
| `query` | no | Other required params as an object, e.g. `{"symbol":"AAPL"}`. |

Each class has its own payload set and a deterministic oracle, so a generic error page or echo never confirms:

| `type` | Technique | Oracle (what confirms) |
| --- | --- | --- |
| `ssrf` | Out-of-band callback, else cloud-metadata URL | Listener hit with our nonce (blind), or an internal/metadata signature reflected |
| `sqli` | Time-based blind (`SLEEP`/`pg_sleep`/`WAITFOR`) | Injected latency ≥ threshold over baseline, re-confirmed |
| `xss` | Reflected marker that breaks out of attribute/text | Payload reflected **unescaped** (HTML-escaped ⇒ refuted) |
| `redirect` | Attacker URL + filter bypasses, no-follow client | `3xx` with a `Location` to the attacker host |
| `path-traversal` | Climb to `/etc/passwd` · `win.ini` (+ encoding bypasses) | A known system-file signature in the body (`root:…:0:0:`) |
| `command-injection` | Out-of-band `curl`, else time-based `sleep` | Listener hit (blind), or injected latency ≥ threshold, re-confirmed |
| `ssti` | Template arithmetic in each engine's delimiters | The product renders as a standalone number while the expression does not |
| `xxe` | XML body with an external entity → listener | Listener hit — the parser dereferenced the entity (blind, out-of-band) |

!!! danger "Two safety rails — the model never holds the trigger"
    - **RAIL 1 — no auto-fire.** With nothing configured, `verify_finding` runs **dry-run**: it builds the payload and returns the plan, sending *nothing*.
    - **RAIL 2 — scope gate.** Even configured, a probe only fires when the `target` matches the operator's allow-list. Out-of-scope ⇒ dry-run.

    The model chooses *which* finding to verify; it never sees or chooses the target scope or the credentials. Both come from an operator-controlled file outside the repo.

### Configuring scope (operator only)

Two environment variables, highest precedence first:

`SECURE_VIBE_VERIFY_SCOPE_FILE` — path to a JSON file **outside any scanned repo** (`chmod 600`) listing the targets a probe may fire at and, per target, the auth headers to send. The token lives here, on the operator's machine — never in the repo, never chosen by the model:

```json
{
  "targets": [
    { "match": "localhost:4000", "headers": { "Cookie": "connect.sid=..." } },
    { "match": "*.staging.myco.com", "headers": { "Authorization": "Bearer ..." } }
  ]
}
```

`match` is a substring of the full target URL, or a wildcard pattern (`*`, `?`, `[…]`) matched against the target host.

`SECURE_VIBE_VERIFY_SCOPE` — a simpler comma-separated `host[:port]` allow-list with **no** auth headers, for unauthenticated endpoints:

```bash
export SECURE_VIBE_VERIFY_SCOPE="localhost:4000,127.0.0.1:8080"
```

If neither is set — or the file is missing/unreadable/invalid — the lane denies all live fires and stays in dry-run. A misconfigured operator never accidentally fires at a live target.

!!! tip "When to call it"
    After detection flags a candidate (e.g. an unvalidated `?url=` fetch) on a target you are **authorized** to test — to upgrade "looks vulnerable" to reproducible, confirmed evidence.

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

## Honest scope

The scanners behind these tools are **narrow by design** — four deterministic scanners (secrets, dependencies, Dockerfile, GitHub Actions), not a general SAST. They catch known patterns and exact-match known-bad packages with zero false positives on the data moat, but they miss novel or semantic bugs. That is the accepted trade-off: a fast, offline prevention layer that grounds an AI assistant at generation time, backed by a deterministic gate — not a replacement for human review or a claim to find every vulnerability.

## See also

- [Developer guide](../guides/developer.md) — wiring SecureVibe into your editor and workflow.
- [DevOps guide](../guides/devops.md) — the `gate` in CI with SARIF.
- [Quick start](../quickstart.md) — install and first scan.
