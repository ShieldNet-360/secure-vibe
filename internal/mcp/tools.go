package mcp

// toolDefinitions returns the MCP tool descriptors served on tools/list.
// The schemas follow the MCP `tools/list` definition: name, description,
// and an inputSchema JSON-Schema-shaped object describing the arguments.
func toolDefinitions() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"name":        "lookup_vulnerability",
			"description": "Look up a package in the Skills Library supply-chain vulnerability database. Returns malicious package entries and known typosquats that match the package name.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"package": map[string]string{"type": "string", "description": "Package name to look up."},
					"ecosystem": map[string]interface{}{
						"type":        "string",
						"description": "One of npm, pypi, crates, go, rubygems, maven, nuget, github-actions, docker. Optional — defaults to all ecosystems.",
						"enum":        []string{"npm", "pypi", "crates", "go", "rubygems", "maven", "nuget", "github-actions", "docker"},
					},
					"version": map[string]string{"type": "string", "description": "Optional version pin. Empty matches all affected versions."},
				},
				"required": []string{"package"},
			},
		},
		{
			"name":        "check_secret_pattern",
			"description": "Run the Skills Library secret-detection rules against the supplied text and return matches with severity, name, and whether the match is a known false positive.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"text": map[string]string{"type": "string", "description": "Text to scan for secrets."},
				},
				"required": []string{"text"},
			},
		},
		{
			"name":        "get_skill",
			"description": "Return the requested tier of a Skills Library skill (minimal, compact, or full).",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"skill_id": map[string]string{"type": "string", "description": "Skill ID, e.g. 'secret-detection'."},
					"budget":   map[string]string{"type": "string", "description": "One of minimal, compact, full. Default: compact."},
				},
				"required": []string{"skill_id"},
			},
		},
		{
			"name":        "search_skills",
			"description": "Search the Skills Library by substring match against title, description, ID, and category. Returns matching skill metadata.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"query": map[string]string{"type": "string", "description": "Substring query."},
				},
				"required": []string{"query"},
			},
		},
		{
			"name":        "scan_secrets",
			"description": "Scan text or a local file for secrets using the Skills Library secret-detection rules. Pass `text` for inline content or `file_path` for an absolute path on the host running the MCP server. When --allowed-roots is configured at startup, `file_path` must resolve to a location under one of those roots; sensitive system directories (~/.ssh, ~/.aws, ~/.gnupg, /etc/shadow, ...) are always denied. Pass `format`=\"sarif\" to receive a SARIF 2.1.0 log instead of the rich JSON shape. Returns structured matches with severity, location, score, entropy, and whether the match is a known false positive.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"text":      map[string]string{"type": "string", "description": "Inline text to scan. Mutually exclusive with file_path."},
					"file_path": map[string]string{"type": "string", "description": "Absolute path to a local file to scan. Files larger than 10 MiB are rejected. Subject to --allowed-roots and the sensitive-directory deny-list."},
					"format": map[string]interface{}{
						"type":        "string",
						"description": "Output format. Empty (or \"json\") returns the native MCP shape; \"sarif\" returns a SARIF 2.1.0 log for CI consumption.",
						"enum":        []string{"", "json", "sarif"},
					},
				},
			},
		},
		{
			"name":        "check_dependency",
			"description": "Check a package name (and optional version) against the malicious-packages database for one ecosystem. Returns malicious matches, typosquat matches, and any CVE patterns that mention the package. Version matching is semver-aware: ranges like \"all\", \"*\", \"pre-X.Y.Z\", \">=X.Y.Z\", \"<X.Y.Z\", and inclusive \"X.Y.Z - A.B.C\" are evaluated against the supplied version. Pass `format`=\"sarif\" to receive a SARIF 2.1.0 log instead of the rich JSON shape. Use this when an LLM is about to import or install a new dependency.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"package": map[string]string{"type": "string", "description": "Package name."},
					"version": map[string]string{"type": "string", "description": "Optional version pin. Empty matches all affected versions."},
					"ecosystem": map[string]interface{}{
						"type":        "string",
						"description": "Package ecosystem.",
						"enum":        []string{"npm", "pypi", "crates", "go", "rubygems", "maven", "nuget", "github-actions", "docker"},
					},
					"format": map[string]interface{}{
						"type":        "string",
						"description": "Output format. Empty (or \"json\") returns the native MCP shape; \"sarif\" returns a SARIF 2.1.0 log for CI consumption.",
						"enum":        []string{"", "json", "sarif"},
					},
				},
				"required": []string{"package", "ecosystem"},
			},
		},
		{
			"name":        "check_typosquat",
			"description": "Check a package name against the known typosquat database. Returns every typosquat entry where the supplied name appears as the target (legitimate package being squatted) or as a known typosquat. Useful for catching dependency-confusion attempts before the install lands.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"package": map[string]string{"type": "string", "description": "Package name to check."},
					"ecosystem": map[string]interface{}{
						"type":        "string",
						"description": "Optional ecosystem filter.",
						"enum":        []string{"npm", "pypi", "crates", "go", "rubygems", "maven", "nuget", "github-actions", "docker"},
					},
				},
				"required": []string{"package"},
			},
		},
		{
			"name":        "map_compliance_control",
			"description": "Map a Skills Library skill ID, category, or free-text term to the controls in SOC 2 / HIPAA / PCI DSS that cover it. Returns the matching controls grouped by framework so an LLM can cite the right control alongside a fix.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"skill_id": map[string]string{"type": "string", "description": "A Skills Library skill ID (e.g. 'secret-detection'). Either skill_id or query is required."},
					"query":    map[string]string{"type": "string", "description": "Free-text query matched case-insensitively against control title and description."},
					"framework": map[string]interface{}{
						"type":        "string",
						"description": "Optional framework filter.",
						"enum":        []string{"soc2", "hipaa", "pci-dss"},
					},
				},
			},
		},
		{
			"name":        "get_sigma_rule",
			"description": "Return one or more Sigma-format detection rules from the rules/ directory. Either pass `rule_id` for an exact match or `query` for a substring search against title / id / tags. Optionally filter by `category` (cloud, container, endpoint, saas).",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"rule_id": map[string]string{"type": "string", "description": "Exact Sigma rule UUID."},
					"query":   map[string]string{"type": "string", "description": "Substring search against title, id, and tags."},
					"category": map[string]interface{}{
						"type":        "string",
						"description": "Optional category filter (top-level rules/ subdir).",
						"enum":        []string{"cloud", "container", "endpoint", "saas"},
					},
				},
			},
		},
		{
			"name":        "version_status",
			"description": "Return the Skills Library data version, release timestamp, signature status, and a summary of how many files are tracked in the root manifest. Use this before relying on results from the other tools so the LLM can disclose data freshness and trust state.",
			"inputSchema": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			"name":        "scan_dependencies",
			"description": "Parse a project lockfile or manifest at file_path and run every dependency against the malicious-packages database, the typosquat database, and the CVE-pattern list. Recognises package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml, requirements.txt, Pipfile.lock, poetry.lock, go.sum, Cargo.lock, pom.xml, gradle.lockfile / build.gradle.lockfile, packages.lock.json, *.csproj / *.fsproj / *.vbproj, Gemfile.lock, composer.lock, Package.resolved, and pubspec.lock. Subject to --allowed-roots and the sensitive-directory deny-list. Pass `format`=\"sarif\" for SARIF 2.1.0 output suitable for GitHub Advanced Security ingest.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"file_path": map[string]string{"type": "string", "description": "Absolute path to a lockfile on the host running the MCP server."},
					"format": map[string]interface{}{
						"type":        "string",
						"description": "Output format. Empty (or \"json\") returns the native MCP shape; \"sarif\" returns a SARIF 2.1.0 log.",
						"enum":        []string{"", "json", "sarif"},
					},
				},
				"required": []string{"file_path"},
			},
		},
		{
			"name":        "scan_github_actions",
			"description": "Run the cicd-security hardening checklist against a `.github/workflows/*.yml` (or .yaml) file. Detects unpinned actions, missing `permissions:` defaults, `pull_request_target` checking out untrusted code, untrusted-input script injection, `curl | sh` patterns, and stored cloud credentials. Subject to --allowed-roots and the sensitive-directory deny-list. Pass `format`=\"sarif\" for SARIF 2.1.0 output.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"file_path": map[string]string{"type": "string", "description": "Absolute path to a GitHub Actions workflow YAML file."},
					"format": map[string]interface{}{
						"type":        "string",
						"description": "Output format. Empty (or \"json\") returns the native MCP shape; \"sarif\" returns a SARIF 2.1.0 log.",
						"enum":        []string{"", "json", "sarif"},
					},
				},
				"required": []string{"file_path"},
			},
		},
		{
			"name":        "scan_dockerfile",
			"description": "Run a hardening pass over a Dockerfile. Detects untagged or :latest base images, USER root, secrets baked into ENV/ARG, ADD from a remote URL, `curl | sh` install patterns, and apt-get install lines without version pins. Subject to --allowed-roots and the sensitive-directory deny-list. Pass `format`=\"sarif\" for SARIF 2.1.0 output.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"file_path": map[string]string{"type": "string", "description": "Absolute path to a Dockerfile."},
					"format": map[string]interface{}{
						"type":        "string",
						"description": "Output format. Empty (or \"json\") returns the native MCP shape; \"sarif\" returns a SARIF 2.1.0 log.",
						"enum":        []string{"", "json", "sarif"},
					},
				},
				"required": []string{"file_path"},
			},
		},
		{
			"name":        "list_external_tools",
			"description": "List the industry-standard external CLIs that SecureVibe skills recommend (declared in each skill's `external_tools` frontmatter), each marked with whether its binary is installed on the current host's PATH. Discovery only — the server never runs these tools. Use it to decide which external scanner to run, then run the chosen one yourself via the shell (e.g. `gitleaks dir` for whole-repo/git-history secret scanning, `hadolint <file>` for Dockerfile linting). The built-in MCP scanners (scan_secrets, scan_dockerfile, …) remain the offline default.",
			"inputSchema": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			"name":        "explain_finding",
			"description": "Map a CWE ID, CVE ID, or free-text finding description to the relevant Skills Library skills and CVE-pattern entries. Returns the matching skills (with id, title, category, severity, and a short excerpt of the body) plus any CVE rows whose name or description mentions the query. Use this to attach remediation guidance to a SAST / SCA finding from another scanner.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"query": map[string]string{"type": "string", "description": "Free-text query — a CWE ID like \"CWE-77\", a CVE ID like \"CVE-2024-12345\", or a finding description."},
				},
				"required": []string{"query"},
			},
		},
		{
			"name":        "gate",
			"description": "Pick the right scanner for file_path and report a CI-friendly pass/fail with a per-severity count. Dispatches to scan_dependencies for lockfiles, scan_github_actions for `.github/workflows/*.{yml,yaml}` files, and scan_dockerfile for Dockerfiles, falling back to scan_secrets for any other file. Findings at or above `severity_floor` (default: high) fail the check; the response includes `pass` and `exit_code` (0 on pass, 1 on fail) so a CI wrapper can branch on it. (Formerly `policy_check`; that name is still accepted.)",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"file_path":      map[string]string{"type": "string", "description": "Absolute path to the artifact to scan."},
					"severity_floor": map[string]interface{}{"type": "string", "description": "Findings at or above this severity fail the check. Default: high.", "enum": []string{"", "critical", "high", "medium", "low", "info"}},
				},
				"required": []string{"file_path"},
			},
		},
		{
			"name":        "audit",
			"description": "Run a whole-tree security audit: fan the deterministic scanners (secrets, dependencies, Dockerfile, GitHub Actions) across every file under `path`, then deduplicate, rank by severity, and triage likely fixtures (test/example/sample paths are reported but demoted). One ranked result for the whole tree instead of a per-file pass/fail. Deterministic and offline — the calling agent supplies the reasoning and any dynamic verification. Respects the server's allowed-roots sandbox.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path":           map[string]string{"type": "string", "description": "Directory to audit (default: the current directory). Must be within the server's allowed roots."},
					"severity_floor": map[string]interface{}{"type": "string", "description": "Only collect findings at or above this severity. Default: low.", "enum": []string{"", "critical", "high", "medium", "low", "info"}},
				},
				"required": []string{"path"},
			},
		},
		{
			"name":        "http_probe",
			"description": "Send ONE HTTP request you crafted to an operator-authorized target and read back status / headers / body / elapsed_ms — the primitive for dynamically verifying a candidate finding (SQLi timing, reflected XSS, open redirect, path traversal, SSTI). SAFETY: it is scope-gated. With no scope configured, or a target outside SECURE_VIBE_VERIFY_SCOPE / SECURE_VIBE_VERIFY_SCOPE_FILE, it does NOT send — it returns the request `plan` with `sent:false`. Operator-configured auth headers are merged in; never supply credentials for an out-of-scope host. Use `oob_listener` for blind/out-of-band classes (SSRF/XXE/blind command injection), and your OWN headless browser for XSS execution-proof or DOM XSS (this proves reflection, not execution). Per-class oracles are in the dynamic-verification skill.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"url":              map[string]string{"type": "string", "description": "Target URL to probe."},
					"method":           map[string]interface{}{"type": "string", "description": "HTTP method (default GET).", "enum": []string{"", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}},
					"headers":          map[string]interface{}{"type": "object", "description": "Request headers you crafted. Auth for in-scope hosts is supplied by the operator, not here."},
					"body":             map[string]string{"type": "string", "description": "Request body (e.g. an XML payload for XXE, a form body for POST)."},
					"follow_redirects": map[string]interface{}{"type": "boolean", "description": "Follow 3xx redirects. Default false — keep false to detect open redirects from the Location header."},
					"timeout_ms":       map[string]interface{}{"type": "integer", "description": "Per-request timeout in milliseconds (default 8000, capped at 30000)."},
				},
				"required": []string{"url"},
			},
		},
		{
			"name":        "oob_listener",
			"description": "Out-of-band callback listener for BLIND verification (SSRF, XXE, blind command injection) — classes that leave no trace in the response body. `allocate` returns a unique callback URL to weave into your payload; after probing the target with `http_probe`, `poll` the token to see whether the target called back. A hit is confirmation. The listener runs on 127.0.0.1, so it is reachable from a target on the same host (local / staging); a target that cannot reach it needs an external OOB service. Receiving callbacks is passive, so this is not scope-gated.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"action": map[string]interface{}{"type": "string", "description": "allocate a new callback URL, or poll a token for hits.", "enum": []string{"allocate", "poll"}},
					"token":  map[string]string{"type": "string", "description": "Required for poll: the token returned by a prior allocate."},
				},
				"required": []string{"action"},
			},
		},
	}
}
