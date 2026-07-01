package tools

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// writeTempFile drops `body` into a fresh dir under t.TempDir and
// returns the absolute path. The dir is auto-cleaned by the test
// runner.
func writeTempFile(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func TestScanDependenciesEmptyLockfile(t *testing.T) {
	lib := newLibrary(t)
	path := writeTempFile(t, "package-lock.json", `{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","version":"1.0.0"}}}`)
	res, err := lib.ScanDependencies(path)
	if err != nil {
		t.Fatalf("ScanDependencies: %v", err)
	}
	if res.Findings == nil {
		t.Fatalf("Findings should be []DependencyFinding{} (non-nil) on a clean scan")
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected zero findings on a demo lockfile, got %d", len(res.Findings))
	}
}

func TestScanDependenciesFlagsMaliciousNPM(t *testing.T) {
	lib := newLibrary(t)
	// event-stream is the well-known compromised package in the
	// project's bundled malicious-packages corpus. We use the
	// 3.3.6 line because the corpus references that version range.
	path := writeTempFile(t, "package-lock.json", `{
		"name": "demo",
		"lockfileVersion": 3,
		"packages": {
			"": { "name": "demo", "version": "1.0.0" },
			"node_modules/event-stream": { "version": "3.3.6" }
		}
	}`)
	res, err := lib.ScanDependencies(path)
	if err != nil {
		t.Fatalf("ScanDependencies: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatalf("expected at least one finding for event-stream@3.3.6, got none")
	}
	hit := false
	for _, f := range res.Findings {
		if strings.EqualFold(f.Package, "event-stream") && f.Category == "malicious-package" {
			hit = true
			// event-stream is a curated row (no upstream
			// `source` field), so the confidence band must be
			// "confirmed". A regression to "high" would mean the
			// VulnEntry.Source threading broke.
			if f.Confidence != "confirmed" {
				t.Errorf("expected confidence=confirmed on curated event-stream finding, got %q", f.Confidence)
			}
			break
		}
	}
	if !hit {
		t.Fatalf("expected event-stream to be flagged as malicious-package; got %+v", res.Findings)
	}
}

// TestScanDependenciesSetsConfidenceForOSSFRow asserts that a
// malicious-package row sourced from the OSSF feed surfaces with
// confidence "high" (not "confirmed"). The two-band distinction
// matters for CI consumers that want curated-only enforcement;
// flattening both to a single value would lose that knob.
func TestScanDependenciesSetsConfidenceForOSSFRow(t *testing.T) {
	lib := newLibrary(t)
	// --hiljson is one of the OSSF-imported rows in npm.json at
	// the time of writing. The exact name is unimportant; we
	// just need any row with `source: ossf-malicious-packages`.
	// If the corpus changes such that this row disappears, the
	// test below will be skipped rather than fail.
	ossfName := firstOSSFMaliciousPkg(t, lib, "npm")
	if ossfName == "" {
		t.Skip("no OSSF-sourced npm row in the corpus; nothing to assert")
	}
	lockJSON := "{\n\t\t\"name\": \"demo\",\n\t\t\"lockfileVersion\": 3,\n\t\t\"packages\": {\n\t\t\t\"\": { \"name\": \"demo\", \"version\": \"1.0.0\" },\n\t\t\t\"node_modules/" + ossfName + "\": { \"version\": \"1.0.0\" }\n\t\t}\n\t}"
	path := writeTempFile(t, "package-lock.json", lockJSON)
	res, err := lib.ScanDependencies(path)
	if err != nil {
		t.Fatalf("ScanDependencies: %v", err)
	}
	var seen string
	for _, f := range res.Findings {
		if strings.EqualFold(f.Package, ossfName) && f.Category == "malicious-package" {
			seen = f.Confidence
			break
		}
	}
	if seen == "" {
		t.Skipf("OSSF row %q did not surface as a finding; corpus may have changed", ossfName)
	}
	if seen != "high" {
		t.Errorf("expected confidence=high on OSSF-sourced malicious-package finding, got %q", seen)
	}
}

// firstOSSFMaliciousPkg returns the name of the first VulnEntry in
// the given ecosystem's malicious-packages JSON whose `source` is
// the OSSF feed. Returns "" when no such row exists.
func firstOSSFMaliciousPkg(t *testing.T, lib *Library, eco string) string {
	t.Helper()
	vf, err := lib.loadVulnFile(eco)
	if err != nil {
		return ""
	}
	for _, e := range vf.Entries {
		if strings.TrimSpace(e.Source) == "ossf-malicious-packages" {
			return e.Name
		}
	}
	return ""
}

func TestScanDependenciesRejectsUnknownLockfile(t *testing.T) {
	lib := newLibrary(t)
	// composer.lock is a real PHP lockfile that no parser
	// currently handles, so it is the sentinel for the
	// "unrecognised format" branch.
	path := writeTempFile(t, "composer.lock", "anything")
	if _, err := lib.ScanDependencies(path); err == nil {
		t.Fatalf("expected error for unknown lockfile, got nil")
	}
}

func TestScanGitHubActionsLoadsChecklist(t *testing.T) {
	lib := newLibrary(t)
	wf := writeTempFile(t, "workflow.yml", `name: build
on:
  pull_request_target:
    types: [opened]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "${{ github.event.pull_request.title }}"
      - run: curl -fsSL https://example.com/install.sh | bash
`)
	res, err := lib.ScanGitHubActions(wf)
	if err != nil {
		t.Fatalf("ScanGitHubActions: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatalf("expected findings against a deliberately bad workflow; got none")
	}
	for _, f := range res.Findings {
		if f.Confidence == "" {
			t.Errorf("expected confidence to be set on workflow finding %s; got empty", f.RuleID)
		}
	}
}

func TestScanDockerfileCatchesCommonBugs(t *testing.T) {
	lib := newLibrary(t)
	df := writeTempFile(t, "Dockerfile", `FROM node:latest
USER root
ENV API_TOKEN=abc123
ADD https://example.com/installer.tgz /tmp/
RUN curl -fsSL https://example.com/x.sh | sh
RUN apt-get update && apt-get install curl
`)
	res, err := lib.ScanDockerfile(df)
	if err != nil {
		t.Fatalf("ScanDockerfile: %v", err)
	}
	want := map[string]bool{
		"dkr-explicit-latest-tag": false,
		"dkr-non-root-user":       false,
		"dkr-no-secrets-in-env":   false,
		"dkr-no-add-remote":       false,
		"dkr-no-curl-pipe-sh":     false,
		"dkr-apt-version-pin":     false,
	}
	for _, f := range res.Findings {
		if _, ok := want[f.RuleID]; ok {
			want[f.RuleID] = true
		}
		if f.Confidence == "" {
			t.Errorf("expected confidence to be set on Dockerfile finding %s; got empty", f.RuleID)
		}
	}
	for rid, hit := range want {
		if !hit {
			t.Errorf("expected scan_dockerfile to flag %s, got findings=%+v", rid, res.Findings)
		}
	}
}

func TestScanDockerfileAcceptsPinnedFROM(t *testing.T) {
	lib := newLibrary(t)
	df := writeTempFile(t, "Dockerfile", `FROM node:20-alpine@sha256:abc
USER 10001
`)
	res, err := lib.ScanDockerfile(df)
	if err != nil {
		t.Fatalf("ScanDockerfile: %v", err)
	}
	for _, f := range res.Findings {
		if f.RuleID == "dkr-pinned-base-digest" || f.RuleID == "dkr-explicit-latest-tag" || f.RuleID == "dkr-non-root-user" {
			t.Errorf("clean Dockerfile triggered %s: %+v", f.RuleID, f)
		}
	}
}

func TestExplainFindingByCWE(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.ExplainFinding("CWE-798")
	if err != nil {
		t.Fatalf("ExplainFinding: %v", err)
	}
	if res.CWE != "CWE-798" {
		t.Errorf("expected normalised CWE=CWE-798, got %q", res.CWE)
	}
	// At least one secret-detection / hardcoded-secret skill should
	// mention CWE-798 in its body or rules.
	found := false
	for _, h := range res.Skills {
		if strings.Contains(strings.ToLower(h.SkillID), "secret") {
			found = true
			break
		}
	}
	if !found && len(res.Skills) == 0 && len(res.Vulns) == 0 {
		t.Errorf("expected at least one skill or CVE hit for CWE-798, got zero")
	}
}

func TestExplainFindingRejectsEmptyQuery(t *testing.T) {
	lib := newLibrary(t)
	if _, err := lib.ExplainFinding("  "); err == nil {
		t.Fatalf("expected error on empty query, got nil")
	}
}

func TestPolicyCheckDockerfilePassFail(t *testing.T) {
	lib := newLibrary(t)
	clean := writeTempFile(t, "Dockerfile", `FROM node:20-alpine@sha256:abc
USER 10001
`)
	cleanRes, err := lib.PolicyCheck(clean, "high")
	if err != nil {
		t.Fatalf("PolicyCheck(clean): %v", err)
	}
	if !cleanRes.Pass || cleanRes.ExitCode != 0 {
		t.Errorf("clean Dockerfile should pass at high floor; got %+v", cleanRes)
	}
	dirty := writeTempFile(t, "Dockerfile", `FROM node:latest
USER root
`)
	dirtyRes, err := lib.PolicyCheck(dirty, "high")
	if err != nil {
		t.Fatalf("PolicyCheck(dirty): %v", err)
	}
	if dirtyRes.Pass || dirtyRes.ExitCode != 1 {
		t.Errorf("dirty Dockerfile should fail at high floor; got %+v", dirtyRes)
	}
}

// TestPolicyCheckFallsBackToSecrets verifies that a file matching no
// specialised scanner routes to scan_secrets (rather than erroring), so a
// gate run over an arbitrary set of changed files still catches leaked
// credentials. A clean text file passes. Positive secret detection is
// covered by the ScanSecrets tests; here we only assert the routing.
func TestPolicyCheckFallsBackToSecrets(t *testing.T) {
	lib := newLibrary(t)
	p := writeTempFile(t, "random.txt", "hello world, nothing secret here\n")
	res, err := lib.PolicyCheck(p, "high")
	if err != nil {
		t.Fatalf("PolicyCheck(unknown file): unexpected error %v", err)
	}
	if res.Scan != "scan_secrets" {
		t.Errorf("unknown file should route to scan_secrets, got %q", res.Scan)
	}
	if !res.Pass || res.ExitCode != 0 {
		t.Errorf("clean text file should pass at high floor; got %+v", res)
	}
}

func TestPolicyCheckDefaultsToHighFloor(t *testing.T) {
	lib := newLibrary(t)
	df := writeTempFile(t, "Dockerfile", `FROM node:latest
USER root
`)
	res, err := lib.PolicyCheck(df, "")
	if err != nil {
		t.Fatalf("PolicyCheck: %v", err)
	}
	if res.SeverityFloor != "high" {
		t.Errorf("default severity_floor should be high, got %q", res.SeverityFloor)
	}
}

func TestPolicyCheckRejectsUnknownSeverity(t *testing.T) {
	lib := newLibrary(t)
	df := writeTempFile(t, "Dockerfile", `FROM node:20-alpine@sha256:abc
USER 10001
`)
	if _, err := lib.PolicyCheck(df, "nope"); err == nil {
		t.Fatalf("expected unknown-severity error, got nil")
	}
}

// TestPolicyCheckDispatchesNewEcosystems exercises the policy_check
// dispatcher for the Maven / NuGet / Ruby lockfile shapes added
// alongside this test. It does NOT assert findings (these fixtures
// are deliberately benign); it only confirms the new file types
// are routed to scan_dependencies instead of returning the
// "no scanner is configured" error.
func TestPolicyCheckDispatchesNewEcosystems(t *testing.T) {
	lib := newLibrary(t)
	cases := []struct {
		name string
		body string
	}{
		{
			name: "pom.xml",
			body: `<?xml version="1.0"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>benign</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>
`,
		},
		{
			name: "gradle.lockfile",
			body: "org.example:benign:1.0.0=runtimeClasspath\n",
		},
		{
			name: "packages.lock.json",
			body: `{"version":1,"dependencies":{"net8.0":{"Benign":{"type":"Direct","resolved":"1.0.0"}}}}`,
		},
		{
			name: "App.csproj",
			body: `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Benign" Version="1.0.0" /></ItemGroup></Project>`,
		},
		{
			name: "Gemfile.lock",
			body: `GEM
  remote: https://rubygems.org/
  specs:
    benign (1.0.0)

DEPENDENCIES
  benign
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := writeTempFile(t, tc.name, tc.body)
			res, err := lib.PolicyCheck(p, "high")
			if err != nil {
				t.Fatalf("PolicyCheck(%s): %v", tc.name, err)
			}
			if res.Scan != "scan_dependencies" {
				t.Errorf("expected scan=scan_dependencies for %s, got %q", tc.name, res.Scan)
			}
		})
	}
}

func TestScanDependenciesSARIFShape(t *testing.T) {
	lib := newLibrary(t)
	path := writeTempFile(t, "package-lock.json", `{
		"name": "demo",
		"lockfileVersion": 3,
		"packages": {
			"": { "name": "demo", "version": "1.0.0" },
			"node_modules/event-stream": { "version": "3.3.6" }
		}
	}`)
	res, err := lib.ScanDependencies(path)
	if err != nil {
		t.Fatalf("ScanDependencies: %v", err)
	}
	sarif := ScanDependenciesSARIF(res)
	if sarif.Version != SARIFVersion {
		t.Errorf("SARIF version=%q want %q", sarif.Version, SARIFVersion)
	}
	if len(sarif.Runs) != 1 {
		t.Fatalf("expected one run, got %d", len(sarif.Runs))
	}
	if sarif.Runs[0].Tool.Driver.Rules == nil {
		t.Errorf("driver.rules should be non-nil []SARIFRule even on empty scan")
	}
}

func TestScanDockerfileSARIFShape(t *testing.T) {
	lib := newLibrary(t)
	df := writeTempFile(t, "Dockerfile", `FROM node:latest
USER root
`)
	res, err := lib.ScanDockerfile(df)
	if err != nil {
		t.Fatalf("ScanDockerfile: %v", err)
	}
	sarif := ScanDockerfileSARIF(res)
	if len(sarif.Runs[0].Results) == 0 {
		t.Errorf("expected at least one SARIF result for a bad Dockerfile")
	}
	for _, r := range sarif.Runs[0].Results {
		if r.Locations[0].PhysicalLocation.Region == nil || r.Locations[0].PhysicalLocation.Region.StartLine == 0 {
			t.Errorf("Dockerfile result is missing a line number: %+v", r)
		}
	}
}

func TestPickScanRoutesGitHubWorkflows(t *testing.T) {
	cases := map[string]string{
		"/repo/.github/workflows/build.yml":    "scan_github_actions",
		"/repo/.github/workflows/release.yaml": "scan_github_actions",
		"/repo/Dockerfile":                     "scan_dockerfile",
		"/repo/api.dockerfile":                 "scan_dockerfile",
		"/repo/package-lock.json":              "scan_dependencies",
		"/repo/requirements-dev.txt":           "scan_dependencies",
		"/repo/Cargo.lock":                     "scan_dependencies",
	}
	for path, want := range cases {
		got, err := pickScan(path)
		if err != nil {
			t.Errorf("pickScan(%q) errored: %v", path, err)
			continue
		}
		if got != want {
			t.Errorf("pickScan(%q) = %q, want %q", path, got, want)
		}
	}
	// Files no specialised scanner claims fall back to a secret scan
	// rather than erroring, so a gate over a mixed file set still runs.
	if got, err := pickScan("/repo/notes.md"); err != nil || got != "scan_secrets" {
		t.Errorf("pickScan(/repo/notes.md) = %q, err %v; want scan_secrets, nil", got, err)
	}
}

// TestWalkScanFiles locks the shared directory walker behind gate /
// scan-secrets / scan-dependencies: noise dirs, binary, and empty files
// are pruned, and a keep predicate narrows the set.
func TestWalkScanFiles(t *testing.T) {
	root := t.TempDir()
	mk := func(rel string, body []byte) {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("src/app.go", []byte("package main\n"))
	mk("README.md", []byte("# hi\n"))
	mk("empty.txt", nil)                           // empty -> skipped
	mk("logo.png", []byte("PNG\x00\x00data"))      // binary (NUL) -> skipped
	mk("node_modules/dep/index.js", []byte("x\n")) // noise dir -> skipped
	mk(".git/config", []byte("[core]\n"))          // noise dir -> skipped

	has := func(files []string, base string) bool {
		for _, f := range files {
			if filepath.Base(f) == base {
				return true
			}
		}
		return false
	}

	all, err := WalkScanFiles(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || !has(all, "app.go") || !has(all, "README.md") {
		t.Fatalf("nil keep: want app.go + README.md only, got %v", all)
	}
	for _, bad := range []string{"empty.txt", "logo.png", "index.js", "config"} {
		if has(all, bad) {
			t.Errorf("%s should have been pruned (empty/binary/noise-dir); got %v", bad, all)
		}
	}

	goOnly, err := WalkScanFiles(root, func(p string) bool { return strings.HasSuffix(p, ".go") })
	if err != nil {
		t.Fatal(err)
	}
	if len(goOnly) != 1 || !has(goOnly, "app.go") {
		t.Errorf("keep predicate (*.go): want app.go only, got %v", goOnly)
	}
}

// patternMarkerRe extracts the inline `<!-- pattern: { ... } -->` HTML
// markers from a SKILL.md body. FindAll (not FindString) so a bullet
// carrying more than one marker is fully captured.
var patternMarkerRe = regexp.MustCompile(`<!--\s*pattern\s*:\s*(\{[^}]*\})\s*-->`)

// assertScannerContract is the drift guard binding a scanner to its
// single source of truth, SKILL.md. The checklist YAML is gone; the
// contract lives in the skill's `<!-- pattern: { id, check } -->`
// markers (id filtered by idPrefix):
//
//   - check: deterministic  → a Go scanner check MUST emit this id
//   - check: llm            → the agent reasons it from SKILL.md; no Go check
//
// It enforces the bijection both ways (every Go check has a
// deterministic marker, every deterministic marker has a Go check) and
// that no llm-marked pattern is silently enforced by Go.
func assertScannerContract(t *testing.T, skillRel, idPrefix string, goIDs map[string]bool) {
	t.Helper()
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(skillRel)))
	if err != nil {
		t.Fatal(err)
	}
	deterministic := map[string]bool{}
	llm := map[string]bool{}
	for _, m := range patternMarkerRe.FindAllStringSubmatch(string(data), -1) {
		var p struct {
			ID    string `yaml:"id"`
			Check string `yaml:"check"`
		}
		if err := yaml.Unmarshal([]byte(m[1]), &p); err != nil {
			t.Fatalf("invalid pattern marker %q: %v", m[1], err)
		}
		if !strings.HasPrefix(p.ID, idPrefix) {
			continue
		}
		switch p.Check {
		case "deterministic":
			deterministic[p.ID] = true
		case "llm":
			llm[p.ID] = true
		case "":
			t.Errorf("marker %q has no check: field (want deterministic|llm)", p.ID)
		default:
			t.Errorf("marker %q has unknown check %q (want deterministic|llm)", p.ID, p.Check)
		}
	}
	for id := range goIDs {
		if !deterministic[id] {
			t.Errorf("scanner emits %q but %s has no `check: deterministic` marker for it — "+
				"add the marker or rename the Go id", id, skillRel)
		}
	}
	for id := range deterministic {
		if !goIDs[id] {
			t.Errorf("%s marks %q as `check: deterministic` but no Go scanner check emits it — "+
				"implement the check or change the marker to `check: llm`", skillRel, id)
		}
	}
	for id := range llm {
		if goIDs[id] {
			t.Errorf("%s marks %q as `check: llm` but a Go scanner check emits it — "+
				"change the marker to `check: deterministic`", skillRel, id)
		}
	}
}

func TestDockerfileRuleIDsTraceToSkill(t *testing.T) {
	assertScannerContract(t, "skills/container-security/SKILL.md", "dkr-", DockerfileRuleIDs())
}

func TestGitHubActionsRuleIDsTraceToSkill(t *testing.T) {
	assertScannerContract(t, "skills/cicd-security/SKILL.md", "gha-", GitHubActionsRuleIDs())
}

// TestBlankYAMLComments locks in the comment-blanking lexer that stops a
// workflow's prose from acting as a regex anchor for the hardening
// checks: comment text becomes spaces, byte offsets are preserved, and a
// `#` inside a quoted scalar is left alone.
func TestBlankYAMLComments(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"full-line comment", "# curl x | sh\nrun: ok", "             \nrun: ok"},
		{"inline comment", "run: echo hi # curl | sh", "run: echo hi            "},
		{"hash in double quote kept", `run: echo "a # b"`, `run: echo "a # b"`},
		{"hash in single quote kept", `key: 'v#1'`, `key: 'v#1'`},
		{"no whitespace before hash kept", "key: value#notcomment", "key: value#notcomment"},
		{"offsets preserved", "abc # x\ndef", "abc    \ndef"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := blankYAMLComments(c.in)
			if got != c.want {
				t.Errorf("blankYAMLComments(%q)\n  got  %q\n  want %q", c.in, got, c.want)
			}
			if len(got) != len(c.in) {
				t.Errorf("length changed: %d -> %d (offsets must be preserved)", len(c.in), len(got))
			}
		})
	}
}

// TestScanGitHubActionsInjectionPerStep is the regression for a real FP
// found by dogfooding the scanner on the project's own CI: a run:-anchored
// rule must be evaluated per step, so an innocent `run:` does not bridge
// across the file to a github.event token in an unrelated later step,
// while a genuine same-step injection still fires even when an earlier
// innocent run: precedes it.
func TestScanGitHubActionsInjectionPerStep(t *testing.T) {
	lib := newLibrary(t)

	// Case 1: innocent run: step, then a LATER step that safely env-binds
	// a github.event expression. The file-wide regex used to bridge the
	// two and flag the innocent step. There must be no injection finding.
	clean := writeTempFile(t, "clean.yml", `name: ci
on: [pull_request]
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - name: install
        run: pip install pyyaml
      - name: use base ref safely
        env:
          BASE_REF: ${{ github.event.pull_request.base.ref }}
        run: echo "$BASE_REF"
`)
	res, err := lib.ScanGitHubActions(clean)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if f.RuleID == "gha-no-untrusted-script-injection" {
			t.Errorf("false positive: innocent run: step flagged as injection (line %d)", f.Line)
		}
	}

	// Case 2: an innocent run: step FOLLOWED by a step that really does
	// interpolate github.event into its run body. The real injection must
	// still be detected (and located on its own step).
	bad := writeTempFile(t, "bad.yml", `name: ci
on: [issue_comment]
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - name: install
        run: curl -fsSL https://example.com/i.sh | sh
      - name: echo comment
        run: |
          echo "${{ github.event.comment.body }}"
`)
	res, err = lib.ScanGitHubActions(bad)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range res.Findings {
		if f.RuleID == "gha-no-untrusted-script-injection" {
			found = true
		}
	}
	if !found {
		t.Error("real same-step injection after an innocent run: was not detected")
	}
}
