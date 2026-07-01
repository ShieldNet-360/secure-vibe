package tools

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestScanSecretsRejectsBothInputs(t *testing.T) {
	lib := newLibrary(t)
	if _, err := lib.ScanSecrets("", ""); err == nil {
		t.Error("scan_secrets must reject empty input")
	}
	if _, err := lib.ScanSecrets("x", "/tmp/x"); err == nil {
		t.Error("scan_secrets must reject both text and file_path")
	}
}

func TestScanSecretsTextDelegatesToCheckSecretPattern(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.ScanSecrets("creds: AKIA1234567890ABCDEF", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) == 0 {
		t.Error("expected a match for a real-looking AKIA key")
	}
	if res.FilePath != "" || res.FileSize != 0 {
		t.Error("file fields should be zero for inline text scan")
	}
}

func TestScanSecretsFile(t *testing.T) {
	lib := newLibrary(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "leak.txt")
	if err := os.WriteFile(path, []byte("creds: AKIA1234567890ABCDEF\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := lib.ScanSecrets("", path)
	if err != nil {
		t.Fatal(err)
	}
	if res.FilePath != path {
		t.Errorf("file_path=%q want %q", res.FilePath, path)
	}
	if res.FileSize == 0 {
		t.Error("file_size should be > 0")
	}
	if len(res.Matches) == 0 {
		t.Error("expected at least one match in scanned file")
	}
}

func TestCheckDependencyNeedsEcosystem(t *testing.T) {
	lib := newLibrary(t)
	if _, err := lib.CheckDependency("event-stream", "", ""); err == nil {
		t.Error("check_dependency must require ecosystem")
	}
	if _, err := lib.CheckDependency("", "", "npm"); err == nil {
		t.Error("check_dependency must require package")
	}
}

func TestCheckDependencyEventStreamNpm(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.CheckDependency("event-stream", "", "npm")
	if err != nil {
		t.Fatal(err)
	}
	if res.Ecosystem != "npm" {
		t.Errorf("ecosystem=%q want npm", res.Ecosystem)
	}
	if len(res.Malicious) == 0 {
		t.Fatal("expected at least one malicious entry for event-stream/npm")
	}
}

// TestCheckDependencyDoesNotLeakCrossEcosystemCVEs guards the ecosystem
// filter added to CheckDependency: an npm query for "express" must not
// surface Apache Struts2 Java CVEs whose description happens to contain
// the word "expressions". Prior to the filter, four Java CVEs leaked
// through as false positives because the matcher only did a substring
// check on entry.Name + entry.Description.
func TestCheckDependencyDoesNotLeakCrossEcosystemCVEs(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.CheckDependency("express", "4.18.0", "npm")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range res.CVEs {
		for _, lang := range c.Languages {
			if lang == "java" || lang == "kotlin" || lang == "scala" || lang == "groovy" {
				t.Errorf("CheckDependency(express, npm) leaked %s/%s CVE %s (%s); ecosystem filter regressed",
					c.CVE, lang, c.CVE, c.Name)
			}
		}
	}
}

// TestCheckDependencyDoesNotLeakApplianceCVEs guards the appliance-CVE
// retag: network-appliance / firmware CVEs (Citrix ADC, FortiOS, Pulse,
// Ivanti, PAN-OS, Citrix Bleed) used to carry languages: ["*"], so a
// substring of their name/description leaked them onto unrelated code
// packages — e.g. the npm package "path" matched "Citrix ADC path
// traversal", and "buffer"/"socks" matched "curl SOCKS5 heap buffer
// overflow". After retagging those entries to ["appliance"] / ["c"],
// the existing ecosystem filter drops them for code ecosystems.
func TestCheckDependencyDoesNotLeakApplianceCVEs(t *testing.T) {
	lib := newLibrary(t)
	// Common-word npm package names that previously collided with the
	// prose of appliance CVE descriptions.
	for _, pkg := range []string{"path", "buffer", "tar", "socks", "glob"} {
		res, err := lib.CheckDependency(pkg, "", "npm")
		if err != nil {
			t.Fatalf("CheckDependency(%s, npm): %v", pkg, err)
		}
		for _, c := range res.CVEs {
			t.Errorf("CheckDependency(%s, npm) leaked CVE %s (%s) langs=%v; appliance/infra CVE matched a code package",
				pkg, c.CVE, c.Name, c.Languages)
		}
	}
}

// TestCheckDependencyKeepsSameLanguageCVEs ensures the ecosystem filter
// is not over-tight: a maven query for "spring" must still surface the
// Java/Kotlin Spring CVEs in cve_patterns.json.
func TestCheckDependencyKeepsSameLanguageCVEs(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.CheckDependency("spring", "", "maven")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.CVEs) == 0 {
		t.Fatal("CheckDependency(spring, maven) returned 0 CVE; expected Spring CVEs from cve_patterns.json")
	}
	// Every CVE returned must declare at least one JVM language, otherwise
	// the filter is admitting unrelated entries.
	jvm := map[string]bool{"java": true, "kotlin": true, "scala": true, "groovy": true}
	for _, c := range res.CVEs {
		matched := false
		for _, l := range c.Languages {
			if jvm[strings.ToLower(l)] {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("CheckDependency(spring, maven) returned %s with non-JVM languages %v", c.CVE, c.Languages)
		}
	}
}

// TestCveAppliesToEcosystem exercises the helper directly, covering the
// three "yes" paths (entry wildcard, ecosystem wildcard, overlap), the
// "no" path (disjoint sets), and the permissive unknown-ecosystem default.
func TestCveAppliesToEcosystem(t *testing.T) {
	cases := []struct {
		name      string
		langs     []string
		ecosystem string
		want      bool
	}{
		{"entry wildcard applies to npm", []string{"*"}, "npm", true},
		{"entry wildcard applies to maven", []string{"*"}, "maven", true},
		{"docker accepts java entry", []string{"java"}, "docker", true},
		{"github-actions accepts python entry", []string{"python"}, "github-actions", true},
		{"java entry rejected by npm", []string{"java"}, "npm", false},
		{"kotlin entry accepted by maven", []string{"kotlin"}, "maven", true},
		{"javascript entry accepted by npm", []string{"javascript", "typescript"}, "npm", true},
		{"python entry rejected by maven", []string{"python"}, "maven", false},
		{"case-insensitive overlap", []string{"JavaScript"}, "npm", true},
		{"unknown ecosystem is permissive", []string{"java"}, "made-up", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := cveAppliesToEcosystem(c.langs, c.ecosystem); got != c.want {
				t.Errorf("cveAppliesToEcosystem(%v, %q) = %v, want %v", c.langs, c.ecosystem, got, c.want)
			}
		})
	}
}

func TestCheckTyposquatLodash(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.CheckTyposquat("lodash", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Typosquats) == 0 {
		t.Error("expected at least one typosquat row for lodash")
	}
}

func TestMapComplianceControlBySkill(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.MapComplianceControl("secret-detection", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Frameworks) == 0 {
		t.Fatal("expected secret-detection to map to at least one framework")
	}
}

func TestMapComplianceControlRequiresInput(t *testing.T) {
	lib := newLibrary(t)
	if _, err := lib.MapComplianceControl("", "", ""); err == nil {
		t.Error("map_compliance_control must require skill_id or query")
	}
	if _, err := lib.MapComplianceControl("x", "", "not-a-real-framework"); err == nil {
		t.Error("map_compliance_control must reject unknown framework")
	}
}

func TestMapComplianceControlByQueryAndFramework(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.MapComplianceControl("", "encryption", "pci-dss")
	if err != nil {
		t.Fatal(err)
	}
	// PCI DSS has multiple controls mentioning encryption; just assert
	// the framework filter actually narrowed the result set.
	if len(res.Frameworks) > 1 {
		t.Errorf("framework filter should yield at most one framework, got %v", res.Frameworks)
	}
}

// TestMapComplianceControlResponseKeyShape pins down the response
// shape post-review-flag-4: the Frameworks map MUST be keyed by the
// same machine ID the caller would pass in `framework` ("soc2" /
// "hipaa" / "pci-dss") and each entry MUST carry the human-readable
// name in its own field. An LLM client should be able to round-trip
// any key it sees back into a follow-up MapComplianceControl call.
func TestMapComplianceControlResponseKeyShape(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.MapComplianceControl("secret-detection", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Frameworks) == 0 {
		t.Fatal("expected at least one framework match for secret-detection")
	}
	validKeys := map[string]bool{"soc2": true, "hipaa": true, "pci-dss": true}
	for k, v := range res.Frameworks {
		if !validKeys[k] {
			t.Errorf("framework key %q is not a machine identifier; expected one of %v", k, validKeys)
		}
		if v.Name == "" {
			t.Errorf("framework %q must populate its human-readable Name field", k)
		}
		if len(v.Controls) == 0 {
			t.Errorf("framework %q matched but Controls slice is empty", k)
		}
	}
}

func TestGetSigmaRuleByQuery(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.GetSigmaRule("", "s3", "cloud")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rules) == 0 {
		t.Fatal("expected at least one Sigma rule matching s3 under cloud/")
	}
	found := false
	for _, r := range res.Rules {
		if strings.Contains(strings.ToLower(r.Title), "s3") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected an s3 rule in results; got %v", res.Rules)
	}
}

func TestGetSigmaRuleRequiresInput(t *testing.T) {
	lib := newLibrary(t)
	if _, err := lib.GetSigmaRule("", "", ""); err == nil {
		t.Error("get_sigma_rule must require rule_id or query")
	}
	if _, err := lib.GetSigmaRule("", "x", "not-a-real-category"); err == nil {
		t.Error("get_sigma_rule must reject unknown category")
	}
}

func TestVersionStatusReadsRootManifest(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.VersionStatus()
	if err != nil {
		t.Fatal(err)
	}
	if res.Version == "" {
		t.Error("version_status: version should be populated from manifest.json")
	}
	if res.Files == 0 {
		t.Error("version_status: files count should be > 0")
	}
	switch res.SignatureStatus {
	case "signed", "unsigned", "placeholder":
		// ok
	default:
		t.Errorf("unexpected signature_status %q", res.SignatureStatus)
	}
}

func TestCheckDependencyRejectsUnknownEcosystem(t *testing.T) {
	lib := newLibrary(t)
	if _, err := lib.CheckDependency("foo", "", "rubbish"); err == nil {
		t.Error("check_dependency must reject unknown ecosystem")
	}
}

// LookupVulnerability still rejects the new ecosystems' aliases? Cover
// one of the new ecosystems for parity.
func TestLookupVulnerabilityAcceptsRubygems(t *testing.T) {
	lib := newLibrary(t)
	// Even if there is no malicious-packages hit, the lookup should
	// not fail for a known ecosystem.
	if _, err := lib.LookupVulnerability("rails", "rubygems", ""); err != nil {
		t.Errorf("LookupVulnerability with rubygems should not error: %v", err)
	}
}

// TestLevenshtein covers a handful of obvious cases and the
// case-folded contract upstream callers rely on. The function itself
// does not fold case; callers (CheckTyposquat) normalise to lowercase
// before calling.
func TestLevenshtein(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"a", "", 1},
		{"", "abc", 3},
		{"lodash", "lodahs", 2},
		{"requests", "requets", 1},
		{"requests", "request", 1},
		{"react", "react", 0},
		{"abcdef", "abcxyz", 3},
	}
	for _, tc := range cases {
		if got := levenshtein(tc.a, tc.b); got != tc.want {
			t.Errorf("levenshtein(%q,%q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestCheckTyposquatPotentialFromPopularList exercises the new
// runtime path: an off-by-one variant of `requests` (PyPI) is not in
// the curated DB but is within Levenshtein distance 1 of the popular
// name and must therefore surface as a potential typosquat.
func TestCheckTyposquatPotentialFromPopularList(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.CheckTyposquat("requets", "pypi")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range res.PotentialTyposquats {
		if p.Target == "requests" && p.Distance > 0 && p.Distance <= 2 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected `requests` to surface as a potential typosquat for `requets`; got %+v", res.PotentialTyposquats)
	}
}

// TestCheckTyposquatExactPopularDoesNotSurface confirms a package
// that IS on the popular list yields no potential typosquats at all —
// not merely "not flagged against itself". Popular names sit within
// Levenshtein 2 of each other constantly (chalk/express/react/lodash
// all do), and before the self-popular guard every popular package in
// a lockfile produced a medium typosquat finding through the gate.
func TestCheckTyposquatExactPopularDoesNotSurface(t *testing.T) {
	lib := newLibrary(t)
	for _, pkg := range []string{"react", "chalk", "express", "lodash"} {
		res, err := lib.CheckTyposquat(pkg, "npm")
		if err != nil {
			t.Fatal(err)
		}
		if len(res.PotentialTyposquats) != 0 {
			t.Errorf("%s is itself popular and must yield no potential typosquats; got %+v",
				pkg, res.PotentialTyposquats)
		}
	}
}

// TestScanSecretsAllowedRootsRestriction confirms file_path is
// rejected when it falls outside the configured allow-list.
func TestScanSecretsAllowedRootsRestriction(t *testing.T) {
	lib := newLibrary(t)
	dir := t.TempDir()
	inside := filepath.Join(dir, "leak.txt")
	if err := os.WriteFile(inside, []byte("creds: AKIA1234567890ABCDEF\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	if err := lib.SetAllowedRoots([]string{dir}); err != nil {
		t.Fatalf("SetAllowedRoots: %v", err)
	}
	// Path inside the allowed root: ok.
	if _, err := lib.ScanSecrets("", inside); err != nil {
		t.Errorf("path inside allowed root should be accepted: %v", err)
	}
	// Path outside the allowed root: denied.
	outside := filepath.Join(other, "leak.txt")
	if err := os.WriteFile(outside, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := lib.ScanSecrets("", outside); err == nil {
		t.Errorf("path outside allowed root should be denied")
	}
}

// TestScanSecretsSensitiveDirAlwaysDenied confirms ~/.ssh-like
// directories are denied regardless of the allow-list state.
func TestScanSecretsSensitiveDirAlwaysDenied(t *testing.T) {
	lib := newLibrary(t)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory available")
	}
	target := filepath.Join(home, ".ssh", "id_rsa")
	if _, err := lib.ScanSecrets("", target); err == nil {
		t.Errorf("scan_secrets must deny paths inside ~/.ssh even without an allow-list")
	}
}

// TestScanSecretsTraversalRejected covers raw `..` segments. Even
// without an allow-list these are rejected so a caller cannot use
// path traversal to escape the directory their MCP client believed
// it had restricted them to.
func TestScanSecretsTraversalRejected(t *testing.T) {
	lib := newLibrary(t)
	if _, err := lib.ScanSecrets("", "/tmp/../etc/passwd"); err == nil {
		t.Errorf("scan_secrets must reject paths containing '..' segments")
	}
}

// TestScanSecretsSARIFRoundTrip verifies the SARIF wrapper carries
// the expected metadata for an inline-text scan and survives JSON
// marshalling without panicking.
func TestScanSecretsSARIFRoundTrip(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.ScanSecrets("creds: AKIA1234567890ABCDEF", "")
	if err != nil {
		t.Fatal(err)
	}
	log := ScanSecretsSARIF(res)
	if log.Version != SARIFVersion {
		t.Errorf("sarif version = %q, want %q", log.Version, SARIFVersion)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("expected one SARIF run, got %d", len(log.Runs))
	}
	if log.Runs[0].Tool.Driver.Name != SARIFToolName {
		t.Errorf("driver name = %q, want %q", log.Runs[0].Tool.Driver.Name, SARIFToolName)
	}
	if len(log.Runs[0].Results) == 0 {
		t.Errorf("expected at least one SARIF result")
	}
	if _, err := json.Marshal(log); err != nil {
		t.Errorf("marshalling SARIF log: %v", err)
	}
}

// TestCheckDependencySARIFShape pins the SARIF driver / rule
// identifiers for check_dependency so downstream filters do not
// silently drift.
func TestCheckDependencySARIFShape(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.CheckDependency("event-stream", "3.3.6", "npm")
	if err != nil {
		t.Fatal(err)
	}
	log := CheckDependencySARIF(res)
	if log.Runs[0].Tool.Driver.Name != SARIFToolName {
		t.Errorf("driver name = %q", log.Runs[0].Tool.Driver.Name)
	}
	wantIDs := map[string]bool{
		"secure-vibe.malicious-package": true,
		"secure-vibe.typosquat":         true,
		"secure-vibe.cve-pattern":       true,
	}
	for _, r := range log.Runs[0].Tool.Driver.Rules {
		if !wantIDs[r.ID] {
			t.Errorf("unexpected SARIF rule id %q", r.ID)
		}
	}
	if _, err := json.Marshal(log); err != nil {
		t.Errorf("marshal: %v", err)
	}
}

// TestLookupVulnerabilitySemverRange exercises the new semver-aware
// version matcher end-to-end. event-stream@3.3.6 is the only
// affected version, so 3.3.5 and 3.3.7 must NOT match.
func TestLookupVulnerabilitySemverRange(t *testing.T) {
	lib := newLibrary(t)
	hit, err := lib.LookupVulnerability("event-stream", "npm", "3.3.6")
	if err != nil {
		t.Fatal(err)
	}
	if len(hit.Matches) == 0 {
		t.Fatalf("expected exact-version hit for event-stream@3.3.6")
	}
	miss, err := lib.LookupVulnerability("event-stream", "npm", "3.3.5")
	if err != nil {
		t.Fatal(err)
	}
	if len(miss.Matches) != 0 {
		t.Errorf("expected no hit for event-stream@3.3.5; got %+v", miss.Matches)
	}
}

// TestSetAllowedRootsRejectsAllInvalidInput covers the regression
// surfaced in PR #17 review: a non-empty --allowed-roots input whose
// entries all trim to "" (e.g. " " or ",, ,") must fail loudly
// instead of silently producing an empty allow-list (which would
// then be interpreted by validateScanPath as "no restriction" and
// open the door to every path the process can stat).
func TestSetAllowedRootsRejectsAllInvalidInput(t *testing.T) {
	lib := newLibrary(t)
	cases := [][]string{
		{" "},
		{",", " ", "\t"},
		{""},
	}
	for _, c := range cases {
		if err := lib.SetAllowedRoots(c); err == nil {
			t.Errorf("SetAllowedRoots(%q) must fail; got nil", c)
		}
	}
	// Sanity: a real directory still works.
	if err := lib.SetAllowedRoots([]string{t.TempDir()}); err != nil {
		t.Errorf("SetAllowedRoots with a valid dir must succeed: %v", err)
	}
}

// TestScanSecretsDefaultsToProjectRoot covers the secure-vibe mcp main
// binary's default-to-cwd allow-list behaviour at the library
// level: when the caller has explicitly scoped the allow-list to a
// single directory (mirroring what `secure-vibe mcp` does at startup
// when neither --allowed-roots nor --allow-any-path is supplied),
// a path outside that directory must be rejected even when no
// explicit allow-list was ever provided by the end-user.
//
// This is a regression guard for the security posture promised in
// `cmd/secure-vibe/main.go`: by default the server can only read
// files under the project the operator launched it from. Without
// this test, a future refactor of validateScanPath that
// accidentally collapses the "default cwd root" case into the "no
// restriction" branch would silently re-open the door to /etc/<x>
// and ~/<y> reads.
func TestScanSecretsDefaultsToProjectRoot(t *testing.T) {
	lib := newLibrary(t)
	// Simulate `secure-vibe mcp` started from `project`: the binary
	// installs the cwd as the only allow-list entry.
	project := t.TempDir()
	if err := lib.SetAllowedRoots([]string{project}); err != nil {
		t.Fatalf("SetAllowedRoots(project): %v", err)
	}
	inside := filepath.Join(project, "code.txt")
	if err := os.WriteFile(inside, []byte("AKIA1234567890ABCDEF\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := lib.ScanSecrets("", inside); err != nil {
		t.Errorf("path inside the default project root should be accepted: %v", err)
	}
	// A path under a DIFFERENT temp dir (the operator's "other"
	// scratch area, or anything the launching user happens to
	// have read access to) must be denied.
	other := t.TempDir()
	outside := filepath.Join(other, "leak.txt")
	if err := os.WriteFile(outside, []byte("AKIA1234567890ABCDEF\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := lib.ScanSecrets("", outside)
	if err == nil {
		t.Fatalf("path outside the default project root should be denied")
	}
	if !strings.Contains(err.Error(), "allowed root") {
		t.Errorf("expected allow-list rejection error, got: %v", err)
	}
}

// TestScanSecretsSymlinkBypassDenied covers the regression surfaced
// in PR #17 review: a symlink planted inside an allowed root that
// targets a file OUTSIDE every allowed root must be rejected by
// validateScanPath. Before the fix this passed because the abs path
// was under the allow-list, so the OR short-circuited and the
// resolved (outside) target was never checked.
func TestScanSecretsSymlinkBypassDenied(t *testing.T) {
	lib := newLibrary(t)
	allowed := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(target, []byte("AKIA1234567890ABCDEF\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(allowed, "leak")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported on this platform: %v", err)
	}
	if err := lib.SetAllowedRoots([]string{allowed}); err != nil {
		t.Fatalf("SetAllowedRoots: %v", err)
	}
	if _, err := lib.ScanSecrets("", link); err == nil {
		t.Fatal("scan_secrets must deny a symlink that escapes the allow-list")
	} else if !strings.Contains(err.Error(), "allowed root") {
		t.Errorf("expected allow-list error, got: %v", err)
	}
	// Sanity: a regular file inside the allowed root still works.
	plain := filepath.Join(allowed, "ok.txt")
	if err := os.WriteFile(plain, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := lib.ScanSecrets("", plain); err != nil {
		t.Errorf("regular file inside allow-list should be accepted: %v", err)
	}
}

// TestLoadPopularPackagesDedupes covers the loader-side defence:
// even if the source JSON contains a duplicate, the cached list
// (and therefore CheckTyposquat's PotentialTyposquats output) must
// contain each name at most once.
func TestLoadPopularPackagesDedupes(t *testing.T) {
	lib := newLibrary(t)
	pkgs, err := lib.loadPopularPackages("npm")
	if err != nil {
		t.Fatalf("loadPopularPackages npm: %v", err)
	}
	seen := make(map[string]int)
	for _, p := range pkgs {
		seen[strings.ToLower(p)]++
	}
	for name, n := range seen {
		if n > 1 {
			t.Errorf("popular-package %q appears %d times after dedup", name, n)
		}
	}
}

// TestSARIFOmitemptyZeroValues guards the JSON-tag fix: ruleIndex
// and byteOffset/byteLength are semantically distinct from "unset"
// even at zero, so they must appear literally in the marshalled
// SARIF document. Before the fix `omitempty` dropped them silently.
func TestSARIFOmitemptyZeroValues(t *testing.T) {
	res := &SARIFResult{
		RuleID:    "secure-vibe.malicious-package",
		RuleIndex: 0,
		Message:   SARIFMultiformat{Text: "hi"},
		Locations: []SARIFLocation{{
			PhysicalLocation: SARIFPhysicalLocation{
				ArtifactLocation: SARIFArtifactLocation{URI: "stdin://text"},
				Region:           &SARIFRegion{ByteOffset: 0, ByteLength: 0},
			},
		}},
	}
	body, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	for _, k := range []string{`"ruleIndex":0`, `"byteOffset":0`, `"byteLength":0`} {
		if !strings.Contains(s, k) {
			t.Errorf("SARIF JSON missing %s; got %s", k, s)
		}
	}
}

// TestCheckTyposquatGoFinalSegment exercises the typosquatCompareKey
// path: for Go modules the distance must be computed against the last
// import-path segment, not the full path. A near-miss on the segment
// (`gim` vs `gin`) should surface; an unrelated module that just
// shares a long prefix (`github.com/aaaa/aaaa` vs
// `github.com/gin-gonic/gin`) must not.
func TestCheckTyposquatGoFinalSegment(t *testing.T) {
	lib := newLibrary(t)
	// Near-miss on final segment must surface.
	res, err := lib.CheckTyposquat("github.com/gin-gonic/gim", "go")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, h := range res.PotentialTyposquats {
		if strings.EqualFold(h.Target, "github.com/gin-gonic/gin") {
			found = true
			if h.Distance > 2 {
				t.Errorf("expected distance <=2 for gim->gin, got %d", h.Distance)
			}
		}
	}
	if !found {
		t.Errorf("expected gin to surface as a potential typosquat for gim, got %+v", res.PotentialTyposquats)
	}
	// Unrelated prefix-sharing module must not surface.
	res, err = lib.CheckTyposquat("totally-unrelated-name-xyz", "go")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.PotentialTyposquats) != 0 {
		t.Errorf("unrelated name should not match any popular Go module, got %+v", res.PotentialTyposquats)
	}
}

// TestLoadPopularPackagesDoesNotCacheParseError verifies fix B: when
// the data file fails to parse, the loader must NOT cache an empty
// list. A subsequent call against a valid file must still return the
// real data.
func TestLoadPopularPackagesDoesNotCacheParseError(t *testing.T) {
	lib := newLibrary(t)
	// Sanity: npm currently parses; record what we'd expect on a
	// successful call so we can assert recovery is not silently
	// masked by a stale cached empty list.
	pkgs, err := lib.loadPopularPackages("npm")
	if err != nil {
		t.Fatalf("npm should parse: %v", err)
	}
	if len(pkgs) == 0 {
		t.Fatalf("npm popular list should be non-empty")
	}
	// Now: ask for an ecosystem that does not exist on disk. We expect
	// an error, AND the absence of any cached empty entry that would
	// permanently mask later attempts.
	if _, err := lib.loadPopularPackages("nonexistent-ecosystem-xyz"); err == nil {
		t.Errorf("loading a missing ecosystem must return an error")
	}
	// Confirm the cache for the valid ecosystem is still intact (i.e.
	// we did not corrupt other entries while handling the error).
	pkgs2, err := lib.loadPopularPackages("npm")
	if err != nil {
		t.Fatalf("npm should still parse after a sibling error: %v", err)
	}
	if len(pkgs2) != len(pkgs) {
		t.Errorf("npm cache was disturbed: %d vs %d", len(pkgs2), len(pkgs))
	}
}

// TestVersionMatchesRejectsUnparseable covers fix C: an unparseable
// version (or threshold) must NOT be treated as the zero semver.
// Before the fix, versionMatches(">=0.0.0", "abc") returned true
// because parseSemver("abc") = (0, 0, 0, false) and compareSemver
// ignored the ok flag.
func TestVersionMatchesRejectsUnparseable(t *testing.T) {
	cases := []struct {
		affected string
		version  string
		want     bool
	}{
		// The classic bug.
		{">=0.0.0", "abc", false},
		// Symmetric: unparseable threshold should also miss.
		{">=abc", "1.2.3", false},
		// Range form with one unparseable endpoint.
		{"1.0.0 - bogus", "1.2.3", false},
		// pre- form: version "abc" must not be treated as < 5.0.0.
		{"pre-5.0.0", "abc", false},
		// Sanity: ordinary semver still works.
		{">=1.0.0", "1.2.3", true},
		{"1.0.0 - 2.0.0", "1.5.0", true},
		// And legacy exact-string fall through still works for
		// non-structured forms.
		{"abc", "abc", true},
	}
	for _, c := range cases {
		got := versionMatches(c.affected, c.version)
		if got != c.want {
			t.Errorf("versionMatches(%q, %q) = %v, want %v", c.affected, c.version, got, c.want)
		}
	}
}

// TestSetAllowedRootsSymlinkedRootAcceptsScan reproduces the macOS-
// style regression where the configured allow-list root itself goes
// through a symlink (e.g. /tmp -> /private/tmp). The simulated layout:
//
//	<realRoot>/data            # real directory containing scannable files
//	<linkRoot> -> <realRoot>   # symlink to <realRoot> (stands in for /tmp)
//
// Calling SetAllowedRoots([<linkRoot>/data]) used to store only the
// fully-resolved <realRoot>/data, so validateScanPath's AND check
// against the unresolved abs <linkRoot>/data/leak.txt would fail.
// After the fix, SetAllowedRoots stores BOTH forms so the abs form
// has a matching root.
func TestSetAllowedRootsSymlinkedRootAcceptsScan(t *testing.T) {
	lib := newLibrary(t)
	realRoot := t.TempDir()
	data := filepath.Join(realRoot, "data")
	if err := os.MkdirAll(data, 0o755); err != nil {
		t.Fatal(err)
	}
	leak := filepath.Join(data, "leak.txt")
	if err := os.WriteFile(leak, []byte("AKIA1234567890ABCDEF\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Build a sibling temp dir and replace it with a symlink to
	// realRoot so the *configured* path goes through a symlink.
	parent := t.TempDir()
	linkRoot := filepath.Join(parent, "linked")
	if err := os.Symlink(realRoot, linkRoot); err != nil {
		t.Skipf("symlink unsupported on this platform: %v", err)
	}
	allowed := filepath.Join(linkRoot, "data") // configured via symlinked path
	if err := lib.SetAllowedRoots([]string{allowed}); err != nil {
		t.Fatalf("SetAllowedRoots: %v", err)
	}
	scanPath := filepath.Join(allowed, "leak.txt") // also goes through the symlink
	if _, err := lib.ScanSecrets("", scanPath); err != nil {
		t.Fatalf("scanning a file inside a symlinked allowed root must succeed: %v", err)
	}
	// Defense-in-depth invariant: a symlink inside the allow-list that
	// redirects to a file OUTSIDE every allowed root (and outside
	// sensitivePaths()) must still be denied.
	outside := t.TempDir()
	target := filepath.Join(outside, "outside.txt")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	bypass := filepath.Join(data, "bypass")
	if err := os.Symlink(target, bypass); err != nil {
		t.Skipf("nested symlink unsupported: %v", err)
	}
	if _, err := lib.ScanSecrets("", bypass); err == nil {
		t.Errorf("symlink redirecting outside the allow-list must be denied even when the root itself is symlinked")
	}
}

// TestCheckDependencySARIFEmptyResultsArray pins the fix for the
// `"results": null` regression. A CheckDependencyResult with no
// findings must marshal to a SARIF document where Run.Results is the
// empty JSON array `[]`, not `null`. SARIF 2.1.0 specifies results as
// an array; `null` is interpreted as "results not computed" and GHAS
// will reject the upload.
func TestCheckDependencySARIFEmptyResultsArray(t *testing.T) {
	res := &CheckDependencyResult{
		Package:   "nonexistent-package-xyz",
		Ecosystem: "npm",
		Version:   "1.0.0",
	}
	log := CheckDependencySARIF(res)
	if log == nil || len(log.Runs) != 1 {
		t.Fatalf("expected exactly one SARIF run, got %+v", log)
	}
	if log.Runs[0].Results == nil {
		t.Fatalf("SARIF Run.Results must be a non-nil slice; got nil")
	}
	if len(log.Runs[0].Results) != 0 {
		t.Fatalf("expected empty results for a clean scan, got %d entries", len(log.Runs[0].Results))
	}
	body, err := json.Marshal(log)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"results":[]`) {
		t.Errorf("SARIF JSON must contain \"results\":[]; got: %s", string(body))
	}
	if strings.Contains(string(body), `"results":null`) {
		t.Errorf("SARIF JSON must not contain \"results\":null; got: %s", string(body))
	}
}

// TestVersionMatchesWildcardTokens pins fix for the on-disk-data
// regression: the malicious-packages JSONs use "any", "various", and
// "multiple" alongside "all" and "*" as wildcard markers in
// versions_affected (docker, maven, nuget, github-actions, plus
// left-pad on npm). versionMatches must treat all five as matching
// any concrete version, or check_dependency silently misses the
// malicious-package hit.
func TestVersionMatchesWildcardTokens(t *testing.T) {
	tokens := []string{"all", "*", "any", "various", "multiple",
		"ALL", "Any", "VARIOUS", "Multiple"} // case-insensitive
	for _, tok := range tokens {
		if !versionMatches(tok, "1.2.3") {
			t.Errorf("versionMatches(%q, %q) = false, want true", tok, "1.2.3")
		}
		if !versionMatches(tok, "999.0.0-rc.7+build.42") {
			t.Errorf("versionMatches(%q, %q) = false, want true", tok, "999.0.0-rc.7+build.42")
		}
	}
}

// TestLookupVulnerabilityWildcardMatchesRealEntries reads the actual
// on-disk malicious-packages data and confirms that every entry with
// a wildcard token surfaces when LookupVulnerability is called with
// an arbitrary concrete version. Specifically pins:
//   - left-pad (npm) — versions_affected=["1.0.0","any"]
//   - actions/checkout@untrusted-ref (github-actions) — ["any"]
//   - xmrig-cryptominer-cluster (docker) — ["multiple"]
//
// Before the fix these all silently returned no match.
func TestLookupVulnerabilityWildcardMatchesRealEntries(t *testing.T) {
	lib := newLibrary(t)
	cases := []struct {
		pkg, ecosystem, version string
	}{
		{"left-pad", "npm", "9.9.9"},
		{"actions/checkout@untrusted-ref", "github-actions", "v4"},
		{"xmrig-cryptominer-cluster", "docker", "1.0.0"},
	}
	for _, c := range cases {
		hit, err := lib.LookupVulnerability(c.pkg, c.ecosystem, c.version)
		if err != nil {
			t.Errorf("LookupVulnerability(%q, %q, %q): %v", c.pkg, c.ecosystem, c.version, err)
			continue
		}
		if len(hit.Matches) == 0 {
			t.Errorf("expected wildcard match for %s@%s (%s); got none", c.pkg, c.version, c.ecosystem)
		}
	}
}

// TestPathUnderCaseInsensitiveOnDarwinWindows pins the case-handling
// of pathUnder on case-insensitive host filesystems. On macOS HFS+ /
// APFS and Windows NTFS, /Users/foo/.SSH and /Users/foo/.ssh refer
// to the *same* directory, so a deny-list entry of /Users/foo/.ssh
// must match either spelling. On Linux the comparison stays
// case-sensitive so we don't introduce false positives where
// distinct files share a prefix.
func TestPathUnderCaseInsensitiveOnDarwinWindows(t *testing.T) {
	parent := "/users/foo/.ssh"
	upper := "/Users/Foo/.SSH/id_rsa"
	switch runtime.GOOS {
	case "darwin", "windows":
		if !pathUnder(upper, parent) {
			t.Errorf("pathUnder(%q, %q) must be true on %s (case-insensitive FS)", upper, parent, runtime.GOOS)
		}
	default:
		if pathUnder(upper, parent) {
			t.Errorf("pathUnder(%q, %q) must stay case-sensitive on %s", upper, parent, runtime.GOOS)
		}
	}
}

// TestSARIFMessageTextAlwaysEmitted pins that SARIF message.text is
// emitted even when empty. SARIF 2.1.0 §3.11.11 requires a message
// to have at least text or id; since we never emit id, dropping the
// text key with omitempty would produce invalid SARIF on the (rare)
// future call site that passes "".
func TestSARIFMessageTextAlwaysEmitted(t *testing.T) {
	m := SARIFMultiformat{Text: ""}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"text":""`) {
		t.Errorf("SARIFMultiformat must always emit a text key, got %s", string(b))
	}
}

// TestScanSecretsSARIFEmptyRulesArray pins that a zero-finding
// scan_secrets SARIF emits driver.rules as [] rather than omitting
// the key or producing null. Mirrors the equivalent check on
// CheckDependencySARIF so consumers can rely on a consistent output
// shape across the two tools.
func TestScanSecretsSARIFEmptyRulesArray(t *testing.T) {
	res := &ScanSecretsResult{Matches: nil}
	log := ScanSecretsSARIF(res)
	b, err := json.Marshal(log)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, `"rules":[]`) {
		t.Errorf("expected driver.rules to serialise as \"[]\" on zero findings, got: %s", s)
	}
	if !strings.Contains(s, `"results":[]`) {
		t.Errorf("expected run.results to serialise as \"[]\" on zero findings, got: %s", s)
	}
}

// TestScanSecretsSARIFRuleIDCollisionGuard pins the disambiguation
// behaviour for the unlikely case where two distinct pattern names
// produce the same sarifIDForPattern slug. Without the guard the
// second pattern would silently overwrite the first in
// idxAfterSort. We construct a ScanSecretsResult manually because
// the live dlp_patterns.json has no colliding names.
func TestScanSecretsSARIFRuleIDCollisionGuard(t *testing.T) {
	// sarifIDForPattern lowercases + non-alnum-collapses, so these
	// two names collide under the slug rule.
	res := &ScanSecretsResult{
		Matches: []SecretMatch{
			{Name: "Foo Bar", Severity: "high", Start: 0, End: 3, Score: 1, Entropy: 1},
			{Name: "foo_bar", Severity: "low", Start: 5, End: 8, Score: 0.5, Entropy: 0.5},
		},
	}
	log := ScanSecretsSARIF(res)
	if len(log.Runs) != 1 {
		t.Fatalf("expected one run, got %d", len(log.Runs))
	}
	run := log.Runs[0]
	if len(run.Tool.Driver.Rules) < 2 {
		t.Fatalf("expected at least two distinct rules after collision guard, got %d", len(run.Tool.Driver.Rules))
	}
	ids := make(map[string]int)
	for _, r := range run.Tool.Driver.Rules {
		ids[r.ID]++
	}
	for id, n := range ids {
		if n > 1 {
			t.Errorf("rule ID %q appears %d times after collision guard; expected 1", id, n)
		}
	}
	// Each result must point at a real rule index.
	for i, r := range run.Results {
		if r.RuleIndex < 0 || r.RuleIndex >= len(run.Tool.Driver.Rules) {
			t.Errorf("result %d ruleIndex=%d out of range [0, %d)", i, r.RuleIndex, len(run.Tool.Driver.Rules))
			continue
		}
		if run.Tool.Driver.Rules[r.RuleIndex].ID != r.RuleID {
			t.Errorf("result %d ruleID=%q does not match rules[%d].ID=%q",
				i, r.RuleID, r.RuleIndex, run.Tool.Driver.Rules[r.RuleIndex].ID)
		}
	}
}

// TestLoadPopularPackagesDoesNotCacheNonENOENTErrors verifies that
// loadPopularPackages only caches an empty list when the data file is
// genuinely absent (os.IsNotExist). Other ReadFile errors (permission,
// I/O, EISDIR) must propagate AND must not be cached, so the next call
// can succeed when the underlying condition clears.
//
// We provoke a non-ENOENT error by replacing one ecosystem's JSON
// file with a directory of the same name; os.ReadFile then fails
// with EISDIR (a typed error that is not os.ErrNotExist).
func TestLoadPopularPackagesDoesNotCacheNonENOENTErrors(t *testing.T) {
	tempRoot := t.TempDir()
	// NewLibrary requires a skills/ subdirectory.
	if err := os.MkdirAll(filepath.Join(tempRoot, "skills"), 0o755); err != nil {
		t.Fatalf("mkdir skills: %v", err)
	}
	popDir := filepath.Join(tempRoot, "vulnerabilities", "supply-chain", "popular-packages")
	if err := os.MkdirAll(popDir, 0o755); err != nil {
		t.Fatalf("mkdir popular-packages: %v", err)
	}
	// Replace npm.json with a directory so ReadFile fails with EISDIR
	// rather than ENOENT.
	if err := os.MkdirAll(filepath.Join(popDir, "npm.json"), 0o755); err != nil {
		t.Fatalf("mkdir npm.json/: %v", err)
	}
	lib, err := NewLibrary(tempRoot)
	if err != nil {
		t.Fatalf("NewLibrary: %v", err)
	}
	// First call: must return an error, not silently swallow it.
	if _, err = lib.loadPopularPackages("npm"); err == nil {
		t.Fatalf("expected error for unreadable npm.json (it is a directory)")
	} else if errors.Is(err, os.ErrNotExist) {
		t.Errorf("error must not be ENOENT (npm.json exists as a directory): %v", err)
	}
	// Replace the bad directory with a valid file. If the previous
	// error path had cached an empty list, this recovery call would
	// return that stale empty list and mask the fix.
	if err := os.RemoveAll(filepath.Join(popDir, "npm.json")); err != nil {
		t.Fatalf("rm npm.json/: %v", err)
	}
	if err := os.WriteFile(filepath.Join(popDir, "npm.json"),
		[]byte(`{"ecosystem":"npm","packages":["lodash","react"]}`),
		0o644); err != nil {
		t.Fatalf("write npm.json: %v", err)
	}
	pkgs, err := lib.loadPopularPackages("npm")
	if err != nil {
		t.Fatalf("recovery call must succeed (a cached error would block this): %v", err)
	}
	if len(pkgs) != 2 {
		t.Errorf("expected 2 packages after recovery, got %d: %v", len(pkgs), pkgs)
	}
}

// TestScanSecretsRejectsRelativeFilePath verifies the schema contract
// advertised in tools.go ("Absolute path to a local file to scan"):
// validateScanPath must reject a relative file_path with a clear error
// rather than silently resolving it against the MCP server's CWD.
func TestScanSecretsRejectsRelativeFilePath(t *testing.T) {
	lib := newLibrary(t)
	_, err := lib.ScanSecrets("", "relative/path/to/file.txt")
	if err == nil {
		t.Fatalf("ScanSecrets must reject a relative file_path")
	}
	if !strings.Contains(err.Error(), "must be absolute") {
		t.Errorf("error should mention 'must be absolute', got: %v", err)
	}
	// Plain bare name (no separator) is also relative.
	if _, err := lib.ScanSecrets("", "leak.txt"); err == nil {
		t.Errorf("ScanSecrets must reject a bare filename as relative")
	}
}

// TestScanSecretsSARIFFileURI pins the SARIF artifact-URI shape so
// downstream consumers (CI dashboards, strict SARIF validators) get a
// well-formed RFC 3986 file:// URI for file scans and the
// stdin://text placeholder for inline scans. SARIF 2.1.0 §3.4.4 says
// artifactLocation.uri SHOULD conform to RFC 3986.
func TestScanSecretsSARIFFileURI(t *testing.T) {
	// File scan: artifact URI must be a file:// URI, not a bare path.
	lib := newLibrary(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "leak.txt")
	if err := os.WriteFile(path, []byte("creds: AKIA1234567890ABCDEF\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := lib.ScanSecrets("", path)
	if err != nil {
		t.Fatalf("scan_secrets file: %v", err)
	}
	log := ScanSecretsSARIF(res)
	if len(log.Runs) != 1 || len(log.Runs[0].Results) == 0 {
		t.Fatalf("expected at least one result, got runs=%d", len(log.Runs))
	}
	gotURI := log.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI
	wantPrefix := "file://"
	if !strings.HasPrefix(gotURI, wantPrefix) {
		t.Errorf("artifact URI = %q, want prefix %q (RFC 3986 file:// URI)", gotURI, wantPrefix)
	}
	// The URI must round-trip through net/url so strict validators
	// don't reject the SARIF document.
	if !strings.Contains(gotURI, path) {
		t.Errorf("artifact URI = %q does not contain the scanned path %q", gotURI, path)
	}
	// JSON round-trip: the URI must survive marshalling intact.
	blob, err := json.Marshal(log)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(blob), "file://") {
		t.Errorf("marshalled SARIF must contain a file:// URI: %s", string(blob))
	}

	// Inline-text scan: artifact URI must remain stdin://text (the
	// previously-stable placeholder), not a file:// URI.
	resInline, err := lib.ScanSecrets("creds: AKIA1234567890ABCDEF", "")
	if err != nil {
		t.Fatalf("scan_secrets text: %v", err)
	}
	logInline := ScanSecretsSARIF(resInline)
	if len(logInline.Runs[0].Results) == 0 {
		t.Fatalf("expected at least one inline result")
	}
	gotInline := logInline.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI
	if gotInline != "stdin://text" {
		t.Errorf("inline artifact URI = %q, want %q", gotInline, "stdin://text")
	}
}

// TestVersionMatchesEcoNpmCaretRange pins the ecosystem-native semver
// matcher wired in by P4d. The approximate matcher in library.go
// silently treats a caret prefix as part of an unrecognised string,
// so before this change versionInAnyRange("^1.2.0", "1.5.0") returned
// false. The native matcher in cmd/secure-vibe/internal/tools/semver
// returns true. This test catches any future regression in the
// dispatch path.
func TestVersionMatchesEcoNpmCaretRange(t *testing.T) {
	if !versionInAnyRangeEco("npm", "1.5.0", []string{"^1.2.0"}) {
		t.Errorf("npm: ^1.2.0 should match 1.5.0 via the native matcher")
	}
	if versionInAnyRangeEco("npm", "2.0.0", []string{"^1.2.0"}) {
		t.Errorf("npm: ^1.2.0 should NOT match 2.0.0")
	}
}

// TestVersionMatchesEcoPypiCompatible pins PEP 440 compatible-release
// semantics through the dispatcher. ~=1.2.3 := >=1.2.3, <1.3.
func TestVersionMatchesEcoPypiCompatible(t *testing.T) {
	if !versionInAnyRangeEco("pypi", "1.2.9", []string{"~=1.2.3"}) {
		t.Errorf("pypi: ~=1.2.3 should match 1.2.9")
	}
	if versionInAnyRangeEco("pypi", "1.3.0", []string{"~=1.2.3"}) {
		t.Errorf("pypi: ~=1.2.3 should NOT match 1.3.0")
	}
}

// TestVersionMatchesEcoGoPseudoVersion locks in pseudo-version
// timestamp ordering: a later pseudo timestamp must compare greater
// than an earlier one even when M.m.p are identical.
func TestVersionMatchesEcoGoPseudoVersion(t *testing.T) {
	earlier := "v0.0.0-20210101000000-000000000000"
	later := "v0.0.0-20210101120000-aaaaaaaaaaaa"
	if !versionInAnyRangeEco("go", later, []string{">=" + earlier}) {
		t.Errorf("go: later pseudo must satisfy >= earlier pseudo")
	}
	if versionInAnyRangeEco("go", earlier, []string{">" + later}) {
		t.Errorf("go: earlier pseudo must NOT satisfy > later pseudo")
	}
}

// TestVersionMatchesEcoUnknownFallsBack ensures versionMatchesEco
// for an ecosystem without a native matcher still uses the legacy
// approximate matcher and returns the same answer it always did.
func TestVersionMatchesEcoUnknownFallsBack(t *testing.T) {
	// "rubygems" has no native matcher here (not in the dispatch
	// list), so the approximate matcher in versionMatches is what
	// runs. ">= 1.2.3" should match 1.5.0 just like before.
	if !versionInAnyRangeEco("rubygems", "1.5.0", []string{">= 1.2.3"}) {
		t.Errorf("rubygems fallback: >= 1.2.3 should match 1.5.0")
	}
}

// TestLookupVulnerabilityIncludesOSVAdvisories wires the new
// vulnerabilities/osv/<eco>/index.json into LookupVulnerability. We
// expect every package present in the cache to be discoverable by
// name (case-insensitive) and to come back with a stable osv.dev
// reference URL. The cache for npm always contains at least 30 real
// advisories drawn from osv.dev's bulk export (see
// scripts/ingest-osv.py).
func TestLookupVulnerabilityIncludesOSVAdvisories(t *testing.T) {
	lib := newLibrary(t)
	// Pick the first by_package key from the npm index so the test
	// stays stable across cache refreshes.
	idx := lib.loadOSVIndex("npm")
	if idx == nil || len(idx.ByPackage) == 0 {
		t.Skipf("vulnerabilities/osv/npm/index.json missing or empty; run scripts/ingest-osv.py")
	}
	var pkg string
	for k := range idx.ByPackage {
		pkg = k
		break
	}
	res, err := lib.LookupVulnerability(pkg, "npm", "")
	if err != nil {
		t.Fatalf("LookupVulnerability(%q, npm, _): %v", pkg, err)
	}
	if len(res.OSVAdvisories) == 0 {
		t.Fatalf("expected at least one OSV advisory for %q, got none", pkg)
	}
	got := res.OSVAdvisories[0]
	if got.ID == "" {
		t.Errorf("OSVAdvisory.ID must be populated")
	}
	if got.Reference != "https://osv.dev/vulnerability/"+got.ID {
		t.Errorf("OSVAdvisory.Reference = %q, want osv.dev URL", got.Reference)
	}
	if got.Ecosystem != "npm" {
		t.Errorf("OSVAdvisory.Ecosystem = %q, want npm", got.Ecosystem)
	}
}

// TestLookupVulnerabilityMissingOSVIndexIsSafe ensures that an
// ecosystem with no on-disk OSV cache does not break the tool. The
// "rubygems" cache exists in this repo, so simulate a missing index
// by pointing the library at a temp root with no vulnerabilities/osv
// subdirectory.
func TestLookupVulnerabilityMissingOSVIndexIsSafe(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, "skills"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, "vulnerabilities", "supply-chain", "malicious-packages"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "vulnerabilities", "supply-chain", "malicious-packages", "npm.json"),
		[]byte(`{"ecosystem":"npm","entries":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	lib, err := NewLibrary(tmp)
	if err != nil {
		t.Fatal(err)
	}
	res, err := lib.LookupVulnerability("anything", "npm", "")
	if err != nil {
		t.Fatalf("LookupVulnerability must not fail when OSV cache is absent: %v", err)
	}
	if len(res.OSVAdvisories) != 0 {
		t.Errorf("OSVAdvisories must be empty when cache missing; got %d", len(res.OSVAdvisories))
	}
}

// TestOSVUserCacheOverridesRepoSample verifies the user-cache
// fallback: when SECURE_VIBE_MCP_CACHE points at a directory containing a
// populated osv/<eco>/index.json, the Library reads from there instead
// of the repo-bundled sample.
//
// The test uses a synthetic ecosystem entry ("user-cache-only-pkg")
// that is *not* in the repo sample, so a returned advisory proves the
// lookup hit the user cache rather than falling through.
func TestOSVUserCacheOverridesRepoSample(t *testing.T) {
	tmp := t.TempDir()
	// Minimal library scaffold so NewLibrary accepts the root.
	if err := os.MkdirAll(filepath.Join(tmp, "skills"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, "vulnerabilities", "supply-chain", "malicious-packages"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "vulnerabilities", "supply-chain", "malicious-packages", "npm.json"),
		[]byte(`{"ecosystem":"npm","entries":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// User cache: one synthetic OSV record for a package the repo
	// sample knows nothing about.
	cache := t.TempDir()
	npmDir := filepath.Join(cache, "osv", "npm")
	if err := os.MkdirAll(npmDir, 0o755); err != nil {
		t.Fatal(err)
	}
	const recordID = "TEST-USER-CACHE-2026-0001"
	record := `{
  "schema_version": "1.6.0",
  "id": "` + recordID + `",
  "modified": "2026-05-15T00:00:00Z",
  "summary": "synthetic test advisory routed via SECURE_VIBE_MCP_CACHE",
  "affected": [{"package": {"ecosystem": "npm", "name": "user-cache-only-pkg"}}]
}`
	if err := os.WriteFile(filepath.Join(npmDir, recordID+".json"), []byte(record), 0o644); err != nil {
		t.Fatal(err)
	}
	index := `{
  "schema_version": "1.0",
  "ecosystem": "npm",
  "last_updated": "2026-05-15",
  "by_package": {
    "user-cache-only-pkg": [{
      "id": "` + recordID + `",
      "file": "` + recordID + `.json",
      "modified": "2026-05-15T00:00:00Z",
      "summary": "synthetic test advisory routed via SECURE_VIBE_MCP_CACHE",
      "aliases": [],
      "severity": "medium"
    }]
  }
}`
	if err := os.WriteFile(filepath.Join(npmDir, "index.json"), []byte(index), 0o644); err != nil {
		t.Fatal(err)
	}

	lib, err := NewLibrary(tmp)
	if err != nil {
		t.Fatal(err)
	}
	// NewLibrary picks up SECURE_VIBE_MCP_CACHE at construction-time via
	// defaultUserCacheRoot(); for tests we override after-the-fact
	// rather than mutating the global env (which is fragile when
	// tests run in parallel).
	lib.userCacheRoot = cache

	res, err := lib.LookupVulnerability("user-cache-only-pkg", "npm", "")
	if err != nil {
		t.Fatalf("LookupVulnerability: %v", err)
	}
	if len(res.OSVAdvisories) == 0 {
		t.Fatalf("expected user-cache record to surface; got none. " +
			"This means osvDir() did NOT prefer the user cache.")
	}
	if got := res.OSVAdvisories[0].ID; got != recordID {
		t.Errorf("OSVAdvisory.ID = %q, want %q", got, recordID)
	}
	if got := res.OSVAdvisories[0].Severity; got != "medium" {
		t.Errorf("OSVAdvisory.Severity = %q, want medium (from index entry)", got)
	}
}

// TestOSVUserCacheMissingFallsBackToRepoSample verifies that an unset
// or missing user cache leaves the repo-bundled sample in charge. The
// "rubygems" cache exists in this repo so we use it as the ground
// truth — pointing userCacheRoot at a path with no osv/<eco>/ tree
// must NOT mask the bundled sample.
func TestOSVUserCacheMissingFallsBackToRepoSample(t *testing.T) {
	lib := newLibrary(t)
	lib.userCacheRoot = filepath.Join(t.TempDir(), "definitely-not-populated")

	idx := lib.loadOSVIndex("rubygems")
	if idx == nil || len(idx.ByPackage) == 0 {
		t.Fatalf("repo-bundled rubygems index must remain visible when " +
			"user cache is missing; got nil/empty")
	}
}

// TestCVEVersionAffected unit-tests the affected-range gate for
// CVE-pattern entries (the fix for a patched package being flagged).
func TestCVEVersionAffected(t *testing.T) {
	affected := []cveAffected{
		{Package: "next", Ecosystem: "npm", VersionsAffected: []string{
			">=14.0.0 <14.2.25", ">=15.0.0 <15.2.3",
		}},
	}
	cases := []struct {
		version string
		want    bool
	}{
		{"14.2.20", true},  // in range, vulnerable
		{"14.2.25", false}, // the fix, patched
		{"14.2.35", false}, // past the fix
		{"15.1.6", true},   // in range, vulnerable
		{"15.2.3", false},  // the fix
	}
	for _, c := range cases {
		if got := cveVersionAffected(affected, "npm", "next", c.version); got != c.want {
			t.Errorf("cveVersionAffected(next@%s) = %v, want %v", c.version, got, c.want)
		}
	}
	// Falls open for an ecosystem/package the affected rows don't cover.
	if !cveVersionAffected(affected, "pypi", "next", "1.0.0") {
		t.Error("non-applicable ecosystem should fall open (name-only match preserved)")
	}
	if !cveVersionAffected(affected, "npm", "express", "1.0.0") {
		t.Error("non-applicable package should fall open")
	}
	// No version pin and no applicable row -> fall open.
	if !cveVersionAffected(nil, "npm", "next", "14.0.0") {
		t.Error("empty affected should fall open")
	}
}

// TestCheckDependencyCVEVersionFilter is the end-to-end regression
// against the committed CVE-2025-29927 entry: a patched Next.js must not
// surface the CVE; a vulnerable one must.
func TestCheckDependencyCVEVersionFilter(t *testing.T) {
	lib := newLibrary(t)
	patched, err := lib.CheckDependency("next", "14.2.35", "npm")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range patched.CVEs {
		if c.CVE == "CVE-2025-29927" {
			t.Errorf("patched next@14.2.35 should not flag CVE-2025-29927")
		}
	}
	vuln, err := lib.CheckDependency("next", "15.1.6", "npm")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range vuln.CVEs {
		if c.CVE == "CVE-2025-29927" {
			found = true
		}
	}
	if !found {
		t.Error("vulnerable next@15.1.6 should flag CVE-2025-29927")
	}
}

// TestCheckDependencyNoSubstringFalsePositive locks the fix for the
// description-substring blowup: a CVE pinned (via affected[]) to one
// package must never surface for an unrelated package whose name is a
// substring of the CVE prose. CVE-2025-29927's text contains "subrequest",
// "send", "mishandled", and single letters, which previously flagged
// request/send/sha/i/d/q from any npm lockfile.
func TestCheckDependencyNoSubstringFalsePositive(t *testing.T) {
	lib := newLibrary(t)
	for _, pkg := range []struct{ name, version string }{
		{"request", "2.88.0"}, // "request" ⊂ "subrequest"
		{"send", "0.16.2"},    // "send" ⊂ "send a forged header"
		{"sha", "2.0.1"},      // "sha" ⊂ "mishandled"
		{"i", "0.3.6"},        // single letter
		{"d", "0.1.1"},        // single letter
		{"q", "1.5.1"},        // single letter
	} {
		res, err := lib.CheckDependency(pkg.name, pkg.version, "npm")
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range res.CVEs {
			if c.CVE == "CVE-2025-29927" {
				t.Errorf("%s@%s must not flag CVE-2025-29927 (Next.js-only)", pkg.name, pkg.version)
			}
		}
	}
}

func TestCVEAffectsPackage(t *testing.T) {
	affected := []cveAffected{{Package: "next", Ecosystem: "npm"}}
	if !cveAffectsPackage(affected, "npm", "next") {
		t.Error("exact package+ecosystem should match")
	}
	if cveAffectsPackage(affected, "npm", "request") {
		t.Error("different package in same ecosystem must NOT match")
	}
	if cveAffectsPackage(affected, "pypi", "next") {
		t.Error("same package, different ecosystem must NOT match")
	}
	// Empty Package = ecosystem-wide; empty Ecosystem = any ecosystem.
	if !cveAffectsPackage([]cveAffected{{Ecosystem: "npm"}}, "npm", "anything") {
		t.Error("ecosystem-wide row should match any package in that ecosystem")
	}
	if !cveAffectsPackage([]cveAffected{{Package: "log4j-core"}}, "maven", "log4j-core") {
		t.Error("row with empty ecosystem should match any ecosystem")
	}
}

func TestContainsWord(t *testing.T) {
	cases := []struct {
		hay, needle string
		want        bool
	}{
		{"x-middleware-subrequest header", "request", false}, // substring inside subrequest
		{"attacker to send a forged header", "send", true},   // whole word
		{"15.x mishandled the internal", "sha", false},       // inside mishandled
		{"the lodash.merge prototype path", "lodash.merge", true},
		{"uses apache commons text", "commons", true},
		{"", "x", false},
		{"abc", "", false},
	}
	for _, c := range cases {
		if got := containsWord(c.hay, c.needle); got != c.want {
			t.Errorf("containsWord(%q, %q) = %v, want %v", c.hay, c.needle, got, c.want)
		}
	}
}
