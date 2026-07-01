package tools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for dir := wd; dir != "/"; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
	}
	t.Fatalf("could not find repo root from %s", wd)
	return ""
}

func newLibrary(t *testing.T) *Library {
	t.Helper()
	l, err := NewLibrary(repoRoot(t))
	if err != nil {
		t.Fatalf("NewLibrary: %v", err)
	}
	return l
}

func TestLookupVulnerabilityFindsEventStream(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.LookupVulnerability("event-stream", "npm", "")
	if err != nil {
		t.Fatalf("LookupVulnerability: %v", err)
	}
	if len(res.Matches) == 0 {
		t.Fatalf("expected event-stream in npm.json; got 0 matches")
	}
	if !strings.EqualFold(res.Matches[0].Name, "event-stream") {
		t.Errorf("first match=%q, want event-stream", res.Matches[0].Name)
	}
	if res.Matches[0].Severity == "" {
		t.Error("match has no severity")
	}
}

func TestLookupVulnerabilityAcrossAllEcosystems(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.LookupVulnerability("event-stream", "", "")
	if err != nil {
		t.Fatalf("LookupVulnerability: %v", err)
	}
	if len(res.Matches) == 0 {
		t.Fatalf("expected at least one match across all ecosystems")
	}
}

func TestLookupVulnerabilityRejectsUnknownEcosystem(t *testing.T) {
	lib := newLibrary(t)
	cases := []string{
		"../../../../etc/passwd",
		"..",
		"npm/../../etc",
		"unknown",
		"",
	}
	for _, eco := range cases {
		if eco == "" {
			continue
		}
		_, err := lib.LookupVulnerability("event-stream", eco, "")
		if err == nil {
			t.Errorf("LookupVulnerability(%q) returned nil error; want rejection", eco)
		}
	}
	if _, err := lib.LookupVulnerability("event-stream", "NPM", ""); err != nil {
		t.Errorf("LookupVulnerability with NPM (uppercase) should normalize and succeed: %v", err)
	}
}

func TestLookupVulnerabilityReturnsTyposquats(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.LookupVulnerability("lodash", "npm", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Typosquats) == 0 {
		t.Fatalf("expected at least one typosquat for lodash; got 0")
	}
}

func TestLoadTyposquatsCachesAcrossCalls(t *testing.T) {
	lib := newLibrary(t)
	first, err := lib.loadTyposquats()
	if err != nil {
		t.Fatalf("loadTyposquats: %v", err)
	}
	if first == nil {
		t.Fatal("loadTyposquats returned nil on first call")
	}
	second, err := lib.loadTyposquats()
	if err != nil {
		t.Fatalf("loadTyposquats (second): %v", err)
	}
	if first != second {
		t.Errorf("loadTyposquats did not cache: first=%p second=%p", first, second)
	}
}

// TestCheckSecretPatternDropsDenylistedAWSDocsKey covers the
// AWS-docs-canonical AKIAIOSFODNN7EXAMPLE: it no longer surfaces at
// all because dlp_patterns.json puts "AKIAIOSFODNN7" on the AWS
// Access Key denylist_substrings. The matching dlp_exclusions.json
// entry is a strictly weaker mark-as-false-positive signal kept for
// backwards compatibility; denylist wins.
func TestCheckSecretPatternDropsDenylistedAWSDocsKey(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.CheckSecretPattern("AKIAIOSFODNN7EXAMPLE")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 0 {
		t.Errorf("AKIAIOSFODNN7EXAMPLE should be dropped by denylist_substrings; got %d matches: %v", len(res.Matches), res.Matches)
	}
}

// TestCheckSecretPatternFlagsKnownFalsePositive exercises the path
// where a match survives denylist + entropy + hotword gating but is
// still flagged as KnownFalsePositive via dlp_exclusions.json (the
// wildcard "your-" entry on type=dictionary).
func TestCheckSecretPatternFlagsKnownFalsePositive(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.CheckSecretPattern("creds: api_key = your-secret-here_abc123xyz4567890")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) == 0 {
		t.Fatal("expected the api_key placeholder to match Generic API Key")
	}
	if !res.Matches[0].KnownFalsePositive {
		t.Errorf("placeholder containing 'your-' should be flagged as known false positive")
	}
}

func TestCheckSecretPatternFlagsRealLookingKey(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.CheckSecretPattern("creds: AKIA1234567890ABCDEF")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) == 0 {
		t.Fatal("expected a non-example AKIA key to match")
	}
	if res.Matches[0].KnownFalsePositive {
		t.Errorf("real-looking AKIA key must not be flagged as known false positive")
	}
	if res.Matches[0].Entropy <= 0 {
		t.Errorf("entropy should be computed and non-zero for a real-looking AKIA; got %v", res.Matches[0].Entropy)
	}
}

// TestCheckSecretPatternEntropyGate verifies a low-entropy candidate
// is dropped when the pattern declares entropy_min. The Generic API
// Key pattern requires entropy_min=3.0 and a repeated character
// string fails that gate.
func TestCheckSecretPatternEntropyGate(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.CheckSecretPattern("creds: api_key = aaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range res.Matches {
		if m.Name == "Generic API Key" {
			t.Errorf("low-entropy api_key should be dropped by entropy_min; matched %+v", m)
		}
	}
}

// TestCheckSecretPatternHotwordScoring confirms hotword_boost is
// applied and HotwordHit is reported when a hotword sits inside the
// configured window. The Generic API Key pattern bakes the
// 'api'/'key' hotwords into its own regex prefix, so any hit is
// guaranteed to record HotwordHit=true.
func TestCheckSecretPatternHotwordScoring(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.CheckSecretPattern("api_key = abcdef0123456789ABCDEFGH")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) == 0 {
		t.Fatal("expected api_key match")
	}
	if !res.Matches[0].HotwordHit {
		t.Errorf("hotword 'api' is inside the match itself; HotwordHit must be true, got %+v", res.Matches[0])
	}
	if res.Matches[0].Score <= 0 {
		t.Errorf("score should reflect score_weight + hotword_boost; got %v", res.Matches[0].Score)
	}
}

// TestVersionMatches pins down the affected-version range syntax the
// MCP tools recognise so refactors of versionMatches don't silently
// break upstream callers.
func TestVersionMatches(t *testing.T) {
	cases := []struct {
		affected string
		version  string
		want     bool
	}{
		{"3.3.6", "3.3.6", true},
		{"3.3.6", "3.3.7", false},
		{"all", "99.0.0", true},
		{"*", "0.0.1", true},
		{"pre-3.1.0", "3.0.9", true},
		{"pre-3.1.0", "3.1.0", false},
		{"pre-3.1.0", "3.1.1", false},
		{"pre-3", "2.9.0", true},
		{"pre-3", "3.0.0", false},
		{">=1.0.0", "1.0.0", true},
		{">=1.0.0", "0.9.9", false},
		{">1.0.0", "1.0.0", false},
		{"<=1.0.0", "1.0.0", true},
		{"<1.0.0", "0.9.9", true},
		{"1.0.0 - 1.2.0", "1.1.5", true},
		{"1.0.0 - 1.2.0", "1.3.0", false},
		{"v1.2.3", "1.2.3", true},
	}
	for _, tc := range cases {
		if got := versionMatches(tc.affected, tc.version); got != tc.want {
			t.Errorf("versionMatches(%q, %q) = %v, want %v", tc.affected, tc.version, got, tc.want)
		}
	}
}

func TestGetSkillTiersDifferInLength(t *testing.T) {
	lib := newLibrary(t)
	minimal, err := lib.GetSkill("secret-detection", "minimal")
	if err != nil {
		t.Fatal(err)
	}
	full, err := lib.GetSkill("secret-detection", "full")
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Content) <= len(minimal.Content) {
		t.Errorf("expected full tier longer than minimal; minimal=%d full=%d",
			len(minimal.Content), len(full.Content))
	}
	if minimal.Title == "" || full.Title == "" {
		t.Errorf("title should be populated; got minimal=%q full=%q", minimal.Title, full.Title)
	}
}

func TestGetSkillDefaultsToCompact(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.GetSkill("secret-detection", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Tier != "compact" {
		t.Errorf("default tier=%q, want compact", res.Tier)
	}
}

func TestGetSkillRejectsUnknownSkill(t *testing.T) {
	lib := newLibrary(t)
	if _, err := lib.GetSkill("does-not-exist", "compact"); err == nil {
		t.Error("expected error for unknown skill id")
	}
}

func TestSearchSkillsByQuery(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.SearchSkills("secret")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range res.Skills {
		if s.ID == "secret-detection" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("query 'secret' should return secret-detection; got %v", res.Skills)
	}
}

func TestSearchSkillsEmptyReturnsAll(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.SearchSkills("")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Skills) < 7 {
		t.Errorf("expected all 7+ skills; got %d", len(res.Skills))
	}
}

// TestLoadSecretRulesFromYAMLChecklist is the integration check for
// the PR-B1 migration: the loader must read every type: secret_pattern
// entry from checklists/secret_detection.yaml, populate runtime
// fields, and compile each regex.
func TestLoadSecretRulesFromYAMLChecklist(t *testing.T) {
	lib := newLibrary(t)
	rules, err := lib.loadSecretRules()
	if err != nil {
		t.Fatalf("loadSecretRules: %v", err)
	}
	if len(rules.Patterns) == 0 {
		t.Fatalf("no patterns loaded from checklists/secret_detection.yaml")
	}
	// Spot-check: the well-known AWS Access Key entry must survive
	// the migration with its hotwords and entropy floor intact.
	var aws *Pattern
	for _, p := range rules.Patterns {
		if p.Name == "AWS Access Key" {
			aws = p
			break
		}
	}
	if aws == nil {
		t.Fatalf("AWS Access Key pattern missing after migration")
	}
	if aws.Regex == "" || aws.compiled == nil {
		t.Errorf("AWS Access Key regex did not compile: %q", aws.Regex)
	}
	if aws.EntropyMin <= 0 {
		t.Errorf("AWS Access Key entropy_min not carried: %v", aws.EntropyMin)
	}
	if len(aws.Hotwords) == 0 {
		t.Errorf("AWS Access Key hotwords empty")
	}
	// Exclusions block must also have been carried.
	if len(rules.Exclusions) == 0 {
		t.Errorf("no exclusions loaded from YAML")
	}
}
