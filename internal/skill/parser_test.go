package skill

import (
	"strings"
	"testing"
)

const validSkill = `---
id: example-skill
version: "1.0.0"
title: "Example Skill"
description: "A skill used to exercise the parser"
category: prevention
severity: high
applies_to:
  - "before every commit"
languages: ["*"]
token_budget:
  minimal: 100
  compact: 400
  full: 1200
rules_path: "rules/"
last_updated: "2026-05-12"
sources:
  - "Test source"
---

# Example Skill

## Rules (for AI agents)

### ALWAYS
- Always do thing one.
- Always do thing two.

### NEVER
- Never do bad thing.

### KNOWN FALSE POSITIVES
- Ignore harmless variant.

## Context (for humans)

This skill demonstrates the parser. The body covers everything the parser
needs to produce all three tiers.

## References

- See the test corpus for verified fixtures.
`

func TestParseValidFrontmatter(t *testing.T) {
	s, err := ParseBytes("example/SKILL.md", []byte(validSkill))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s.Frontmatter.ID != "example-skill" {
		t.Errorf("id = %q, want example-skill", s.Frontmatter.ID)
	}
	if s.Frontmatter.Category != "prevention" {
		t.Errorf("category = %q", s.Frontmatter.Category)
	}
	if s.Frontmatter.Severity != "high" {
		t.Errorf("severity = %q", s.Frontmatter.Severity)
	}
	if s.Frontmatter.TokenBudget.Minimal != 100 || s.Frontmatter.TokenBudget.Compact != 400 || s.Frontmatter.TokenBudget.Full != 1200 {
		t.Errorf("token_budget mismatch: %+v", s.Frontmatter.TokenBudget)
	}
	if len(s.Body.Always) != 2 {
		t.Errorf("Always count = %d", len(s.Body.Always))
	}
	if len(s.Body.Never) != 1 {
		t.Errorf("Never count = %d", len(s.Body.Never))
	}
	if len(s.Body.KnownFalsePositives) != 1 {
		t.Errorf("KFP count = %d", len(s.Body.KnownFalsePositives))
	}
	if !strings.Contains(s.Body.Context, "This skill demonstrates") {
		t.Errorf("Context missing expected text: %q", s.Body.Context)
	}
	if !strings.Contains(s.Body.References, "test corpus") {
		t.Errorf("References missing expected text: %q", s.Body.References)
	}
}

func TestParseMissingClosingDelimiter(t *testing.T) {
	bad := "---\nid: x\nversion: \"1.0.0\"\ntitle: \"x\"\n# no closing ---\n"
	_, err := ParseBytes("bad.md", []byte(bad))
	if err == nil {
		t.Fatalf("expected error for missing closing ---")
	}
	if !strings.Contains(err.Error(), "frontmatter") {
		t.Errorf("error should mention frontmatter, got %v", err)
	}
}

func TestParseFrontmatterWithDashesInValues(t *testing.T) {
	// Description contains "---" inline. The line-anchored regex must NOT
	// terminate the frontmatter at a non-line-anchored occurrence.
	bodyWithInlineDashes := `---
id: inline-dash
version: "1.0.0"
title: "Inline dash"
description: "before --- after"
category: prevention
severity: medium
applies_to: ["a"]
languages: ["*"]
token_budget:
  minimal: 50
  compact: 200
  full: 500
last_updated: "2026-05-12"
sources: ["s"]
---

# Inline dash

## Rules (for AI agents)
### ALWAYS
- a
### NEVER
- b
### KNOWN FALSE POSITIVES
- c
## Context (for humans)
ctx
## References
ref
`
	s, err := ParseBytes("inline.md", []byte(bodyWithInlineDashes))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s.Frontmatter.Description != "before --- after" {
		t.Errorf("description not preserved: %q", s.Frontmatter.Description)
	}
}

func TestParseMissingRequiredFields(t *testing.T) {
	missingSeverity := `---
id: x
version: "1.0.0"
title: "x"
description: "x"
category: prevention
applies_to: ["a"]
languages: ["*"]
token_budget:
  minimal: 1
  compact: 2
  full: 3
last_updated: "2026-05-12"
sources: ["s"]
---
body
`
	_, err := ParseBytes("missing.md", []byte(missingSeverity))
	if err == nil {
		t.Fatalf("expected error for missing severity")
	}
	if !strings.Contains(err.Error(), "severity") {
		t.Errorf("error should mention severity, got %v", err)
	}
}

func TestParseInvalidCategory(t *testing.T) {
	bad := strings.Replace(validSkill, "category: prevention", "category: bogus", 1)
	_, err := ParseBytes("bad.md", []byte(bad))
	if err == nil {
		t.Fatalf("expected error for invalid category")
	}
	if !strings.Contains(err.Error(), "category") {
		t.Errorf("error should mention category, got %v", err)
	}
}

func TestParseInvalidSeverity(t *testing.T) {
	bad := strings.Replace(validSkill, "severity: high", "severity: ultra", 1)
	_, err := ParseBytes("bad.md", []byte(bad))
	if err == nil {
		t.Fatalf("expected error for invalid severity")
	}
	if !strings.Contains(err.Error(), "severity") {
		t.Errorf("error should mention severity, got %v", err)
	}
}

// TestParseRejectsEmptyListFields verifies ParseBytes' slice-emptiness
// parity with Validate: a SKILL.md declaring `applies_to: []`,
// `languages: []`, or `sources: []` has the key present (so the raw-map
// check passes) but no entries, which has the same semantic meaning as
// the key being absent. Both shapes must be rejected uniformly.
func TestParseRejectsEmptyListFields(t *testing.T) {
	cases := []struct {
		name    string
		find    string
		replace string
		wantMsg string
	}{
		{
			"empty applies_to",
			"applies_to:\n  - \"before every commit\"",
			"applies_to: []",
			"applies_to must list at least one entry",
		},
		{
			"empty languages",
			`languages: ["*"]`,
			`languages: []`,
			"languages must list at least one entry",
		},
		{
			"empty sources",
			"sources:\n  - \"Test source\"",
			"sources: []",
			"sources must list at least one entry",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := strings.Replace(validSkill, tc.find, tc.replace, 1)
			if doc == validSkill {
				t.Fatalf("setup: failed to swap %q in validSkill fixture", tc.find)
			}
			_, err := ParseBytes("bad.md", []byte(doc))
			if err == nil {
				t.Fatalf("ParseBytes accepted %s; want error containing %q", tc.name, tc.wantMsg)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("ParseBytes error for %s = %v, want substring %q", tc.name, err, tc.wantMsg)
			}
		})
	}
}

// TestValidateAccumulatesAllDefects pins the accumulator contract:
// when a Skill has multiple defects, Validate must report every one
// of them in a single returned error (joined via errors.Join) so a
// caller fixing the typed Skill can address everything in one pass,
// matching sdk/go.Validate's collect-all behavior.
func TestValidateAccumulatesAllDefects(t *testing.T) {
	good, err := ParseBytes("skills/example-skill/SKILL.md", []byte(validSkill))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	s := *good
	// Three distinct defects in unrelated fields.
	s.Frontmatter.Title = ""
	s.Frontmatter.Category = "nonsense"
	s.Frontmatter.TokenBudget.Minimal = 0

	verr := s.Validate()
	if verr == nil {
		t.Fatalf("Validate accepted skill with 3 defects; want a joined error")
	}
	msg := verr.Error()
	wants := []string{
		"missing title",
		"invalid category \"nonsense\"",
		"token_budget",
	}
	for _, want := range wants {
		if !strings.Contains(msg, want) {
			t.Errorf("accumulated Validate error missing substring %q; got %v", want, verr)
		}
	}
	// errors.Join also exposes the individual errors via Unwrap() []error.
	type multiError interface{ Unwrap() []error }
	if multi, ok := verr.(multiError); !ok {
		t.Errorf("Validate result is not a multi-error (no Unwrap() []error); got %T", verr)
	} else if got := len(multi.Unwrap()); got != 3 {
		t.Errorf("Validate accumulated %d errors; want 3", got)
	}
}

// TestValidateEmptyEnumReportsOneError pins the no-double-reporting
// contract: an empty Category must surface as "missing category" only,
// never as both "missing category" and "invalid category \"\"". Same
// for Severity.
func TestValidateEmptyEnumReportsOneError(t *testing.T) {
	good, err := ParseBytes("skills/example-skill/SKILL.md", []byte(validSkill))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, field := range []string{"category", "severity"} {
		t.Run("empty "+field, func(t *testing.T) {
			s := *good
			switch field {
			case "category":
				s.Frontmatter.Category = ""
			case "severity":
				s.Frontmatter.Severity = ""
			}
			verr := s.Validate()
			if verr == nil {
				t.Fatalf("Validate accepted empty %s; want missing-%s error", field, field)
			}
			msg := verr.Error()
			if !strings.Contains(msg, "missing "+field) {
				t.Errorf("Validate error for empty %s = %v, want substring %q", field, verr, "missing "+field)
			}
			if strings.Contains(msg, "invalid "+field+" \"\"") {
				t.Errorf("Validate double-reported empty %s as 'invalid X \"\"'; got %v", field, verr)
			}
		})
	}
}

func TestBodySectionExtraction(t *testing.T) {
	s, err := ParseBytes("example.md", []byte(validSkill))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s.Body.Title != "Example Skill" {
		t.Errorf("body title %q", s.Body.Title)
	}
	if !strings.Contains(s.Body.RawRules, "ALWAYS") {
		t.Errorf("RawRules missing ALWAYS section")
	}
	if !strings.Contains(s.Body.RawRules, "KNOWN FALSE POSITIVES") {
		t.Errorf("RawRules missing KFP section")
	}
}

func TestTierExtraction(t *testing.T) {
	s, err := ParseBytes("example.md", []byte(validSkill))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	minimal := s.Extract(TierMinimal)
	compact := s.Extract(TierCompact)
	full := s.Extract(TierFull)

	if !strings.Contains(minimal, "Always do thing one.") {
		t.Errorf("minimal missing always bullet:\n%s", minimal)
	}
	if !strings.Contains(minimal, "Never do bad thing.") {
		t.Errorf("minimal missing never bullet")
	}
	if strings.Contains(minimal, "Ignore harmless variant.") {
		t.Errorf("minimal should NOT contain KFP bullet")
	}
	if !strings.Contains(compact, "Ignore harmless variant.") {
		t.Errorf("compact missing KFP bullet")
	}
	if strings.Contains(compact, "demonstrates the parser") {
		t.Errorf("compact should NOT contain Context block")
	}
	if !strings.Contains(full, "demonstrates the parser") {
		t.Errorf("full missing Context block")
	}
	if len(full) <= len(compact) || len(compact) <= len(minimal) {
		t.Errorf("expected minimal < compact < full, got %d / %d / %d", len(minimal), len(compact), len(full))
	}
}

func TestExtractWithHeading(t *testing.T) {
	s, _ := ParseBytes("example.md", []byte(validSkill))
	out := s.ExtractWithHeading(TierCompact)
	if !strings.HasPrefix(out, "## Example Skill") {
		t.Errorf("ExtractWithHeading should start with title heading, got %q", out[:50])
	}
}

func TestIsValidTier(t *testing.T) {
	cases := map[string]bool{
		"minimal": true,
		"compact": true,
		"full":    true,
		"":        false,
		"unknown": false,
		"COMPACT": false,
	}
	for in, want := range cases {
		if got := IsValidTier(in); got != want {
			t.Errorf("IsValidTier(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestValidateMirrorsParseBytes ensures Skill.Validate() catches every kind
// of frontmatter defect that ParseBytes catches — required-field presence,
// allowlists, and TokenBudget positives — so callers constructing a Skill
// outside the parser cannot bypass validation.
func TestValidateMirrorsParseBytes(t *testing.T) {
	// Start from a fully valid Skill, then mutate one field at a time.
	good, err := ParseBytes("skills/example-skill/SKILL.md", []byte(validSkill))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("baseline Validate failed: %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(s *Skill)
		wantMsg string
	}{
		{"missing id", func(s *Skill) { s.Frontmatter.ID = "" }, "missing id"},
		{"missing version", func(s *Skill) { s.Frontmatter.Version = "" }, "missing version"},
		{"missing title", func(s *Skill) { s.Frontmatter.Title = "" }, "missing title"},
		{"missing description", func(s *Skill) { s.Frontmatter.Description = "" }, "missing description"},
		{"missing last_updated", func(s *Skill) { s.Frontmatter.LastUpdated = "" }, "missing last_updated"},
		{"empty applies_to", func(s *Skill) { s.Frontmatter.AppliesTo = nil }, "applies_to"},
		{"empty languages", func(s *Skill) { s.Frontmatter.Languages = nil }, "languages"},
		{"empty sources", func(s *Skill) { s.Frontmatter.Sources = nil }, "sources"},
		{"bad category", func(s *Skill) { s.Frontmatter.Category = "nonsense" }, "invalid category"},
		{"bad severity", func(s *Skill) { s.Frontmatter.Severity = "spicy" }, "invalid severity"},
		{"zero minimal budget", func(s *Skill) { s.Frontmatter.TokenBudget.Minimal = 0 }, "token_budget"},
		{"zero compact budget", func(s *Skill) { s.Frontmatter.TokenBudget.Compact = 0 }, "token_budget"},
		{"zero full budget", func(s *Skill) { s.Frontmatter.TokenBudget.Full = 0 }, "token_budget"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Shallow struct copy is enough — every mutation below either
			// replaces a scalar or clears a slice header; nothing writes
			// through the shared backing arrays.
			s := *good
			tc.mutate(&s)
			err := s.Validate()
			if err == nil {
				t.Fatalf("Validate accepted %s; want error containing %q", tc.name, tc.wantMsg)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("Validate error for %s = %v, want substring %q", tc.name, err, tc.wantMsg)
			}
		})
	}
}

// TestValidateEmptyEnumsReportMissing verifies that empty-string Category /
// Severity surface as "missing X" rather than "invalid X", matching the
// wording ParseBytes uses for absent YAML keys. The allowlist check still
// catches the *invalid-non-empty* case, exercised separately in
// TestValidateMirrorsParseBytes.
func TestValidateEmptyEnumsReportMissing(t *testing.T) {
	good, err := ParseBytes("skills/example-skill/SKILL.md", []byte(validSkill))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(s *Skill)
		wantMsg string
	}{
		{"empty category", func(s *Skill) { s.Frontmatter.Category = "" }, "missing category"},
		{"empty severity", func(s *Skill) { s.Frontmatter.Severity = "" }, "missing severity"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := *good
			tc.mutate(&s)
			err := s.Validate()
			if err == nil {
				t.Fatalf("Validate accepted %s; want %q", tc.name, tc.wantMsg)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("Validate error for %s = %v, want substring %q", tc.name, err, tc.wantMsg)
			}
			if strings.Contains(err.Error(), "invalid") {
				t.Errorf("Validate error for %s should say 'missing', not 'invalid': %v", tc.name, err)
			}
		})
	}
}

// TestValidateInvalidEnumMatchesParseBytes pins the wording-alignment
// contract: when given the same invalid category / severity value,
// Validate's error must contain the same "(allowed: ...)" allowed-set
// suffix ParseBytes emits, so users hitting the same defect via either
// code path see equivalent guidance.
func TestValidateInvalidEnumMatchesParseBytes(t *testing.T) {
	cases := []struct {
		name       string
		swapKey    string
		swapValue  string
		wantSuffix string
	}{
		{
			"bad category",
			"category: prevention",
			"category: nonsense",
			"(allowed: prevention, detection, compliance, supply-chain, hardening)",
		},
		{
			"bad severity",
			"severity: high",
			"severity: spicy",
			"(allowed: critical, high, medium, low)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := strings.Replace(validSkill, tc.swapKey, tc.swapValue, 1)
			if doc == validSkill {
				t.Fatalf("setup: failed to swap %q in validSkill fixture", tc.swapKey)
			}

			// ParseBytes path.
			_, parseErr := ParseBytes("bad.md", []byte(doc))
			if parseErr == nil {
				t.Fatalf("ParseBytes accepted %s; want error containing %q", tc.name, tc.wantSuffix)
			}
			if !strings.Contains(parseErr.Error(), tc.wantSuffix) {
				t.Errorf("ParseBytes error for %s = %v, want suffix %q", tc.name, parseErr, tc.wantSuffix)
			}

			// Validate path — same fixture, route through ParseBytes
			// with the allowlist temporarily relaxed so we land on a
			// typed Skill carrying the invalid value, then call
			// Validate.
			good, err := ParseBytes("skills/example-skill/SKILL.md", []byte(validSkill))
			if err != nil {
				t.Fatalf("setup parse: %v", err)
			}
			s := *good
			switch tc.name {
			case "bad category":
				s.Frontmatter.Category = "nonsense"
			case "bad severity":
				s.Frontmatter.Severity = "spicy"
			}
			validateErr := s.Validate()
			if validateErr == nil {
				t.Fatalf("Validate accepted %s; want error containing %q", tc.name, tc.wantSuffix)
			}
			if !strings.Contains(validateErr.Error(), tc.wantSuffix) {
				t.Errorf("Validate error for %s = %v, want suffix %q (must match ParseBytes wording)", tc.name, validateErr, tc.wantSuffix)
			}
		})
	}
}
