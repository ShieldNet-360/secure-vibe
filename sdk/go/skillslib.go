// Package skillslib is the public Go SDK for the Skills Library.
//
// This package is a thin re-export over the existing internal/skill loader so
// downstream Go programs (Devin agents, custom IDE bridges, security
// dashboards) can load and validate skills without depending on internal
// packages.
//
// Stability: the function signatures here are part of the public API
// surface. The structs they return live under the existing
// github.com/shieldnet-360/secure-vibe/internal/skill package and are
// intentionally re-exported as aliases so a single source of truth defines
// the schema.
package skillslib

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/shieldnet-360/secure-vibe/internal/skill"
)

var (
	skillIDRegex = regexp.MustCompile(`^[a-z][a-z0-9-]{1,63}$`)
	semverRegex  = regexp.MustCompile(`^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
)

// Skill is the parsed representation of a skills/<id>/SKILL.md file. It
// carries both the YAML frontmatter and the prose body.
type Skill = skill.Skill

// Frontmatter is the YAML metadata at the top of a SKILL.md file.
type Frontmatter = skill.Frontmatter

// Tier names the three packaging budgets supported by the library:
// "minimal", "compact", and "full".
type Tier = skill.Tier

const (
	TierMinimal Tier = skill.TierMinimal
	TierCompact Tier = skill.TierCompact
	TierFull    Tier = skill.TierFull
)

// LoadSkill parses a single SKILL.md file from disk and returns the typed
// Skill struct.
func LoadSkill(path string) (*Skill, error) {
	return skill.Parse(path)
}

// LoadAll walks a `skills/` directory tree and returns every parsed
// SKILL.md file it finds.
func LoadAll(dir string) ([]*Skill, error) {
	return skill.LoadAll(dir)
}

// Validate runs the same schema checks the CLI's `secure-vibe dev validate`
// command runs against a single skill, plus the broader cross-SDK schema
// checks performed by the Python and TypeScript SDKs (semver-shape
// version, non-empty title/description/languages/last_updated, positive
// token_budget values for all three tiers, and a non-empty rule body).
// It returns a slice of errors, one per violation, so callers can present
// every issue at once. An empty slice means the skill is valid.
//
// This function is intentionally stricter than internal/skill.(*Skill).
// Validate(): the internal validator runs at Parse() time and only checks
// the fields it strictly needs to render content. Programmatically
// constructed Skills (not loaded from disk via LoadSkill) bypass Parse()'s
// implicit checks, so the SDK applies them explicitly here to keep the
// Go, Python, and TypeScript SDK contracts identical.
func Validate(s *Skill) []error {
	if s == nil {
		return []error{errNilSkill}
	}
	var errs []error
	fm := s.Frontmatter
	if !skillIDRegex.MatchString(fm.ID) {
		errs = append(errs, fmt.Errorf("id %q must match ^[a-z][a-z0-9-]{1,63}$", fm.ID))
	}
	if !semverRegex.MatchString(fm.Version) {
		errs = append(errs, fmt.Errorf("version %q is not valid semver", fm.Version))
	}
	if strings.TrimSpace(fm.Title) == "" {
		errs = append(errs, fmt.Errorf("title is required"))
	}
	if strings.TrimSpace(fm.Description) == "" {
		errs = append(errs, fmt.Errorf("description is required"))
	}
	if !skill.AllowedCategories[fm.Category] {
		errs = append(errs, fmt.Errorf("category %q must be one of [compliance detection hardening prevention supply-chain]", fm.Category))
	}
	if !skill.AllowedSeverities[fm.Severity] {
		errs = append(errs, fmt.Errorf("severity %q must be one of [critical high low medium]", fm.Severity))
	}
	if len(fm.Languages) == 0 {
		errs = append(errs, fmt.Errorf("languages must list at least one language id (or ['*'])"))
	}
	if fm.TokenBudget.Minimal <= 0 {
		errs = append(errs, fmt.Errorf("token_budget.minimal must be > 0"))
	}
	if fm.TokenBudget.Compact <= 0 {
		errs = append(errs, fmt.Errorf("token_budget.compact must be > 0"))
	}
	if fm.TokenBudget.Full <= 0 {
		errs = append(errs, fmt.Errorf("token_budget.full must be > 0"))
	}
	if strings.TrimSpace(fm.LastUpdated) == "" {
		errs = append(errs, fmt.Errorf("last_updated is required"))
	}
	if isBodyEmpty(s.Body) {
		errs = append(errs, fmt.Errorf("SKILL body is empty"))
	}
	return errs
}

// isBodyEmpty reports whether the parsed Body carries no rule content.
// Mirrors the Python/TypeScript SDKs' `if not skill.body.strip()` check,
// adapted for Go's structured Body (which is a parsed AST rather than the
// raw markdown string the other SDKs hold).
func isBodyEmpty(b skill.Body) bool {
	return len(b.Always) == 0 &&
		len(b.Never) == 0 &&
		len(b.KnownFalsePositives) == 0 &&
		strings.TrimSpace(b.Context) == "" &&
		strings.TrimSpace(b.References) == "" &&
		strings.TrimSpace(b.RawRules) == ""
}

// Extract returns the rendered SKILL.md body for the given tier (minimal /
// compact / full). The result is suitable for direct injection into an LLM
// prompt or for compiling into an IDE-specific configuration file.
func Extract(s *Skill, tier Tier) string {
	if s == nil {
		return ""
	}
	return s.Extract(tier)
}
