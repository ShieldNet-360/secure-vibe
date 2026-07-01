// Package skill parses SKILL.md files into typed structures.
//
// A SKILL.md file consists of a YAML frontmatter block (delimited by `---`
// lines, anchored at the start of the file) followed by a markdown body. The
// body must contain three top-level sections in this order:
//
//	## Rules (for AI agents)
//	## Context (for humans)
//	## References
//
// The Rules section must contain `### ALWAYS`, `### NEVER`, and
// `### KNOWN FALSE POSITIVES` subsections. The parser exposes tier extraction
// helpers (Minimal, Compact, Full) that mirror the compiler's expectations.
package skill

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// FrontmatterRegex is the same line-anchored pattern used by the CI validator.
var FrontmatterRegex = regexp.MustCompile(`(?s)\A---\s*\n(.*?)\n---\s*(?:\n|\z)`)

// TokenBudget declares the token budgets for each tier of a skill.
type TokenBudget struct {
	Minimal int `yaml:"minimal"`
	Compact int `yaml:"compact"`
	Full    int `yaml:"full"`
}

// Frontmatter is the typed view of the YAML frontmatter block.
type Frontmatter struct {
	ID            string      `yaml:"id"`
	Version       string      `yaml:"version"`
	Title         string      `yaml:"title"`
	Description   string      `yaml:"description"`
	Category      string      `yaml:"category"`
	Severity      string      `yaml:"severity"`
	AppliesTo     []string    `yaml:"applies_to"`
	Languages     []string    `yaml:"languages"`
	TokenBudget   TokenBudget `yaml:"token_budget"`
	RulesPath     string      `yaml:"rules_path,omitempty"`
	TestsPath     string      `yaml:"tests_path,omitempty"`
	RelatedSkills []string    `yaml:"related_skills,omitempty"`
	LastUpdated   string      `yaml:"last_updated"`
	Sources       []string    `yaml:"sources"`
	// ExternalTools lists industry-standard CLIs the skill recommends
	// running (via the shell) for deeper coverage than the built-in
	// scanners — e.g. gitleaks for secrets, hadolint for Dockerfiles.
	// This is the single source of truth: the pointer-file generator
	// lifts these into the always-loaded CLAUDE.md so the agent sees
	// them every session without having to fetch the skill body.
	ExternalTools []ExternalTool `yaml:"external_tools,omitempty"`
}

// ExternalTool is one recommended external CLI declared by a skill.
// Only Name and Purpose surface in the generated pointer file; Command
// is kept as on-disk documentation for a human reading the SKILL.md.
type ExternalTool struct {
	Name    string `yaml:"name"`
	Purpose string `yaml:"purpose,omitempty"`
	Command string `yaml:"command,omitempty"`
}

// Body contains the parsed markdown body subsections.
type Body struct {
	Title               string
	Always              []string
	Never               []string
	KnownFalsePositives []string
	Context             string
	References          string
	RawRules            string
}

// Skill is the parsed SKILL.md file.
type Skill struct {
	Path        string
	Frontmatter Frontmatter
	Body        Body
}

// AllowedCategories enumerates the only valid `category` values.
var AllowedCategories = map[string]bool{
	"prevention":   true,
	"detection":    true,
	"compliance":   true,
	"supply-chain": true,
	"hardening":    true,
}

// AllowedSeverities enumerates the only valid `severity` values.
var AllowedSeverities = map[string]bool{
	"critical": true,
	"high":     true,
	"medium":   true,
	"low":      true,
}

// requiredFields are checked by Validate (mirrors the CI validator).
var requiredFields = []string{
	"id", "version", "title", "description", "category",
	"severity", "applies_to", "languages", "token_budget",
	"last_updated", "sources",
}

// Parse reads a SKILL.md file and returns the typed Skill.
func Parse(path string) (*Skill, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ParseBytes(path, data)
}

// ParseBytes parses raw SKILL.md bytes.
func ParseBytes(path string, data []byte) (*Skill, error) {
	match := FrontmatterRegex.FindSubmatch(data)
	if match == nil {
		return nil, fmt.Errorf("%s: missing or malformed YAML frontmatter (expected leading and closing '---' lines)", path)
	}

	// Use a raw node first so we can detect missing fields by key presence,
	// not just zero-value comparison.
	var raw map[string]any
	if err := yaml.Unmarshal(match[1], &raw); err != nil {
		return nil, fmt.Errorf("%s: invalid YAML frontmatter: %w", path, err)
	}

	missing := make([]string, 0)
	for _, f := range requiredFields {
		if _, ok := raw[f]; !ok {
			missing = append(missing, f)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("%s: missing required frontmatter fields: %v", path, missing)
	}

	var fm Frontmatter
	if err := yaml.Unmarshal(match[1], &fm); err != nil {
		return nil, fmt.Errorf("%s: frontmatter does not match schema: %w", path, err)
	}

	if !AllowedCategories[fm.Category] {
		return nil, fmt.Errorf("%s: invalid category %q (allowed: prevention, detection, compliance, supply-chain, hardening)", path, fm.Category)
	}
	if !AllowedSeverities[fm.Severity] {
		return nil, fmt.Errorf("%s: invalid severity %q (allowed: critical, high, medium, low)", path, fm.Severity)
	}
	// Slice-emptiness parity with Validate: ParseBytes' key-presence check
	// above accepts a file declaring `applies_to: []` (the key is present);
	// but an empty slice has the same semantic meaning as a missing key
	// ("the skill applies to nothing"), so we reject both shapes uniformly.
	if len(fm.AppliesTo) == 0 {
		return nil, fmt.Errorf("%s: applies_to must list at least one entry", path)
	}
	if len(fm.Languages) == 0 {
		return nil, fmt.Errorf("%s: languages must list at least one entry", path)
	}
	if len(fm.Sources) == 0 {
		return nil, fmt.Errorf("%s: sources must list at least one entry", path)
	}
	if fm.TokenBudget.Minimal <= 0 || fm.TokenBudget.Compact <= 0 || fm.TokenBudget.Full <= 0 {
		return nil, fmt.Errorf("%s: token_budget must declare positive minimal, compact, and full counts", path)
	}

	body := data[len(match[0]):]
	parsed := parseBody(string(body))

	return &Skill{
		Path:        path,
		Frontmatter: fm,
		Body:        parsed,
	}, nil
}

// LoadAll walks a `skills/` root and returns every parsed SKILL.md.
func LoadAll(root string) ([]*Skill, error) {
	skills := make([]*Skill, 0)
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Base(p) != "SKILL.md" {
			return nil
		}
		s, err := Parse(p)
		if err != nil {
			return err
		}
		skills = append(skills, s)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(skills, func(i, j int) bool {
		return skills[i].Frontmatter.ID < skills[j].Frontmatter.ID
	})
	return skills, nil
}

// parseBody walks the markdown body and extracts the three top-level sections.
//
// Body extraction is keyed on the English section headers "## Rules",
// "## Context", and "## References".
func parseBody(body string) Body {
	out := Body{}
	lines := strings.Split(body, "\n")

	type section int
	const (
		secNone section = iota
		secTitle
		secRules
		secContext
		secRefs
	)

	type subsection int
	const (
		subNone subsection = iota
		subAlways
		subNever
		subFalsePositives
	)

	cur := secNone
	sub := subNone
	var rulesLines, contextLines, refLines []string

	flushBullet := func(line string) (string, bool) {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "* ") {
			return strings.TrimSpace(trimmed[2:]), true
		}
		return "", false
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "# "):
			out.Title = strings.TrimSpace(trimmed[2:])
			cur = secTitle
			sub = subNone
			continue
		case strings.HasPrefix(trimmed, "## Rules"):
			cur = secRules
			sub = subNone
			continue
		case strings.HasPrefix(trimmed, "## Context"):
			cur = secContext
			sub = subNone
			continue
		case strings.HasPrefix(trimmed, "## References"):
			cur = secRefs
			sub = subNone
			continue
		case strings.HasPrefix(trimmed, "## "):
			// Unknown top-level section; ignore but reset.
			cur = secNone
			sub = subNone
			continue
		}

		if cur == secRules {
			rulesLines = append(rulesLines, line)
			switch {
			case strings.HasPrefix(trimmed, "### ALWAYS"):
				sub = subAlways
				continue
			case strings.HasPrefix(trimmed, "### NEVER"):
				sub = subNever
				continue
			case strings.HasPrefix(trimmed, "### KNOWN FALSE POSITIVES"):
				sub = subFalsePositives
				continue
			case strings.HasPrefix(trimmed, "### "):
				sub = subNone
				continue
			}
			if bullet, ok := flushBullet(line); ok {
				switch sub {
				case subAlways:
					out.Always = append(out.Always, bullet)
				case subNever:
					out.Never = append(out.Never, bullet)
				case subFalsePositives:
					out.KnownFalsePositives = append(out.KnownFalsePositives, bullet)
				}
			} else if sub != subNone && trimmed != "" {
				target := pickList(&out, int(sub))
				if target != nil && len(*target) > 0 {
					(*target)[len(*target)-1] = strings.TrimSpace((*target)[len(*target)-1] + " " + trimmed)
				}
			}
		}

		if cur == secContext {
			contextLines = append(contextLines, line)
		}
		if cur == secRefs {
			refLines = append(refLines, line)
		}
	}

	out.RawRules = strings.TrimSpace(strings.Join(rulesLines, "\n"))
	out.Context = strings.TrimSpace(strings.Join(contextLines, "\n"))
	out.References = strings.TrimSpace(strings.Join(refLines, "\n"))
	return out
}

func pickList(b *Body, sub int) *[]string {
	switch sub {
	case int(1):
		return &b.Always
	case int(2):
		return &b.Never
	case int(3):
		return &b.KnownFalsePositives
	}
	return nil
}

// Tier identifies which token-budget tier to extract.
type Tier string

const (
	TierMinimal Tier = "minimal"
	TierCompact Tier = "compact"
	TierFull    Tier = "full"
)

// IsValidTier reports whether the given string is a known tier.
func IsValidTier(t string) bool {
	switch Tier(t) {
	case TierMinimal, TierCompact, TierFull:
		return true
	}
	return false
}

// Extract renders the rule content for the requested tier. The output
// intentionally omits the skill title and description — those are formatter
// concerns. Token counts produced from this function measure the rule body
// only, matching the budgets declared in the SKILL.md frontmatter.
//
//	minimal: ALWAYS + NEVER bullets
//	compact: ALWAYS + NEVER + KNOWN FALSE POSITIVES + References
//	full:    everything (adds Context)
//
// Use ExtractWithHeading when you also want a skill heading prepended for
// display formatters; per-skill token counting uses the bare Extract output so
// formatter chrome does not push a skill over its declared budget.
func (s *Skill) Extract(tier Tier) string {
	var b strings.Builder
	switch tier {
	case TierMinimal:
		writeBullets(&b, "ALWAYS", s.Body.Always)
		writeBullets(&b, "NEVER", s.Body.Never)
	case TierCompact:
		writeBullets(&b, "ALWAYS", s.Body.Always)
		writeBullets(&b, "NEVER", s.Body.Never)
		writeBullets(&b, "KNOWN FALSE POSITIVES", s.Body.KnownFalsePositives)
		if s.Body.References != "" {
			b.WriteString("### References\n")
			b.WriteString(s.Body.References)
			b.WriteString("\n")
		}
	case TierFull:
		writeBullets(&b, "ALWAYS", s.Body.Always)
		writeBullets(&b, "NEVER", s.Body.Never)
		writeBullets(&b, "KNOWN FALSE POSITIVES", s.Body.KnownFalsePositives)
		if s.Body.Context != "" {
			b.WriteString("### Context\n")
			b.WriteString(s.Body.Context)
			b.WriteString("\n\n")
		}
		if s.Body.References != "" {
			b.WriteString("### References\n")
			b.WriteString(s.Body.References)
			b.WriteString("\n")
		}
	}
	return strings.TrimSpace(b.String()) + "\n"
}

// ExtractWithHeading prepends a "## Title" heading and italicized description
// before the tier content, suitable for direct concatenation in display
// formatters.
func (s *Skill) ExtractWithHeading(tier Tier) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## %s\n\n", s.Frontmatter.Title)
	fmt.Fprintf(&b, "_%s_\n\n", s.Frontmatter.Description)
	b.WriteString(s.Extract(tier))
	return b.String()
}

// patternMarkerStrip removes the build-time `<!-- pattern: { ... } -->`
// markers from a rendered bullet. Those markers are the scanner
// contract consumed by derive-checklists and the gate's trace test
// (which read the raw SKILL.md); an agent loading the rendered skill
// never needs to see them or pay tokens for them.
var patternMarkerStrip = regexp.MustCompile(`\s*<!--\s*pattern\s*:\s*\{[^}]*\}\s*-->`)

// StripBodyMarkers removes the build-time pattern markers from a single
// body bullet. Exposed so the compiler can render marker-free dist
// output that matches what Extract already counts; derive-checklists and
// the gate's trace test read the raw SKILL.md and are unaffected.
func StripBodyMarkers(line string) string {
	return strings.TrimSpace(patternMarkerStrip.ReplaceAllString(line, ""))
}

func writeBullets(b *strings.Builder, label string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(b, "### %s\n", label)
	for _, item := range items {
		item = strings.TrimSpace(patternMarkerStrip.ReplaceAllString(item, ""))
		fmt.Fprintf(b, "- %s\n", item)
	}
	b.WriteString("\n")
}

// Validate checks a Skill that may have been constructed outside the parser
// (e.g. built in code, decoded from a non-YAML cache, or rebuilt by a
// downstream tool).
//
// Validate is *at least as strict* as ParseBytes: every defect ParseBytes
// rejects on a SKILL.md file, Validate also rejects on the typed Skill.
// It is strictly stricter for one case ParseBytes cannot see on the raw
// YAML — empty strings for required scalars. On a typed Frontmatter we
// cannot distinguish "key missing" from "key present but empty," and
// either way the field has no usable value, so we reject both.
//
// Validate accumulates every defect into a single error (joined via
// errors.Join) instead of returning the first failure. This matches
// sdk/go.Validate's behavior and lets callers see every problem in
// one pass instead of fix-one-rerun-fix-another.
//
// If you add or change a check here, mirror the corresponding check in
// ParseBytes and vice versa.
func (s *Skill) Validate() error {
	fm := s.Frontmatter
	var errs []error

	// Required scalar fields. We treat an empty string as "missing" since
	// the typed view cannot distinguish absent-from-YAML from
	// present-but-empty. This intentionally produces a "missing X" error
	// (matching the wording ParseBytes uses for raw-map absence) rather
	// than "invalid X".
	if fm.ID == "" {
		errs = append(errs, fmt.Errorf("%s: missing id", s.Path))
	}
	if fm.Version == "" {
		errs = append(errs, fmt.Errorf("%s: missing version", s.Path))
	}
	if fm.Title == "" {
		errs = append(errs, fmt.Errorf("%s: missing title", s.Path))
	}
	if fm.Description == "" {
		errs = append(errs, fmt.Errorf("%s: missing description", s.Path))
	}
	if fm.Category == "" {
		errs = append(errs, fmt.Errorf("%s: missing category", s.Path))
	}
	if fm.Severity == "" {
		errs = append(errs, fmt.Errorf("%s: missing severity", s.Path))
	}
	if fm.LastUpdated == "" {
		errs = append(errs, fmt.Errorf("%s: missing last_updated", s.Path))
	}
	// Required slice fields.
	if len(fm.AppliesTo) == 0 {
		errs = append(errs, fmt.Errorf("%s: applies_to must list at least one entry", s.Path))
	}
	if len(fm.Languages) == 0 {
		errs = append(errs, fmt.Errorf("%s: languages must list at least one entry", s.Path))
	}
	if len(fm.Sources) == 0 {
		errs = append(errs, fmt.Errorf("%s: sources must list at least one entry", s.Path))
	}
	// Allowlist checks for non-empty enum-style fields. Error messages
	// include the allowed-set suffix to match ParseBytes. We skip the
	// allowlist check when the value is empty so the user sees a single
	// "missing X" error rather than both "missing X" and "invalid X \"\"".
	if fm.Category != "" && !AllowedCategories[fm.Category] {
		errs = append(errs, fmt.Errorf("%s: invalid category %q (allowed: prevention, detection, compliance, supply-chain, hardening)", s.Path, fm.Category))
	}
	if fm.Severity != "" && !AllowedSeverities[fm.Severity] {
		errs = append(errs, fmt.Errorf("%s: invalid severity %q (allowed: critical, high, medium, low)", s.Path, fm.Severity))
	}
	// Numeric / structural checks.
	if fm.TokenBudget.Minimal <= 0 || fm.TokenBudget.Compact <= 0 || fm.TokenBudget.Full <= 0 {
		errs = append(errs, fmt.Errorf("%s: token_budget must declare positive minimal, compact, and full counts", s.Path))
	}
	return errors.Join(errs...)
}
