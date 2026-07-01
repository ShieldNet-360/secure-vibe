// Package compiler renders parsed skills into IDE-specific configuration
// files. Each supported tool has its own Formatter; the core Compile loop is
// the pure function (skills, tool, budget) -> rendered string + token report.
package compiler

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/shieldnet-360/secure-vibe/cmd/secure-vibe/internal/token"
	"github.com/shieldnet-360/secure-vibe/internal/skill"
)

// Formatter renders the provided skills into a single string at the requested
// tier. Implementations should be deterministic for the same input.
type Formatter interface {
	Name() string
	OutputName() string
	DefaultTier() skill.Tier
	Format(skills []*skill.Skill, tier skill.Tier, ctx Context) string
}

// Context carries optional injected content (vulnerability summary, glossary
// entries) that formatters may include.
type Context struct {
	VulnerabilitySummary string
	GlossaryEntries      []string
	AttackTechniques     []string
	// FullInline opts every per-tool dist/ file (CLAUDE.md,
	// .cursorrules, copilot-instructions.md, AGENTS.md, devin.md,
	// .windsurfrules, .clinerules) back into the pre-v2 behaviour
	// of inlining every skill body. The default — when this field
	// is false — emits a minimal <4 KiB pointer file per tool that
	// refers consumers to the MCP server and the on-disk skills/
	// directory. The CLI exposes this as `regenerate --full-inline`
	// (alias `--legacy`).
	//
	// The universal SECURITY-SKILLS.md output is unaffected by this
	// flag; it remains the canonical full-inline reference for
	// users who want every skill body in a single file regardless
	// of tool surface.
	FullInline bool

	// AgentsFullInline is the legacy alias for FullInline. It only
	// affected the AGENTS.md formatter in v2; callers should
	// migrate to FullInline. Either field set to true triggers the
	// monolithic output across every per-tool formatter.
	//
	// Deprecated: use FullInline. Removed once external callers
	// have migrated.
	AgentsFullInline bool
}

// fullInline reports whether either the new or legacy flag is set.
// Formatters and tests should call this helper instead of reading
// the fields directly.
func (c Context) fullInline() bool {
	return c.FullInline || c.AgentsFullInline
}

// Report is the per-skill + total token accounting for a compiled output.
type Report struct {
	Tool       string
	Tier       skill.Tier
	Total      token.Counts
	PerSkill   map[string]token.Counts
	BudgetSums map[string]int
}

// Registry maps tool ID -> Formatter. Adding a new tool requires registering
// here and writing a formatter in the same package.
var Registry = map[string]Formatter{
	"claude":    claudeFormatter{},
	"cursor":    cursorFormatter{},
	"copilot":   copilotFormatter{},
	"agents":    agentsFormatter{},
	"codex":     agentsFormatter{}, // codex consumes AGENTS.md
	"windsurf":  windsurfFormatter{},
	"devin":     devinFormatter{},
	"cline":     clineFormatter{},
	"universal": universalFormatter{},
}

// AllTools returns the canonical-named formatters (the 8 distribution files).
// "codex" is an alias for "agents" and is not enumerated here.
func AllTools() []Formatter {
	names := []string{"claude", "cursor", "copilot", "agents", "windsurf", "devin", "cline", "universal"}
	out := make([]Formatter, 0, len(names))
	for _, n := range names {
		out = append(out, Registry[n])
	}
	return out
}

// Compile runs a single formatter end-to-end. It returns the rendered string,
// a token report, and any non-fatal warning text.
func Compile(skills []*skill.Skill, tool string, tier skill.Tier, ctx Context) (string, *Report, []string, error) {
	f, ok := Registry[tool]
	if !ok {
		return "", nil, nil, fmt.Errorf("unknown tool %q (valid: %s)", tool, strings.Join(sortedKeys(Registry), ", "))
	}
	if tier == "" {
		tier = f.DefaultTier()
	}
	if !skill.IsValidTier(string(tier)) {
		return "", nil, nil, fmt.Errorf("invalid tier %q (valid: minimal, compact, full)", tier)
	}

	sortSkills(skills)
	// Render against marker-free copies so the build-time pattern
	// markers never reach dist output or the token counts; the raw
	// SKILL.md (read by derive-checklists and the gate's trace test)
	// keeps them.
	skills = stripSkillMarkers(skills)
	out := f.Format(skills, tier, ctx)

	report := &Report{
		Tool:       f.Name(),
		Tier:       tier,
		PerSkill:   make(map[string]token.Counts),
		BudgetSums: make(map[string]int),
	}
	for _, s := range skills {
		section := s.Extract(tier)
		c, err := token.Count(section)
		if err != nil {
			return "", nil, nil, err
		}
		report.PerSkill[s.Frontmatter.ID] = c
		report.BudgetSums[s.Frontmatter.ID] = budgetFor(s, tier)
	}
	total, err := token.Count(out)
	if err != nil {
		return "", nil, nil, err
	}
	report.Total = total

	warnings := make([]string, 0)
	for _, s := range skills {
		limit := budgetFor(s, tier)
		c := report.PerSkill[s.Frontmatter.ID]
		if limit > 0 && c.Claude > limit {
			warnings = append(warnings, fmt.Sprintf(
				"%s/%s: %d tokens (claude) exceeds declared %s budget of %d",
				s.Frontmatter.ID, tier, c.Claude, tier, limit,
			))
		}
	}
	// File-level soft caps. These scale with the number of skills compiled
	// (per-skill caps are enforced individually above); these warnings
	// surface when an entire dist/ file is becoming context-window-heavy.
	switch tier {
	case skill.TierCompact:
		cap := 1500 * len(skills)
		if report.Total.OpenAI > cap {
			warnings = append(warnings, fmt.Sprintf("%s compact total %d tokens exceeds %d soft cap (1500 * %d skills)",
				f.Name(), report.Total.OpenAI, cap, len(skills)))
		}
	case skill.TierFull:
		cap := 3000 * len(skills)
		if report.Total.OpenAI > cap {
			warnings = append(warnings, fmt.Sprintf("%s full total %d tokens exceeds %d soft cap (3000 * %d skills)",
				f.Name(), report.Total.OpenAI, cap, len(skills)))
		}
	}
	return out, report, warnings, nil
}

// stripSkillMarkers returns shallow copies of each skill whose body
// bullets have the build-time `<!-- pattern: { ... } -->` markers
// removed. The originals are left untouched so other consumers (and the
// raw on-disk SKILL.md) keep the markers the trace test relies on.
func stripSkillMarkers(skills []*skill.Skill) []*skill.Skill {
	stripLines := func(in []string) []string {
		if len(in) == 0 {
			return in
		}
		out := make([]string, len(in))
		for i, line := range in {
			out[i] = skill.StripBodyMarkers(line)
		}
		return out
	}
	out := make([]*skill.Skill, len(skills))
	for i, s := range skills {
		cp := *s
		cp.Body.Always = stripLines(s.Body.Always)
		cp.Body.Never = stripLines(s.Body.Never)
		cp.Body.KnownFalsePositives = stripLines(s.Body.KnownFalsePositives)
		out[i] = &cp
	}
	return out
}

// WriteFile compiles and writes a single distribution file to outDir.
func WriteFile(skills []*skill.Skill, tool string, tier skill.Tier, ctx Context, outDir string) (*Report, []string, error) {
	f, ok := Registry[tool]
	if !ok {
		return nil, nil, fmt.Errorf("unknown tool %q", tool)
	}
	content, report, warnings, err := Compile(skills, tool, tier, ctx)
	if err != nil {
		return nil, warnings, err
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, warnings, err
	}
	out := filepath.Join(outDir, f.OutputName())
	if err := os.WriteFile(out, []byte(content), 0o644); err != nil {
		return nil, warnings, err
	}
	return report, warnings, nil
}

// WriteAll regenerates all 8 distribution files in outDir using each
// formatter's default tier.
func WriteAll(skills []*skill.Skill, ctx Context, outDir string) (map[string]*Report, []string, error) {
	reports := make(map[string]*Report)
	var allWarnings []string
	for _, f := range AllTools() {
		r, warns, err := WriteFile(skills, f.Name(), f.DefaultTier(), ctx, outDir)
		if err != nil {
			return reports, allWarnings, err
		}
		reports[f.Name()] = r
		allWarnings = append(allWarnings, warns...)
	}
	return reports, allWarnings, nil
}

func budgetFor(s *skill.Skill, tier skill.Tier) int {
	switch tier {
	case skill.TierMinimal:
		return s.Frontmatter.TokenBudget.Minimal
	case skill.TierCompact:
		return s.Frontmatter.TokenBudget.Compact
	case skill.TierFull:
		return s.Frontmatter.TokenBudget.Full
	}
	return 0
}

func sortSkills(skills []*skill.Skill) {
	sort.SliceStable(skills, func(i, j int) bool {
		return skills[i].Frontmatter.ID < skills[j].Frontmatter.ID
	})
}

func sortedKeys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Header is the common preamble injected at the top of every distribution.
func Header(toolDisplay string, tier skill.Tier, n int) string {
	return fmt.Sprintf(`# Skills Library — %s (%s tier)

This file is generated by `+"`secure-vibe dev regenerate`"+`. Do not edit by hand;
update the source skills under `+"`skills/`"+` and regenerate.

Contains %d security skills compiled at the %s budget tier.

`, toolDisplay, tier, n, tier)
}

// VulnSummary is the section block injected when ctx.VulnerabilitySummary is
// non-empty.
func VulnSummary(ctx Context) string {
	if strings.TrimSpace(ctx.VulnerabilitySummary) == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString("## Known Malicious Packages (recent)\n\n")
	b.WriteString(ctx.VulnerabilitySummary)
	b.WriteString("\n")
	return b.String()
}

// GlossaryBlock renders the injected glossary entries.
func GlossaryBlock(ctx Context) string {
	if len(ctx.GlossaryEntries) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("## Reference Glossary\n\n")
	for _, e := range ctx.GlossaryEntries {
		fmt.Fprintf(&b, "- %s\n", e)
	}
	b.WriteString("\n")
	return b.String()
}

// AttackBlock renders the injected MITRE ATT&CK technique callouts.
func AttackBlock(ctx Context) string {
	if len(ctx.AttackTechniques) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("## Mapped MITRE ATT&CK Techniques\n\n")
	for _, t := range ctx.AttackTechniques {
		fmt.Fprintf(&b, "- %s\n", t)
	}
	b.WriteString("\n")
	return b.String()
}
