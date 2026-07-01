package compiler

import (
	"fmt"
	"strings"

	"github.com/shieldnet-360/secure-vibe/internal/skill"
)

type universalFormatter struct{}

func (universalFormatter) Name() string            { return "universal" }
func (universalFormatter) OutputName() string      { return "SECURITY-SKILLS.md" }
func (universalFormatter) DefaultTier() skill.Tier { return skill.TierCompact }

func (universalFormatter) Format(skills []*skill.Skill, tier skill.Tier, ctx Context) string {
	var b strings.Builder
	b.WriteString(Header("Universal (any markdown-aware tool)", tier, len(skills)))
	b.WriteString("This file is the tool-agnostic compilation of every skill in the library.\n")
	b.WriteString("Drop it in your project root and reference it from any AI assistant that\n")
	b.WriteString("does not have a dedicated config file format.\n\n")
	b.WriteString("## Skill catalogue\n\n")
	b.WriteString("| Skill | Category | Severity | Languages |\n|-------|----------|----------|-----------|\n")
	for _, s := range skills {
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n",
			s.Frontmatter.ID,
			s.Frontmatter.Category,
			s.Frontmatter.Severity,
			strings.Join(s.Frontmatter.Languages, ", "),
		)
	}
	b.WriteString("\n")
	for _, s := range skills {
		fmt.Fprintf(&b, "## %s (`%s`)\n\n", s.Frontmatter.Title, s.Frontmatter.ID)
		fmt.Fprintf(&b, "_%s_\n\n", s.Frontmatter.Description)
		writeMarkdownBullets(&b, "Always", s.Body.Always)
		writeMarkdownBullets(&b, "Never", s.Body.Never)
		if tier != skill.TierMinimal {
			writeMarkdownBullets(&b, "Known false positives", s.Body.KnownFalsePositives)
		}
		if tier == skill.TierFull && s.Body.Context != "" {
			b.WriteString("**Context:**\n\n")
			b.WriteString(s.Body.Context)
			b.WriteString("\n\n")
		}
	}
	b.WriteString(VulnSummary(ctx))
	b.WriteString(GlossaryBlock(ctx))
	b.WriteString(AttackBlock(ctx))
	return b.String()
}
