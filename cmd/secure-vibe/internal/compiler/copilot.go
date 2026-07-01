package compiler

import (
	"fmt"
	"strings"

	"github.com/shieldnet-360/secure-vibe/internal/skill"
)

type copilotFormatter struct{}

func (copilotFormatter) Name() string            { return "copilot" }
func (copilotFormatter) OutputName() string      { return "copilot-instructions.md" }
func (copilotFormatter) DefaultTier() skill.Tier { return skill.TierCompact }

// Format renders dist/copilot-instructions.md. Since v3 the default
// output is a minimal pointer file (<4 KiB) matching dist/AGENTS.md.
// The legacy monolithic output that inlines every skill body remains
// available via `secure-vibe dev regenerate --full-inline`
// (alias --legacy).
func (copilotFormatter) Format(skills []*skill.Skill, tier skill.Tier, ctx Context) string {
	if ctx.fullInline() {
		return renderCopilotFullInline(skills, tier, ctx)
	}
	return RenderPointer(PointerSpec{
		OutputFile: "copilot-instructions.md",
		Audience:   "this GitHub Copilot project",
	}, skills)
}

func renderCopilotFullInline(skills []*skill.Skill, tier skill.Tier, ctx Context) string {
	var b strings.Builder
	b.WriteString(Header("GitHub Copilot", tier, len(skills)))
	b.WriteString("These instructions are applied to every suggestion Copilot makes in this\n")
	b.WriteString("repository. Follow the security rules below alongside any project style\n")
	b.WriteString("guidelines you have already received.\n\n")
	for _, s := range skills {
		fmt.Fprintf(&b, "### %s\n\n", s.Frontmatter.Title)
		fmt.Fprintf(&b, "%s. Category: %s. Severity: %s.\n\n", s.Frontmatter.Description, s.Frontmatter.Category, s.Frontmatter.Severity)
		writeMarkdownBullets(&b, "Required", s.Body.Always)
		writeMarkdownBullets(&b, "Forbidden", s.Body.Never)
		if tier != skill.TierMinimal {
			writeMarkdownBullets(&b, "Known false positives", s.Body.KnownFalsePositives)
		}
	}
	b.WriteString(VulnSummary(ctx))
	b.WriteString(GlossaryBlock(ctx))
	b.WriteString(AttackBlock(ctx))
	return b.String()
}

func writeMarkdownBullets(b *strings.Builder, label string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(b, "**%s:**\n", label)
	for _, item := range items {
		fmt.Fprintf(b, "- %s\n", item)
	}
	b.WriteString("\n")
}
