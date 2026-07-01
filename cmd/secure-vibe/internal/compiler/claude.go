package compiler

import (
	"strings"

	"github.com/shieldnet-360/secure-vibe/internal/skill"
)

type claudeFormatter struct{}

func (claudeFormatter) Name() string            { return "claude" }
func (claudeFormatter) OutputName() string      { return "CLAUDE.md" }
func (claudeFormatter) DefaultTier() skill.Tier { return skill.TierCompact }

// Format renders dist/CLAUDE.md. Since v3 the default output is a
// minimal pointer file (<4 KiB) that names the MCP server and the
// on-disk skills/<id>/SKILL.md tree, matching the design of
// dist/AGENTS.md. The legacy monolithic output that inlines every
// skill body is still available via `secure-vibe dev regenerate
// --full-inline` (alias --legacy) and the corresponding
// Context.FullInline flag.
func (claudeFormatter) Format(skills []*skill.Skill, tier skill.Tier, ctx Context) string {
	if ctx.fullInline() {
		return renderClaudeFullInline(skills, tier, ctx)
	}
	return RenderPointer(PointerSpec{
		OutputFile: "CLAUDE.md",
		Audience:   "this Claude Code project",
	}, skills)
}

func renderClaudeFullInline(skills []*skill.Skill, tier skill.Tier, ctx Context) string {
	var b strings.Builder
	b.WriteString(Header("Claude Code", tier, len(skills)))
	b.WriteString("Apply every skill below whenever you generate, review, or refactor code in this project. The rules are non-negotiable.\n\n")
	for _, s := range skills {
		b.WriteString(s.ExtractWithHeading(tier))
		b.WriteString("\n")
	}
	b.WriteString(VulnSummary(ctx))
	b.WriteString(GlossaryBlock(ctx))
	b.WriteString(AttackBlock(ctx))
	return b.String()
}
