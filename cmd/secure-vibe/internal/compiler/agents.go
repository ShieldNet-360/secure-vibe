package compiler

import (
	"fmt"
	"strings"

	"github.com/shieldnet-360/secure-vibe/internal/skill"
)

type agentsFormatter struct{}

func (agentsFormatter) Name() string            { return "agents" }
func (agentsFormatter) OutputName() string      { return "AGENTS.md" }
func (agentsFormatter) DefaultTier() skill.Tier { return skill.TierCompact }

// Format renders the AGENTS.md distribution file. By default it emits
// the minimal pointer file (target <4 KiB) that the v2 redesign moved
// to; set Context.FullInline to fall back to the legacy monolithic
// output that inlines every skill body.
//
// The minimal file is intentionally short. It exists so that an LLM
// running in a consumer repo learns:
//  1. there are local skills it should consult,
//  2. how to reach the MCP server for structured lookups, and
//  3. that the file is not a substitute for SAST / SCA / secret scanning.
//
// Anything richer (the full "Always / Never / KFP" body of every skill)
// belongs behind the MCP server, which is auditable and versioned.
func (agentsFormatter) Format(skills []*skill.Skill, tier skill.Tier, ctx Context) string {
	if ctx.fullInline() {
		return renderAgentsFullInline(skills, tier, ctx)
	}
	return RenderPointer(PointerSpec{
		OutputFile: "AGENTS.md",
		Audience:   "this Codex / OpenAI agents project",
	}, skills)
}

// renderAgentsFullInline is the pre-v2 monolithic AGENTS.md output. It
// inlines every skill body and remains available via
// `secure-vibe dev regenerate --full-inline` (alias `--legacy`).
func renderAgentsFullInline(skills []*skill.Skill, tier skill.Tier, ctx Context) string {
	var b strings.Builder
	b.WriteString(Header("AGENTS.md (Codex / OpenAI agents)", tier, len(skills)))
	b.WriteString("Operating contract: you are an autonomous coding agent. Treat the skills\n")
	b.WriteString("below as binding constraints on every commit, PR, or refactor you produce.\n\n")
	for _, s := range skills {
		fmt.Fprintf(&b, "## Skill: %s\n", s.Frontmatter.Title)
		fmt.Fprintf(&b, "Applies to: %s\n\n", strings.Join(s.Frontmatter.AppliesTo, "; "))
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
