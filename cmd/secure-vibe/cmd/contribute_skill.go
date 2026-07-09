package cmd

import (
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/spf13/cobra"

	"github.com/shieldnet-360/secure-vibe/internal/proposal"
)

// upstreamRepo is where a reviewed knowledge proposal is contributed.
const upstreamRepo = "ShieldNet-360/secure-vibe"

// contributeSkillCmd is the review half of the knowledge LEARN loop. An
// agent records proposals via the propose_skill_update MCP tool (an
// inert append to .secure-vibe/skill-proposals.jsonl); a maintainer uses
// this command to read them, and — when one holds up — to turn it into a
// paste-ready upstream contribution.
//
// The command deliberately does NOT edit any SKILL.md, sign anything, or
// open a PR. Applying a proposal is a human act: edit skills/<id>/SKILL.md
// by hand, then re-run the signing pipeline (validate → regenerate →
// manifest compute → sign). That human review + re-sign is the trust gate
// that keeps a model — steerable by prompt injection — from mutating
// signed knowledge.
func contributeSkillCmd() *cobra.Command {
	var dir, show, upstream string
	c := &cobra.Command{
		Use:   "skill",
		Short: "Review agent-recorded skill-update proposals (knowledge LEARN loop)",
		Long: `Review the skill-knowledge proposals an agent recorded via the
propose_skill_update MCP tool. Proposals are inert suggestions in
.secure-vibe/skill-proposals.jsonl — this command reads them; it never edits
or signs a skill.

  secure-vibe contribute skill                 # list pending proposals
  secure-vibe contribute skill --show <id>     # full detail for one proposal
  secure-vibe contribute skill --upstream <id> # a paste-ready upstream contribution

To adopt a proposal: edit skills/<skill-id>/SKILL.md by hand, then re-run the
signing pipeline. To share it upstream, use --upstream and open the printed URL.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := proposal.PathFor(dir)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			switch {
			case strings.TrimSpace(show) != "":
				p, err := proposal.Get(path, show)
				if err != nil {
					return err
				}
				if p == nil {
					return fmt.Errorf("no proposal matching %q in %s", show, path)
				}
				printProposalDetail(w, p)
				return nil
			case strings.TrimSpace(upstream) != "":
				p, err := proposal.Get(path, upstream)
				if err != nil {
					return err
				}
				if p == nil {
					return fmt.Errorf("no proposal matching %q in %s", upstream, path)
				}
				printUpstreamBundle(w, p)
				return nil
			default:
				return listProposals(w, path)
			}
		},
	}
	c.Flags().StringVar(&dir, "dir", "", "project directory holding .secure-vibe/skill-proposals.jsonl (default: cwd)")
	c.Flags().StringVar(&show, "show", "", "print full detail for one proposal id")
	c.Flags().StringVar(&upstream, "upstream", "", "print a paste-ready upstream contribution for one proposal id")
	return c
}

func listProposals(w io.Writer, path string) error {
	all, err := proposal.Load(path)
	if err != nil {
		return err
	}
	if len(all) == 0 {
		fmt.Fprintf(w, "No skill proposals yet (%s).\nAgents record them via the propose_skill_update MCP tool.\n", path)
		return nil
	}
	fmt.Fprintf(w, "%d skill proposal(s) in %s:\n", len(all), path)
	for _, p := range all {
		fmt.Fprintf(w, "  %s  [%s]  %s\n      %s\n", p.ID, p.Kind, p.SkillID, oneLine(p.Claim, 100))
	}
	fmt.Fprintf(w, "\nInspect one: secure-vibe contribute skill --show <id>\n")
	return nil
}

func printProposalDetail(w io.Writer, p *proposal.Proposal) {
	fmt.Fprintf(w, "id:         %s\n", p.ID)
	fmt.Fprintf(w, "skill:      %s\n", p.SkillID)
	fmt.Fprintf(w, "kind:       %s\n", p.Kind)
	fmt.Fprintf(w, "recorded:   %s (by %s)\n", p.Recorded, p.Source)
	fmt.Fprintf(w, "\nclaim:\n  %s\n", p.Claim)
	fmt.Fprintf(w, "\nevidence:\n  %s\n", p.Evidence)
	if strings.TrimSpace(p.SuggestedText) != "" {
		fmt.Fprintf(w, "\nsuggested text:\n  %s\n", p.SuggestedText)
	}
	fmt.Fprintf(w, "\nTo adopt: edit skills/%s/SKILL.md, then re-run the signing pipeline.\n", p.SkillID)
	fmt.Fprintf(w, "To share: secure-vibe contribute skill --upstream %s\n", p.ID)
}

// printUpstreamBundle emits a Markdown block a maintainer can paste into
// an upstream issue/PR, plus a prefilled "new issue" URL. It never opens
// anything — publishing is the human's explicit act.
func printUpstreamBundle(w io.Writer, p *proposal.Proposal) {
	title := fmt.Sprintf("skill(%s): %s knowledge — %s", p.SkillID, p.Kind, oneLine(p.Claim, 60))
	var b strings.Builder
	fmt.Fprintf(&b, "## Proposed skill update: `%s`\n\n", p.SkillID)
	fmt.Fprintf(&b, "**Kind:** %s\n\n", p.Kind)
	fmt.Fprintf(&b, "**Claim**\n\n%s\n\n", p.Claim)
	fmt.Fprintf(&b, "**Evidence**\n\n%s\n\n", p.Evidence)
	if strings.TrimSpace(p.SuggestedText) != "" {
		fmt.Fprintf(&b, "**Suggested wording for `skills/%s/SKILL.md`**\n\n%s\n\n", p.SkillID, p.SuggestedText)
	}
	fmt.Fprintf(&b, "_Recorded locally by %s on %s (proposal %s). A maintainer should verify the evidence, edit `skills/%s/SKILL.md`, and re-sign._\n",
		p.Source, p.Recorded, p.ID, p.SkillID)
	body := b.String()

	issueURL := fmt.Sprintf("https://github.com/%s/issues/new?title=%s&body=%s&labels=%s",
		upstreamRepo, url.QueryEscape(title), url.QueryEscape(body), url.QueryEscape("skill-knowledge"))

	fmt.Fprintf(w, "%s\n", body)
	fmt.Fprintf(w, "----\nPaste the block above into a PR, or open a prefilled issue:\n\n%s\n", issueURL)
}

// oneLine collapses whitespace and truncates s to n runes for compact
// listings and titles.
func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}
