package compiler

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/shieldnet-360/secure-vibe/internal/skill"
)

// Rule bundles are the per-skill, context-scoped equivalent of the native
// skill trees for IDEs that load rules selectively rather than via a single
// always-on pointer file. Each skill becomes one rule file whose frontmatter
// tells the IDE WHEN to surface it:
//
//	Cursor   dist/cursor-rules/.cursor/rules/<id>.mdc
//	           globs: <file patterns>   (Auto Attached) — or, for skills that
//	           apply everywhere, no globs + description (Agent Requested).
//	Copilot  dist/copilot-rules/.github/instructions/<id>.instructions.md
//	           applyTo: <file patterns>
//	Devin    dist/devin-rules/.devin/rules/<id>.md
//	           trigger: glob | model_decision
//
// This gives Cursor / VS Code Copilot the same progressive-disclosure benefit
// that Claude Code gets from .claude/skills: only the rule relevant to the
// files in play is pulled into context, instead of one ~4 KB digest of all 28
// skills loaded all the time.

// langGlobs maps a skill `languages:` entry to the file globs that should
// auto-attach that skill. A language not listed here contributes no glob.
var langGlobs = map[string][]string{
	"dockerfile": {"**/Dockerfile", "**/Dockerfile.*", "**/*.dockerfile"},
	"yaml":       {"**/*.yml", "**/*.yaml"},
	"yml":        {"**/*.yml", "**/*.yaml"},
	"json":       {"**/*.json"},
	"go":         {"**/*.go"},
	"python":     {"**/*.py"},
	"hcl":        {"**/*.tf", "**/*.tfvars", "**/*.hcl"},
	"typescript": {"**/*.ts", "**/*.tsx"},
	"javascript": {"**/*.js", "**/*.jsx", "**/*.mjs", "**/*.cjs"},
	"shell":      {"**/*.sh", "**/*.bash"},
}

// skillGlobOverrides pins precise path globs for skills whose surface area is
// a directory/path convention rather than a file language (where a pure
// language→glob mapping would be too broad). Override wins over languages.
var skillGlobOverrides = map[string][]string{
	"cicd-security": {".github/workflows/**", ".gitlab-ci.yml", "**/*.yml", "**/*.yaml"},
}

// skillGlobs derives the auto-attach globs for a skill. The bool return is
// true when the skill is "broad" — it declares languages: ["*"] (or none), so
// no specific file globs apply and the IDE should instead surface it by
// description (Cursor Agent-Requested) or apply it everywhere (Copilot).
func skillGlobs(s *skill.Skill) ([]string, bool) {
	if ov, ok := skillGlobOverrides[s.Frontmatter.ID]; ok {
		return dedupeSorted(ov), false
	}
	broad := len(s.Frontmatter.Languages) == 0
	set := map[string]bool{}
	for _, lang := range s.Frontmatter.Languages {
		if lang == "*" {
			broad = true
			continue
		}
		for _, g := range langGlobs[strings.ToLower(lang)] {
			set[g] = true
		}
	}
	globs := make([]string, 0, len(set))
	for g := range set {
		globs = append(globs, g)
	}
	sort.Strings(globs)
	// A skill that is "broad" yet also names concrete languages keeps those
	// concrete globs (they're a useful auto-attach signal); broad only means
	// "also relevant beyond these". With no concrete globs at all, it's purely
	// broad.
	if len(globs) == 0 {
		return nil, true
	}
	return globs, broad
}

func dedupeSorted(in []string) []string {
	set := map[string]bool{}
	for _, v := range in {
		set[v] = true
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// WriteRuleBundles emits the Cursor, Copilot, and Devin per-skill rule
// trees under outDir, purging stale per-skill files first.
func WriteRuleBundles(skills []*skill.Skill, outDir string) error {
	skills = stripSkillMarkers(skills)
	cursorDir := filepath.Join(outDir, "cursor-rules", ".cursor", "rules")
	copilotDir := filepath.Join(outDir, "copilot-rules", ".github", "instructions")
	devinDir := filepath.Join(outDir, "devin-rules", ".devin", "rules")

	if err := purgeStale(cursorDir, ".mdc", skills); err != nil {
		return fmt.Errorf("cursor-rules purge: %w", err)
	}
	if err := purgeStale(copilotDir, ".instructions.md", skills); err != nil {
		return fmt.Errorf("copilot-rules purge: %w", err)
	}
	if err := purgeStale(devinDir, ".md", skills); err != nil {
		return fmt.Errorf("devin-rules purge: %w", err)
	}
	for _, d := range []string{cursorDir, copilotDir, devinDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}

	for _, s := range skills {
		id := s.Frontmatter.ID
		if err := os.WriteFile(filepath.Join(cursorDir, id+".mdc"), []byte(renderCursorRule(s)), 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(copilotDir, id+".instructions.md"), []byte(renderCopilotInstruction(s)), 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(devinDir, id+".md"), []byte(renderDevinRule(s)), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// purgeStale removes rule files (matching suffix) whose skill id is no longer
// in the current set, so renamed/deleted skills don't linger.
func purgeStale(dir, suffix string, skills []*skill.Skill) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	keep := make(map[string]bool, len(skills))
	for _, s := range skills {
		keep[s.Frontmatter.ID+suffix] = true
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), suffix) || keep[e.Name()] {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// renderCursorRule produces a Cursor `.mdc` Project Rule. Skills with concrete
// file globs are Auto-Attached (`globs:` + `alwaysApply: false`); broad skills
// drop globs and rely on `description` so Cursor surfaces them as
// Agent-Requested rather than loading them on every file.
func renderCursorRule(s *skill.Skill) string {
	globs, broad := skillGlobs(s)
	var b strings.Builder
	b.WriteString("---\n")
	fmt.Fprintf(&b, "description: %s\n", yamlQuote(nativeDescription(s)))
	if len(globs) > 0 {
		fmt.Fprintf(&b, "globs: %s\n", strings.Join(globs, ","))
	}
	// Never always-on: auto-attach by glob, or agent-requested by description.
	b.WriteString("alwaysApply: false\n")
	_ = broad
	b.WriteString("---\n\n")
	b.WriteString(renderRuleBody(s, "Cursor"))
	return b.String()
}

// renderCopilotInstruction produces a GitHub Copilot `.instructions.md` scoped
// by `applyTo`. Broad skills apply to all files ("**"); language/path skills
// apply only to matching files.
func renderCopilotInstruction(s *skill.Skill) string {
	globs, broad := skillGlobs(s)
	applyTo := "**"
	if !broad && len(globs) > 0 {
		applyTo = strings.Join(globs, ",")
	}
	var b strings.Builder
	b.WriteString("---\n")
	fmt.Fprintf(&b, "applyTo: %s\n", yamlQuote(applyTo))
	b.WriteString("---\n\n")
	b.WriteString(renderRuleBody(s, "GitHub Copilot"))
	return b.String()
}

// renderDevinRule produces a Devin `.devin/rules/<id>.md` rule.
// Activation modes mirror Cursor: a `glob` trigger auto-attaches by
// file pattern; a `model_decision` trigger lets the agent pull the rule
// based on its description (used for broad skills, so they're never
// always-on).
func renderDevinRule(s *skill.Skill) string {
	globs, _ := skillGlobs(s)
	var b strings.Builder
	b.WriteString("---\n")
	if len(globs) > 0 {
		b.WriteString("trigger: glob\n")
		fmt.Fprintf(&b, "globs: %s\n", strings.Join(globs, ","))
	} else {
		b.WriteString("trigger: model_decision\n")
		fmt.Fprintf(&b, "description: %s\n", yamlQuote(nativeDescription(s)))
	}
	b.WriteString("---\n\n")
	b.WriteString(renderRuleBody(s, "Devin"))
	return b.String()
}

// renderRuleBody renders the shared, frontmatter-free rule body: title,
// description, and the ALWAYS / NEVER / KNOWN FALSE POSITIVES sections.
func renderRuleBody(s *skill.Skill, audience string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<!-- SecureVibe rule for %s. Generated by `secure-vibe dev regenerate`. -->\n", audience)
	fmt.Fprintf(&b, "<!-- Do not edit by hand; the source of truth is skills/%s/SKILL.md. -->\n\n", s.Frontmatter.ID)
	fmt.Fprintf(&b, "# %s\n\n", s.Frontmatter.Title)
	b.WriteString(s.Frontmatter.Description)
	b.WriteString("\n\n")
	if len(s.Body.Always) > 0 {
		b.WriteString("## ALWAYS\n\n")
		for _, line := range s.Body.Always {
			fmt.Fprintf(&b, "- %s\n", line)
		}
		b.WriteString("\n")
	}
	if len(s.Body.Never) > 0 {
		b.WriteString("## NEVER\n\n")
		for _, line := range s.Body.Never {
			fmt.Fprintf(&b, "- %s\n", line)
		}
		b.WriteString("\n")
	}
	if len(s.Body.KnownFalsePositives) > 0 {
		b.WriteString("## KNOWN FALSE POSITIVES\n\n")
		for _, line := range s.Body.KnownFalsePositives {
			fmt.Fprintf(&b, "- %s\n", line)
		}
		b.WriteString("\n")
	}
	return b.String()
}
