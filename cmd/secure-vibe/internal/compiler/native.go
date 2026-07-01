package compiler

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/shieldnet-360/secure-vibe/internal/skill"
)

// NativeBundle describes one native-skill output tree.
//
// "Native" here means the on-disk layout that a specific IDE / agent
// discovers automatically — e.g. Claude Code reads
// `.claude/skills/<id>/SKILL.md`, GitHub Copilot reads
// `.github/skills/<id>/SKILL.md`, and the cross-tool "agent skills"
// convention is `.agents/skills/<id>/SKILL.md`. Each tree contains one
// directory per skill ID with a normalised SKILL.md plus a
// metadata.json that preserves the full custom frontmatter the source
// SKILL.md carried.
//
// The relative root inside dist/ (Subdir) and the auto-loaded path the
// consumer IDE expects (InstallPath) are separated so that the same
// generator code can also tell the user where to drop the tree.
type NativeBundle struct {
	// Subdir is the directory under dist/ where this bundle is
	// emitted (e.g. "claude-skills", "agent-skills",
	// "copilot-skills").
	Subdir string
	// InstallPath is the consumer-side relative path the bundle is
	// designed to be copied to (e.g. ".claude/skills",
	// ".github/skills", ".agents/skills"). It is what we write the
	// skill directories under, inside Subdir.
	InstallPath string
	// Audience is a short human-readable label used in the
	// banner comment of each generated SKILL.md so a reader can
	// see at a glance which tool's convention this file follows.
	Audience string
}

// DefaultNativeBundles is the canonical set of native-skill trees this
// repository ships. Adding a new IDE convention is a single append to
// this slice plus (optionally) updating the README.
var DefaultNativeBundles = []NativeBundle{
	{Subdir: "agent-skills", InstallPath: ".agents/skills", Audience: "agent-skills (cross-tool convention)"},
	{Subdir: "copilot-skills", InstallPath: ".github/skills", Audience: "GitHub Copilot"},
	{Subdir: "claude-skills", InstallPath: ".claude/skills", Audience: "Claude Code"},
}

// WriteNativeBundles writes every NativeBundle tree under outDir. For
// each skill in skills it emits:
//
//	<outDir>/<bundle.Subdir>/<bundle.InstallPath>/<skill-id>/SKILL.md
//	<outDir>/<bundle.Subdir>/<bundle.InstallPath>/<skill-id>/metadata.json
//
// SKILL.md uses the IDE-portable frontmatter — `name` + `description`
// — and inlines the ALWAYS / NEVER / KNOWN FALSE POSITIVES sections
// from the source. metadata.json carries the rest of the custom
// frontmatter (id, version, severity, category, token budgets, etc.)
// so consumers that want richer metadata can read it without
// reparsing the human-facing SKILL.md.
func WriteNativeBundles(skills []*skill.Skill, outDir string) error {
	skills = stripSkillMarkers(skills)
	for _, bundle := range DefaultNativeBundles {
		if err := writeBundle(bundle, skills, outDir); err != nil {
			return fmt.Errorf("native bundle %s: %w", bundle.Subdir, err)
		}
	}
	return nil
}

// writeBundle emits one NativeBundle tree under outDir/<bundle.Subdir>.
//
// Stale skills (renamed or deleted in skills/) would otherwise leak into
// the regenerated bundle because the previous regeneration's per-skill
// directories still exist. IDE auto-discovery would then surface a
// skill that no longer has a source-of-truth SKILL.md. So we purge any
// previously-emitted skill directories that are not in the current
// skill set before writing the new ones, deliberately leaving the
// containing `<bundle.Subdir>/<bundle.InstallPath>` directory itself
// alone (it may legitimately host hand-authored files in some
// installs, e.g. a top-level README).
func writeBundle(bundle NativeBundle, skills []*skill.Skill, outDir string) error {
	root := filepath.Join(outDir, bundle.Subdir, bundle.InstallPath)
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	keep := make(map[string]bool, len(skills))
	for _, s := range skills {
		keep[s.Frontmatter.ID] = true
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() || keep[entry.Name()] {
			continue
		}
		// Only remove directories that look like a previous native
		// skill bundle (i.e. they contain SKILL.md), to keep this
		// safe in case an operator drops other directories under
		// the install root.
		skillMD := filepath.Join(root, entry.Name(), "SKILL.md")
		if _, statErr := os.Stat(skillMD); statErr != nil {
			continue
		}
		if err := os.RemoveAll(filepath.Join(root, entry.Name())); err != nil {
			return err
		}
	}
	for _, s := range skills {
		dir := filepath.Join(root, s.Frontmatter.ID)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(renderNativeSkillMD(s, bundle)), 0o644); err != nil {
			return err
		}
		meta, err := renderNativeMetadataJSON(s)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "metadata.json"), meta, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// renderNativeSkillMD produces the IDE-portable SKILL.md body. The
// frontmatter is intentionally restricted to `name` and `description`
// because that is the minimum surface agreed on across the Claude /
// Copilot / cross-tool agent-skills conventions; everything else
// lives in metadata.json so the file stays interoperable.
func renderNativeSkillMD(s *skill.Skill, bundle NativeBundle) string {
	var b strings.Builder
	b.WriteString("---\n")
	fmt.Fprintf(&b, "name: %s\n", s.Frontmatter.ID)
	fmt.Fprintf(&b, "description: %s\n", yamlQuote(nativeDescription(s)))
	b.WriteString("---\n\n")
	fmt.Fprintf(&b, "<!-- Native skill bundle for %s. Generated by `secure-vibe dev regenerate`. -->\n", bundle.Audience)
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

// nativeDescription composes a single-line description suitable for
// IDE auto-discovery. It joins the human-written description with the
// applies_to list so an agent scanning native skill manifests can see
// both the intent and the surface area in one place.
func nativeDescription(s *skill.Skill) string {
	desc := strings.TrimSpace(s.Frontmatter.Description)
	if len(s.Frontmatter.AppliesTo) == 0 {
		return desc
	}
	applies := strings.Join(s.Frontmatter.AppliesTo, "; ")
	if desc == "" {
		return applies
	}
	return desc + " — Applies to: " + applies
}

// yamlQuote returns a YAML double-quoted scalar that is safe regardless
// of what punctuation the source description contains. The frontmatter
// description routinely embeds ": ", "—", semicolons, and other tokens
// that look like YAML structural markers when emitted as a plain
// scalar, so every description gets the same quoted form for parser
// portability. Go's `%q` already escapes `"`, `\`, and control runes
// in a way that is compatible with the YAML 1.2 double-quoted style.
func yamlQuote(s string) string {
	return fmt.Sprintf("%q", s)
}

// nativeTokenBudget is the JSON-tagged shape of the per-tier token
// budget. The source skill.TokenBudget struct only carries `yaml:`
// tags, so we cannot use it directly without leaking Go-style
// `Minimal` / `Compact` / `Full` keys to disk; this local mirror keeps
// metadata.json in the canonical lowercase shape.
type nativeTokenBudget struct {
	Minimal int `json:"minimal"`
	Compact int `json:"compact"`
	Full    int `json:"full"`
}

// nativeMetadata mirrors the full custom frontmatter that the source
// SKILL.md carries. Its JSON shape is deliberately a subset of the
// `Frontmatter` struct so that future fields are picked up
// automatically when the Frontmatter struct gains them.
type nativeMetadata struct {
	ID            string            `json:"id"`
	Version       string            `json:"version"`
	Title         string            `json:"title"`
	Description   string            `json:"description"`
	Category      string            `json:"category"`
	Severity      string            `json:"severity"`
	AppliesTo     []string          `json:"applies_to"`
	Languages     []string          `json:"languages"`
	TokenBudget   nativeTokenBudget `json:"token_budget"`
	RulesPath     string            `json:"rules_path,omitempty"`
	TestsPath     string            `json:"tests_path,omitempty"`
	RelatedSkills []string          `json:"related_skills,omitempty"`
	LastUpdated   string            `json:"last_updated"`
	Sources       []string          `json:"sources"`
}

// renderNativeMetadataJSON serialises the full source frontmatter as
// pretty-printed JSON so consumers that want the rich (non-portable)
// metadata — severity, token budgets, related skills, etc. — can read
// it without reparsing the human-facing SKILL.md.
func renderNativeMetadataJSON(s *skill.Skill) ([]byte, error) {
	m := nativeMetadata{
		ID:          s.Frontmatter.ID,
		Version:     s.Frontmatter.Version,
		Title:       s.Frontmatter.Title,
		Description: s.Frontmatter.Description,
		Category:    s.Frontmatter.Category,
		Severity:    s.Frontmatter.Severity,
		AppliesTo:   s.Frontmatter.AppliesTo,
		Languages:   s.Frontmatter.Languages,
		TokenBudget: nativeTokenBudget{
			Minimal: s.Frontmatter.TokenBudget.Minimal,
			Compact: s.Frontmatter.TokenBudget.Compact,
			Full:    s.Frontmatter.TokenBudget.Full,
		},
		RulesPath:     s.Frontmatter.RulesPath,
		TestsPath:     s.Frontmatter.TestsPath,
		RelatedSkills: s.Frontmatter.RelatedSkills,
		LastUpdated:   s.Frontmatter.LastUpdated,
		Sources:       s.Frontmatter.Sources,
	}
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}
