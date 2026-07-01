package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var skillIDRegexp = regexp.MustCompile(`^[a-z][a-z0-9-]{1,63}$`)

// AllowedCategories and AllowedSeverities mirror the schema enforced by
// internal/skill/parser.go so the scaffolded file passes validation.
var (
	allowedSkillCategories  = []string{"prevention", "hardening", "detection", "compliance", "supply-chain"}
	allowedSkillSeverities  = []string{"low", "medium", "high", "critical"}
	defaultSkillCategoryNew = "prevention"
	defaultSkillSeverityNew = "high"
)

func newCmd() *cobra.Command {
	var (
		libraryPath string
		title       string
		description string
		category    string
		severity    string
		languages   string
		rulesKind   string
		force       bool
	)

	c := &cobra.Command{
		Use:   "new <skill-id>",
		Short: "Scaffold a new skill directory under skills/<id>/",
		Long: `Create skills/<id>/SKILL.md with a template frontmatter and section
stubs, plus an empty rules/ or checklists/ directory containing a
schema-versioned starter file.

Example:
  secure-vibe dev new my-skill --title "My Skill" --category prevention --severity high
`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			id := strings.TrimSpace(args[0])
			if !skillIDRegexp.MatchString(id) {
				return fmt.Errorf("invalid skill id %q (must match %s)", id, skillIDRegexp)
			}
			if !contains(allowedSkillCategories, category) {
				return fmt.Errorf("invalid --category %q (valid: %s)", category, strings.Join(allowedSkillCategories, ", "))
			}
			if !contains(allowedSkillSeverities, severity) {
				return fmt.Errorf("invalid --severity %q (valid: %s)", severity, strings.Join(allowedSkillSeverities, ", "))
			}
			if rulesKind != "rules" && rulesKind != "checklists" {
				return fmt.Errorf("--rules-kind must be 'rules' or 'checklists'")
			}

			lib, err := filepath.Abs(libraryPath)
			if err != nil {
				return err
			}
			skillDir := filepath.Join(lib, "skills", id)
			if !force {
				if _, err := os.Stat(skillDir); err == nil {
					return fmt.Errorf("skills/%s already exists; pass --force to overwrite", id)
				}
			}

			rulesDir := filepath.Join(skillDir, rulesKind)
			if err := os.MkdirAll(rulesDir, 0o755); err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Join(skillDir, "tests"), 0o755); err != nil {
				return err
			}

			if title == "" {
				title = humanize(id)
			}
			if description == "" {
				description = fmt.Sprintf("TODO: 1-line description of what %s catches.", id)
			}

			skillMD := renderSkillTemplate(id, title, description, category, severity, languages, rulesKind)
			if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(skillMD), 0o644); err != nil {
				return err
			}

			starterPath := filepath.Join(rulesDir, "patterns.json")
			if rulesKind == "checklists" {
				starterPath = filepath.Join(rulesDir, "checklist.yaml")
			}
			if err := os.WriteFile(starterPath, []byte(renderStarterRule(rulesKind)), 0o644); err != nil {
				return err
			}

			corpusPath := filepath.Join(skillDir, "tests", "corpus.json")
			if err := os.WriteFile(corpusPath, []byte(renderStarterCorpus()), 0o644); err != nil {
				return err
			}

			fmt.Fprintf(c.OutOrStdout(), "Created skills/%s/ (%s + tests/)\n", id, rulesKind)
			fmt.Fprintf(c.OutOrStdout(), "Edit skills/%s/SKILL.md, fill out Rules / Context / References,\n", id)
			fmt.Fprintf(c.OutOrStdout(), "then run: secure-vibe dev validate\n")
			return nil
		},
	}

	c.Flags().StringVar(&libraryPath, "library", ".", "Path to the skills library root")
	c.Flags().StringVar(&title, "title", "", "Human-readable skill title (defaults to humanized id)")
	c.Flags().StringVar(&description, "description", "", "One-line description (defaults to TODO placeholder)")
	c.Flags().StringVar(&category, "category", defaultSkillCategoryNew, "Skill category: prevention|detection|compliance|supply-chain|hardening")
	c.Flags().StringVar(&severity, "severity", defaultSkillSeverityNew, "Skill severity: low|medium|high|critical")
	c.Flags().StringVar(&languages, "languages", "*", "Comma-separated language list, or '*' for any")
	c.Flags().StringVar(&rulesKind, "rules-kind", "rules", "Whether to scaffold a rules/ or checklists/ directory")
	c.Flags().BoolVar(&force, "force", false, "Overwrite skills/<id>/ if it already exists")
	return c
}

func renderSkillTemplate(id, title, description, category, severity, languages, rulesKind string) string {
	rulesPath := rulesKind + "/"
	langs := renderYAMLList(splitCSV(languages))
	return fmt.Sprintf(`---
id: %s
version: "0.1.0"
title: %q
description: %q
category: %s
severity: %s
applies_to:
  - "TODO: when this skill should apply"
languages: %s
token_budget:
  minimal: 1000
  compact: 1500
  full: 2500
rules_path: %q
related_skills: []
last_updated: %q
sources:
  - "TODO: cite OWASP / CWE / NIST / CIS / vendor reference"
---

# %s

## Rules (for AI agents)

### ALWAYS
- TODO: positive rule

### NEVER
- TODO: negative rule

### KNOWN FALSE POSITIVES
- TODO: edge case the rule should not fire on

## Context (for humans)

TODO: 2–4 paragraphs of background. Cite the authoritative reference,
explain the failure mode this skill catches, and why AI assistants tend
to get it wrong without it.

## References

- %s
- TODO: external reference URL
`,
		id,
		title,
		description,
		category,
		severity,
		langs,
		rulesPath,
		time.Now().UTC().Format("2006-01-02"),
		title,
		rulesPath,
	)
}

func renderStarterRule(kind string) string {
	if kind == "checklists" {
		return `schema_version: "1.0"
framework: "TODO: cite framework"
last_updated: "` + time.Now().UTC().Format("2006-01-02") + `"
patterns:
  - id: example-rule
    severity: medium
    rule: "TODO: describe rule"
`
	}
	return `{
  "schema_version": "1.0",
  "last_updated": "` + time.Now().UTC().Format("2006-01-02") + `",
  "description": "TODO: describe this rule file",
  "patterns": []
}
`
}

func renderStarterCorpus() string {
	return `{
  "schema_version": "1.0",
  "description": "Test corpus for this skill",
  "fixtures": []
}
`
}

func renderYAMLList(items []string) string {
	if len(items) == 1 && items[0] == "*" {
		return `["*"]`
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, fmt.Sprintf("%q", it))
	}
	return "[" + strings.Join(out, ", ") + "]"
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		out = []string{"*"}
	}
	return out
}

func contains(set []string, want string) bool {
	for _, s := range set {
		if s == want {
			return true
		}
	}
	return false
}

func humanize(id string) string {
	parts := strings.Split(id, "-")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, " ")
}
