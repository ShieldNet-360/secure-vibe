package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/shieldnet-360/secure-vibe/internal/skill"
)

// frameworkSlugRegex restricts the --framework value to a simple slug so the
// derived mapping path (compliance/<slug>_mapping.yaml) can never traverse
// out of the compliance/ directory or pull in unintended files.
var frameworkSlugRegex = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// ComplianceMapping is the shape of the per-framework mapping files under
// compliance/<framework>_mapping.yaml.
type ComplianceMapping struct {
	SchemaVersion string `yaml:"schema_version" json:"schema_version"`
	Framework     string `yaml:"framework" json:"framework"`
	Version       string `yaml:"version" json:"version"`
	LastUpdated   string `yaml:"last_updated" json:"last_updated"`
	Controls      []struct {
		ID          string   `yaml:"id" json:"id"`
		Title       string   `yaml:"title" json:"title"`
		Description string   `yaml:"description" json:"description"`
		Skills      []string `yaml:"skills" json:"skills"`
		References  []string `yaml:"references" json:"references"`
	} `yaml:"controls" json:"controls"`
}

// EvidenceReport is the rendered audit artifact for `secure-vibe dev evidence`.
type EvidenceReport struct {
	GeneratedAt      time.Time         `json:"generated_at"`
	Framework        string            `json:"framework"`
	FrameworkVersion string            `json:"framework_version,omitempty"`
	LibraryRoot      string            `json:"library_root"`
	SkillsCount      int               `json:"skills_count"`
	Controls         []ControlEvidence `json:"controls"`
	UnmappedSkills   []string          `json:"unmapped_skills"`
	UnmappedControls []string          `json:"unmapped_controls"`
	Metadata         map[string]string `json:"metadata,omitempty"`
}

type ControlEvidence struct {
	ID            string         `json:"id"`
	Title         string         `json:"title"`
	Description   string         `json:"description,omitempty"`
	Status        string         `json:"status"` // covered | partial | missing
	MappedSkills  []string       `json:"mapped_skills"`
	PresentSkills []SkillSummary `json:"present_skills"`
	MissingSkills []string       `json:"missing_skills"`
	References    []string       `json:"references,omitempty"`
}

type SkillSummary struct {
	ID          string `json:"id"`
	Version     string `json:"version"`
	LastUpdated string `json:"last_updated"`
	Path        string `json:"path"`
}

func evidenceCmd() *cobra.Command {
	var (
		libraryPath string
		framework   string
		format      string
		outFile     string
	)

	c := &cobra.Command{
		Use:   "evidence",
		Short: "Emit a compliance coverage report showing which installed skills map to framework controls",
		Long: `Compile a compliance coverage report that maps installed skills onto
the controls of a compliance framework (SOC2, HIPAA, PCI-DSS).

The report is timestamped and lists which controls are covered by which skill
versions, flagging missing skills — showing which installed skills map to
framework controls. It is a developer-facing coverage map, not an audit
artifact: a real audit also needs runtime evidence, change-management
records, access reviews, and so on.
`,
		RunE: func(c *cobra.Command, args []string) error {
			if framework == "" {
				return fmt.Errorf("--framework is required (SOC2|HIPAA|PCI-DSS)")
			}
			if !frameworkSlugRegex.MatchString(framework) {
				return fmt.Errorf(
					"--framework %q is invalid: must match %s (no path separators or '..')",
					framework, frameworkSlugRegex.String(),
				)
			}
			fwSlug := strings.ToLower(framework)
			fwSlug = strings.ReplaceAll(fwSlug, "-", "_")

			lib, err := filepath.Abs(resolveLibraryRoot(libraryPath))
			if err != nil {
				return err
			}

			mappingPath := filepath.Join(lib, "compliance", fwSlug+"_mapping.yaml")
			mapData, err := os.ReadFile(mappingPath)
			if err != nil {
				return fmt.Errorf("read mapping for %s: %w (expected %s)", framework, err, mappingPath)
			}
			var mapping ComplianceMapping
			if err := yaml.Unmarshal(mapData, &mapping); err != nil {
				return fmt.Errorf("parse mapping: %w", err)
			}
			if mapping.SchemaVersion == "" {
				return fmt.Errorf("mapping %s missing schema_version", mappingPath)
			}

			skills, err := skill.LoadAll(filepath.Join(lib, "skills"))
			if err != nil {
				return err
			}
			byID := map[string]*skill.Skill{}
			for _, s := range skills {
				byID[s.Frontmatter.ID] = s
			}

			report := EvidenceReport{
				GeneratedAt:      time.Now().UTC(),
				Framework:        mapping.Framework,
				FrameworkVersion: mapping.Version,
				LibraryRoot:      lib,
				SkillsCount:      len(skills),
				Controls:         make([]ControlEvidence, 0, len(mapping.Controls)),
				// Pre-initialize so empty reports marshal as `[]` not `null` (audit JSON shape).
				UnmappedSkills:   []string{},
				UnmappedControls: []string{},
				Metadata: map[string]string{
					"mapping_schema_version": mapping.SchemaVersion,
					"mapping_last_updated":   mapping.LastUpdated,
				},
			}

			referencedSkills := map[string]bool{}
			for _, ctrl := range mapping.Controls {
				ev := ControlEvidence{
					ID:           ctrl.ID,
					Title:        ctrl.Title,
					Description:  ctrl.Description,
					MappedSkills: append([]string{}, ctrl.Skills...),
					References:   append([]string{}, ctrl.References...),
					// Pre-initialize so per-control JSON marshals as `[]` not `null` when empty.
					PresentSkills: []SkillSummary{},
					MissingSkills: []string{},
				}
				for _, sid := range ctrl.Skills {
					referencedSkills[sid] = true
					if s, ok := byID[sid]; ok {
						ev.PresentSkills = append(ev.PresentSkills, SkillSummary{
							ID:          s.Frontmatter.ID,
							Version:     s.Frontmatter.Version,
							LastUpdated: s.Frontmatter.LastUpdated,
							Path:        s.Path,
						})
					} else {
						ev.MissingSkills = append(ev.MissingSkills, sid)
					}
				}
				switch {
				case len(ev.MappedSkills) == 0:
					ev.Status = "unmapped"
				case len(ev.MissingSkills) == 0:
					ev.Status = "covered"
				case len(ev.PresentSkills) == 0:
					ev.Status = "missing"
				default:
					ev.Status = "partial"
				}
				report.Controls = append(report.Controls, ev)
			}

			for _, s := range skills {
				if !referencedSkills[s.Frontmatter.ID] {
					report.UnmappedSkills = append(report.UnmappedSkills, s.Frontmatter.ID)
				}
			}
			sort.Strings(report.UnmappedSkills)

			for _, ctrl := range report.Controls {
				if ctrl.Status == "unmapped" {
					report.UnmappedControls = append(report.UnmappedControls, ctrl.ID)
				}
			}
			sort.Strings(report.UnmappedControls)

			out, err := renderEvidence(report, format)
			if err != nil {
				return err
			}
			if outFile == "" || outFile == "-" {
				fmt.Fprint(c.OutOrStdout(), out)
			} else {
				if err := os.MkdirAll(filepath.Dir(outFile), 0o755); err != nil {
					return err
				}
				if err := os.WriteFile(outFile, []byte(out), 0o644); err != nil {
					return err
				}
				fmt.Fprintf(c.OutOrStdout(), "wrote evidence report to %s (%d controls)\n", outFile, len(report.Controls))
			}
			return nil
		},
	}

	c.Flags().StringVar(&libraryPath, "library", ".", "Path to the skills library root (default: $SECURE_VIBE_LIBRARY_PATH, else cwd)")
	c.Flags().StringVar(&framework, "framework", "", "Compliance framework: SOC2|HIPAA|PCI-DSS")
	c.Flags().StringVar(&format, "format", "json", "Output format: json|markdown")
	c.Flags().StringVar(&outFile, "out", "", "Write report to this file; '-' or empty for stdout")
	return c
}

func renderEvidence(r EvidenceReport, format string) (string, error) {
	switch strings.ToLower(format) {
	case "json", "":
		b, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			return "", err
		}
		return string(b) + "\n", nil
	case "markdown", "md":
		return renderEvidenceMarkdown(r), nil
	default:
		return "", fmt.Errorf("unknown format %q (valid: json|markdown)", format)
	}
}

func renderEvidenceMarkdown(r EvidenceReport) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Compliance Evidence Report — %s\n\n", r.Framework)
	if r.FrameworkVersion != "" {
		fmt.Fprintf(&sb, "**Framework version:** %s  \n", r.FrameworkVersion)
	}
	fmt.Fprintf(&sb, "**Generated:** %s  \n", r.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(&sb, "**Library root:** `%s`  \n", r.LibraryRoot)
	fmt.Fprintf(&sb, "**Skills installed:** %d  \n", r.SkillsCount)
	fmt.Fprintf(&sb, "**Controls evaluated:** %d\n\n", len(r.Controls))

	var covered, partial, missing, unmapped int
	for _, c := range r.Controls {
		switch c.Status {
		case "covered":
			covered++
		case "partial":
			partial++
		case "missing":
			missing++
		case "unmapped":
			unmapped++
		}
	}
	fmt.Fprintf(&sb, "## Summary\n\n- Covered: %d\n- Partial: %d\n- Missing: %d\n- Unmapped: %d\n\n", covered, partial, missing, unmapped)
	fmt.Fprintf(&sb, "## Controls\n\n")
	fmt.Fprintf(&sb, "| Control | Status | Skills present | Skills missing |\n")
	fmt.Fprintf(&sb, "|---|---|---|---|\n")
	for _, c := range r.Controls {
		present := make([]string, 0, len(c.PresentSkills))
		for _, s := range c.PresentSkills {
			present = append(present, escapeMarkdownTableCell(fmt.Sprintf("%s@%s", s.ID, s.Version)))
		}
		missing := make([]string, 0, len(c.MissingSkills))
		for _, m := range c.MissingSkills {
			missing = append(missing, escapeMarkdownTableCell(m))
		}
		fmt.Fprintf(&sb, "| %s | %s | %s | %s |\n",
			escapeMarkdownTableCell(c.ID),
			escapeMarkdownTableCell(c.Status),
			strings.Join(present, ", "),
			strings.Join(missing, ", "))
	}
	if len(r.UnmappedSkills) > 0 {
		fmt.Fprintf(&sb, "\n## Skills not referenced by any control\n\n")
		for _, s := range r.UnmappedSkills {
			fmt.Fprintf(&sb, "- %s\n", s)
		}
	}
	if len(r.UnmappedControls) > 0 {
		fmt.Fprintf(&sb, "\n## Controls with no mapped skills\n\n")
		for _, id := range r.UnmappedControls {
			fmt.Fprintf(&sb, "- %s\n", id)
		}
	}
	return sb.String()
}

// escapeMarkdownTableCell escapes characters that would break a GFM table
// row when interpolated as a cell value: pipes terminate columns and
// newlines terminate rows. Future compliance frameworks may emit control
// IDs or skill identifiers that contain these characters; today's data
// does not, so this is a robustness fix rather than a fix for current
// breakage.
func escapeMarkdownTableCell(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "\r\n", "<br>")
	s = strings.ReplaceAll(s, "\n", "<br>")
	s = strings.ReplaceAll(s, "\r", "<br>")
	return s
}
