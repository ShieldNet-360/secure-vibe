package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"github.com/shieldnet-360/secure-vibe/internal/tools"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// coverageMarkerRe extracts the inline `<!-- pattern: { ... } -->`
// markers from a SKILL.md body. FindAll so a bullet carrying more than
// one marker is fully captured.
var coverageMarkerRe = regexp.MustCompile(`<!--\s*pattern\s*:\s*(\{[^}]*\})\s*-->`)

// coverageMarker is one parsed scanner-contract marker.
type coverageMarker struct {
	ID       string `yaml:"id"`
	Severity string `yaml:"severity"`
	Check    string `yaml:"check"`
}

// scannerRuleIDs maps a skill id to the set of rule ids its
// deterministic gate scanner can emit. A skill absent from this map has
// no deterministic scanner backing, so every `check:` marker it carries
// should be `llm`.
func scannerRuleIDs(skillID string) map[string]bool {
	switch skillID {
	case "container-security":
		return tools.DockerfileRuleIDs()
	case "cicd-security":
		return tools.GitHubActionsRuleIDs()
	default:
		return nil
	}
}

func coverageCmd() *cobra.Command {
	var path string
	c := &cobra.Command{
		Use:   "coverage [skill-id]",
		Short: "Show which SKILL.md patterns the gate enforces vs leaves to the agent",
		Long: `coverage reads a skill's <!-- pattern: { id, severity, check } -->
markers and reports, for each, whether a deterministic gate check
enforces it (check: deterministic, shown as a tick) or the agent reasons
it from the skill (check: llm, shown as a robot). It is the
human-readable view of the skill<->scanner contract that the trace test
enforces — "read the skill, know what the CLI already scans".`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root := resolveLibraryRoot(path)
			abs, err := filepath.Abs(root)
			if err != nil {
				return err
			}
			var skillIDs []string
			if len(args) == 1 {
				skillIDs = []string{args[0]}
			} else {
				matches, _ := filepath.Glob(filepath.Join(abs, "skills", "*", "SKILL.md"))
				for _, m := range matches {
					skillIDs = append(skillIDs, filepath.Base(filepath.Dir(m)))
				}
				sort.Strings(skillIDs)
			}

			out := cmd.OutOrStdout()
			shown := 0
			for _, id := range skillIDs {
				markers, err := readCoverageMarkers(filepath.Join(abs, "skills", id, "SKILL.md"))
				if err != nil {
					return err
				}
				if len(markers) == 0 {
					if len(args) == 1 {
						fmt.Fprintf(out, "%s has no scanner-bound (check:) markers.\n", id)
					}
					continue
				}
				shown++
				printCoverage(out, id, markers, scannerRuleIDs(id))
			}
			if shown == 0 && len(args) == 0 {
				fmt.Fprintln(out, "No skills carry scanner-bound (check:) markers yet.")
			}
			return nil
		},
	}
	c.Flags().StringVar(&path, "path", ".", "library root (default: $SECURE_VIBE_LIBRARY_PATH, else cwd)")
	return c
}

// readCoverageMarkers parses every `check:`-tagged pattern marker from a
// SKILL.md. Markers without a check field are governance-only and are
// skipped here.
func readCoverageMarkers(skillPath string) ([]coverageMarker, error) {
	data, err := os.ReadFile(skillPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no SKILL.md at %s", skillPath)
		}
		return nil, err
	}
	out := make([]coverageMarker, 0)
	for _, m := range coverageMarkerRe.FindAllStringSubmatch(string(data), -1) {
		var p coverageMarker
		if err := yaml.Unmarshal([]byte(m[1]), &p); err != nil {
			return nil, fmt.Errorf("invalid pattern marker %q: %w", m[1], err)
		}
		if p.Check == "" {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

func printCoverage(out interface{ Write([]byte) (int, error) }, skillID string, markers []coverageMarker, goIDs map[string]bool) {
	var det, llm, anomalies []coverageMarker
	for _, m := range markers {
		switch m.Check {
		case "deterministic":
			det = append(det, m)
			if !goIDs[m.ID] {
				anomalies = append(anomalies, m) // claimed deterministic, no Go check
			}
		case "llm":
			llm = append(llm, m)
			if goIDs[m.ID] {
				anomalies = append(anomalies, m) // llm but a Go check emits it
			}
		default:
			anomalies = append(anomalies, m)
		}
	}
	sortMarkers(det)
	sortMarkers(llm)

	fmt.Fprintf(out, "\n%s — %d scanner-bound pattern(s): %d enforced by gate, %d agent-reasoned\n",
		skillID, len(markers), len(det), len(llm))
	if len(det) > 0 {
		fmt.Fprintf(out, "\n  ENFORCED BY GATE (deterministic)\n")
		for _, m := range det {
			mark := "✓" // ✓
			if !goIDs[m.ID] {
				mark = "✗" // ✗ claimed but unimplemented
			}
			fmt.Fprintf(out, "    %s %-30s %s\n", mark, m.ID, m.Severity)
		}
	}
	if len(llm) > 0 {
		fmt.Fprintf(out, "\n  AGENT-REASONED (llm — read the skill)\n")
		for _, m := range llm {
			fmt.Fprintf(out, "    \U0001F916 %-30s %s\n", m.ID, m.Severity)
		}
	}
	if len(anomalies) > 0 {
		fmt.Fprintf(out, "\n  ⚠ %d contract anomaly(ies) — run the trace test:\n", len(anomalies))
		for _, m := range anomalies {
			fmt.Fprintf(out, "    %s (check: %s)\n", m.ID, m.Check)
		}
	}
}

func sortMarkers(m []coverageMarker) {
	sort.Slice(m, func(i, j int) bool { return m[i].ID < m[j].ID })
}
