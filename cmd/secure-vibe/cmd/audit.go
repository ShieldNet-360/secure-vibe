package cmd

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/shieldnet-360/secure-vibe/internal/audit"
	"github.com/shieldnet-360/secure-vibe/internal/tools"
)

// auditCmd is the whole-tree orchestration layer above `gate`. It fans the same
// deterministic scanners out across an entire directory concurrently, then
// deduplicates, ranks, and triages the findings into one report. No new
// detection logic and no network — it is a strict superset of `gate` that runs
// offline. The model-pluggable LLM lanes and dynamic verify layer on top of the
// Report it produces (see later phases).
func auditCmd() *cobra.Command {
	var repoPath, severityFloor, format, vulnSource, sarifBase, report string
	var jobs int
	c := &cobra.Command{
		Use:   "audit [path]",
		Short: "Whole-tree security audit: fan out every scanner, dedup, rank, and triage findings",
		Long: `audit runs SecureVibe's deterministic scanners across an entire tree
(secrets, dependencies, Dockerfile, GitHub Actions), deduplicates and ranks the
findings by severity, and applies a first false-positive triage pass — findings
in test / fixture / example paths are still reported but demoted below confirmed
ones.

It is the DETECT layer above 'gate': the very same scanners, but repo-wide
breadth and one ranked report instead of a per-file pass/fail. With no path it
audits the current directory. It always exits 0 (text/json); use 'gate' when you
need a CI-failing check on specific files.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := validateFormat(format, true); err != nil {
				return err
			}
			root := "."
			if len(args) == 1 {
				root = args[0]
			}
			rootAbs, err := filepath.Abs(root)
			if err != nil {
				return fmt.Errorf("resolve audit path %q: %w", root, err)
			}
			files, err := tools.ExpandGateFiles([]string{rootAbs})
			if err != nil {
				return err
			}
			if len(files) == 0 {
				fmt.Fprintf(c.OutOrStdout(), "audit: no scannable files under %s.\n", root)
				return nil
			}

			// One library per worker, each sandboxed to the audit root so the
			// file scanners may read anything under it.
			newLib := func() (*tools.Library, error) {
				lib, err := newLibraryForCmd(repoPath, vulnSource, "")
				if err != nil {
					return nil, err
				}
				if err := lib.SetAllowedRoots([]string{rootAbs}); err != nil {
					return nil, fmt.Errorf("scope library to %s: %w", rootAbs, err)
				}
				return lib, nil
			}

			rep, err := audit.Run(c.Context(), files, newLib, audit.Options{
				Root:          rootAbs,
				SeverityFloor: severityFloor,
				Jobs:          jobs,
			})
			if err != nil {
				return err
			}

			if report != "" {
				rep2 := newReport("audit", []string{root})
				for _, res := range rep.Results {
					rep2.Sections = append(rep2.Sections, gateSection(res))
				}
				return writeReport(c, report, rep2)
			}
			switch format {
			case "json":
				return emitJSON(c.OutOrStdout(), rep)
			case "sarif":
				base, err := filepath.Abs(sarifBase)
				if err != nil {
					base = ""
				}
				return emitJSON(c.OutOrStdout(), tools.PolicyCheckSARIF(rep.Results, base))
			default:
				renderAuditText(c, rep)
			}
			return nil
		},
	}
	c.Flags().StringVar(&repoPath, "path", ".", "secure-vibe library checkout (default: $SECURE_VIBE_LIBRARY_PATH, else cwd)")
	c.Flags().StringVar(&severityFloor, "severity-floor", "low",
		"only collect findings at or above this severity: critical | high | medium | low")
	c.Flags().IntVar(&jobs, "jobs", 0, "concurrent scanner workers (default: min(NumCPU, 8))")
	c.Flags().StringVar(&sarifBase, "sarif-base", ".",
		"directory SARIF artifact URIs are made relative to; only used with --format sarif")
	addFormatFlag(c, &format, true)
	addReportFlag(c, &report)
	addVulnSourceFlag(c, &vulnSource)
	return c
}

// renderAuditText prints the ranked, human-readable audit summary. Confirmed
// findings are grouped by severity; triaged (likely-fixture) findings are
// summarised as a count so the report reads honest without drowning in samples.
func renderAuditText(c *cobra.Command, rep *audit.Report) {
	out := c.OutOrStdout()
	fmt.Fprintf(out, "=== secure-vibe audit: %s ===\n", rep.Root)
	fmt.Fprintf(out, "Files scanned: %d\n", rep.FilesScanned)

	confirmed := rep.Total()
	fmt.Fprintf(out, "Findings: %d%s", confirmed, severitySummary(rep.Counts))
	if rep.Triaged > 0 {
		fmt.Fprintf(out, "   [+%d triaged as likely fixtures]", rep.Triaged)
	}
	fmt.Fprintln(out)

	if confirmed == 0 {
		fmt.Fprintln(out, "\nNo confirmed findings.")
		if rep.Triaged > 0 {
			fmt.Fprintln(out, "(triaged findings are hidden here — see --format json for the full list)")
		}
		return
	}

	lastSev := ""
	for _, f := range rep.Findings {
		if f.Triage != "" {
			continue
		}
		sev := strings.ToLower(strings.TrimSpace(f.Severity))
		if sev == "" {
			sev = "info"
		}
		if sev != lastSev {
			fmt.Fprintf(out, "\n%s\n", strings.ToUpper(sev))
			lastSev = sev
		}
		loc := f.FilePath
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.FilePath, f.Line)
		}
		fmt.Fprintf(out, "  %s  [%s]  %s\n", loc, f.RuleID, f.Title)
	}
	if rep.Triaged > 0 {
		fmt.Fprintf(out, "\n%d finding(s) triaged as likely fixtures (test/example/sample paths) — see --format json.\n", rep.Triaged)
	}
}

// severitySummary renders the per-severity breakdown in severity order,
// e.g. "   (critical: 1, high: 2)".
func severitySummary(counts map[string]int) string {
	order := []string{"critical", "high", "medium", "low", "info"}
	var parts []string
	for _, sev := range order {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s: %d", sev, n))
		}
	}
	// Surface any non-standard severities after the known ones, sorted for
	// determinism (map iteration order is random).
	var extras []string
	for sev, n := range counts {
		if n > 0 && !contains(order, sev) {
			extras = append(extras, fmt.Sprintf("%s: %d", sev, n))
		}
	}
	sort.Strings(extras)
	parts = append(parts, extras...)
	if len(parts) == 0 {
		return ""
	}
	return "   (" + strings.Join(parts, ", ") + ")"
}
