package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/shieldnet-360/secure-vibe/internal/audit"
	"github.com/shieldnet-360/secure-vibe/internal/tools"
)

// auditCmd is THE scanning command: it fans SecureVibe's deterministic scanners
// (secrets, dependencies, Dockerfile, GitHub Actions) across the given paths — a
// whole tree by default, or a PR's changed set with --diff — then deduplicates,
// ranks by severity, and triages likely fixtures (test/example paths reported but
// demoted). It reports by default (exit 0) and gates CI with --fail-on. It is
// deterministic and offline; AI reasoning and dynamic verification are the job of
// the coding agent driving SecureVibe, not the binary.
func auditCmd() *cobra.Command {
	var repoPath, severityFloor, format, vulnSource, sarifBase, report, diff, failOn string
	var jobs int
	var noTriage bool
	c := &cobra.Command{
		Use:   "audit [path...]",
		Short: "Security audit: fan out every scanner across the tree, dedup, rank, and triage findings",
		Long: `audit runs SecureVibe's deterministic scanners across the given paths
(secrets, dependencies, Dockerfile, GitHub Actions), deduplicates and ranks the
findings by severity, and applies a false-positive triage pass — findings in
test / fixture / example paths are reported but demoted below confirmed ones.

With no path it audits the current directory; pass files or directories to narrow
it, or --diff to audit only a PR's changed set. It reports and exits 0 by default;
add --fail-on <severity> to make it a CI gate. Use --no-triage for a strict gate
that treats fixtures like any other finding.`,
		Args: cobra.ArbitraryArgs,
		RunE: func(c *cobra.Command, args []string) error {
			if err := validateFormat(format, true); err != nil {
				return err
			}
			raw := args
			if len(raw) == 0 {
				raw = []string{"."}
			}
			targets := make([]string, 0, len(raw))
			for _, t := range raw {
				abs, err := filepath.Abs(t)
				if err != nil {
					return fmt.Errorf("resolve audit path %q: %w", t, err)
				}
				targets = append(targets, abs)
			}

			// Audit surface: the given paths, or — with --diff — only the files
			// that changed vs a git ref (a PR's changed set).
			var files []string
			var err error
			if strings.TrimSpace(diff) != "" {
				root := dirOf(targets[0])
				changed, cerr := changedFiles(root, diff)
				if cerr != nil {
					return fmt.Errorf("--diff: %w", cerr)
				}
				if len(changed) == 0 {
					fmt.Fprintf(c.OutOrStdout(), "audit: no changed files vs %s.\n", diff)
					return nil
				}
				fmt.Fprintf(c.ErrOrStderr(), "audit: diff mode vs %s — %d changed file(s)\n", diff, len(changed))
				files, err = tools.ExpandGateFiles(changed)
			} else {
				files, err = tools.ExpandGateFiles(targets)
			}
			if err != nil {
				return err
			}
			if len(files) == 0 {
				fmt.Fprintf(c.OutOrStdout(), "audit: no scannable files under %s.\n", strings.Join(raw, " "))
				return nil
			}

			// One library per worker, each sandboxed to the audited paths so the
			// file scanners may read anything under them.
			allowed := allowedRootsFor(targets)
			newLib := func() (*tools.Library, error) {
				lib, err := newLibraryForCmd(repoPath, vulnSource, "")
				if err != nil {
					return nil, err
				}
				if err := lib.SetAllowedRoots(allowed); err != nil {
					return nil, fmt.Errorf("scope library to %s: %w", strings.Join(allowed, ", "), err)
				}
				return lib, nil
			}

			rep, err := audit.Run(c.Context(), files, newLib, audit.Options{
				Root:          targets[0],
				SeverityFloor: severityFloor,
				Jobs:          jobs,
				NoTriage:      noTriage,
			})
			if err != nil {
				return err
			}

			// Emit the report first (so a failing gate still publishes its
			// findings), then apply --fail-on.
			switch {
			case report != "":
				rep2 := newReport("audit", raw)
				for _, res := range rep.Results {
					rep2.Sections = append(rep2.Sections, gateSection(res))
				}
				if err := writeReport(c, report, rep2); err != nil {
					return err
				}
			case format == "json":
				if err := emitJSON(c.OutOrStdout(), rep); err != nil {
					return err
				}
			case format == "sarif":
				base, err := filepath.Abs(sarifBase)
				if err != nil {
					base = ""
				}
				if err := emitJSON(c.OutOrStdout(), rep.SARIF(base)); err != nil {
					return err
				}
			default:
				renderAuditText(c, rep)
			}

			// CI gate: exit non-zero when confirmed findings meet --fail-on.
			if strings.TrimSpace(failOn) != "" {
				if n := rep.CountAtOrAbove(failOn); n > 0 {
					c.SilenceUsage = true
					return &policyFailureError{count: n, floor: failOn}
				}
			}
			return nil
		},
	}
	c.Flags().StringVar(&repoPath, "path", ".", "secure-vibe library checkout (default: $SECURE_VIBE_LIBRARY_PATH, else cwd)")
	c.Flags().StringVar(&diff, "diff", "",
		"audit only files changed vs a git ref (a PR's changed set); bare --diff diffs vs HEAD, or pass a ref e.g. --diff origin/main")
	c.Flags().Lookup("diff").NoOptDefVal = "HEAD" // bare `--diff` == `--diff HEAD`
	c.Flags().StringVar(&severityFloor, "severity-floor", "low",
		"only collect findings at or above this severity: critical | high | medium | low")
	c.Flags().StringVar(&failOn, "fail-on", "",
		"exit non-zero when a confirmed finding is at or above this severity (critical|high|medium|low) — turns audit into a CI gate; empty = always exit 0")
	c.Flags().BoolVar(&noTriage, "no-triage", false,
		"do not demote fixtures — a strict gate that treats test/example findings like any other")
	c.Flags().IntVar(&jobs, "jobs", 0, "concurrent scanner workers (default: min(NumCPU, 8))")
	c.Flags().StringVar(&sarifBase, "sarif-base", ".",
		"directory SARIF artifact URIs are made relative to; only used with --format sarif")
	addFormatFlag(c, &format, true)
	addReportFlag(c, &report)
	addVulnSourceFlag(c, &vulnSource)
	return c
}

// dirOf returns p if it is a directory (or unknown), else its parent — used to
// pick a git root for --diff when a file path is given.
func dirOf(p string) string {
	if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
		return filepath.Dir(p)
	}
	return p
}

// allowedRootsFor is the sandbox for the scanners: each target dir (or a file's
// parent), deduplicated.
func allowedRootsFor(targets []string) []string {
	seen := map[string]bool{}
	var roots []string
	for _, t := range targets {
		r := dirOf(t)
		if !seen[r] {
			seen[r] = true
			roots = append(roots, r)
		}
	}
	return roots
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
		fmt.Fprintf(out, "\n%d finding(s) triaged as likely fixtures — see --format json (or --no-triage to include them).\n", rep.Triaged)
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
