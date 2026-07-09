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
					sec := gateSection(res)
					sec.Title = relInRoot(rep.Root, sec.Title) // compact, repo-relative path
					rep2.Sections = append(rep2.Sections, sec)
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

// scanCategory maps a scanner id (scan_secrets, …) to a short human tag shown
// next to each finding so the class is legible without the verbose rule id.
func scanCategory(scan string) string {
	switch scan {
	case "scan_secrets":
		return "secret"
	case "scan_dependencies":
		return "dependency"
	case "scan_dockerfile":
		return "dockerfile"
	case "scan_github_actions":
		return "actions"
	}
	if s := strings.TrimPrefix(scan, "scan_"); s != "" && s != scan {
		return s
	}
	return "finding"
}

// relInRoot renders p relative to root for compact display, falling back to the
// absolute path when it lies outside root.
func relInRoot(root, p string) string {
	if r, err := filepath.Rel(root, p); err == nil && !strings.HasPrefix(r, "..") {
		return r
	}
	return p
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// sevAnsi colours severity accents in an interactive terminal (see colorTo).
var sevAnsi = map[string]string{
	"critical": "\x1b[1;31m",
	"high":     "\x1b[31m",
	"medium":   "\x1b[33m",
	"low":      "\x1b[34m",
	"info":     "\x1b[90m",
}

// renderAuditText prints the ranked, human-readable audit summary: a one-line
// header, a summary line, then confirmed findings grouped by severity and then
// by file (path relative, class tagged). Triaged (likely-fixture) findings are
// summarised as a count so the report reads honest without drowning in samples.
func renderAuditText(c *cobra.Command, rep *audit.Report) {
	out := c.OutOrStdout()
	color := colorTo(out)
	dim := func(s string) string {
		if color {
			return "\x1b[90m" + s + "\x1b[0m"
		}
		return s
	}
	sevAccent := func(sev, s string) string {
		if color {
			if a := sevAnsi[sev]; a != "" {
				return a + s + "\x1b[0m"
			}
		}
		return s
	}

	name := filepath.Base(rep.Root)
	if name == "." || name == "" || name == string(filepath.Separator) {
		name = rep.Root
	}
	fmt.Fprintf(out, "secure-vibe audit %s %s\n", dim("·"), name)

	confirmed := rep.Total()
	if confirmed == 0 {
		line := fmt.Sprintf("No findings %s %d file(s) scanned", dim("·"), rep.FilesScanned)
		if rep.Triaged > 0 {
			line += fmt.Sprintf(" %s +%d triaged (fixtures)", dim("·"), rep.Triaged)
		}
		fmt.Fprintln(out, line)
		return
	}

	// Bucket confirmed findings by severity; count the files they touch.
	buckets := map[string][]audit.Finding{}
	files := map[string]bool{}
	for _, f := range rep.Findings {
		if f.Triage != "" {
			continue
		}
		files[f.FilePath] = true
		sev := strings.ToLower(strings.TrimSpace(f.Severity))
		if sev == "" {
			sev = "info"
		}
		buckets[sev] = append(buckets[sev], f)
	}

	summary := fmt.Sprintf("%d finding%s %s across %d file%s %s %d scanned",
		confirmed, plural(confirmed), strings.TrimSpace(severitySummary(rep.Counts)),
		len(files), plural(len(files)), dim("·"), rep.FilesScanned)
	if rep.Triaged > 0 {
		summary += fmt.Sprintf(" %s +%d triaged", dim("·"), rep.Triaged)
	}
	fmt.Fprintln(out, summary)

	// Severity iteration order: known ranks that are present, then any extras.
	order := []string{"critical", "high", "medium", "low", "info"}
	var sevs []string
	for _, s := range order {
		if len(buckets[s]) > 0 {
			sevs = append(sevs, s)
		}
	}
	var extras []string
	for s := range buckets {
		if !contains(order, s) {
			extras = append(extras, s)
		}
	}
	sort.Strings(extras)
	sevs = append(sevs, extras...)

	for _, sev := range sevs {
		group := buckets[sev]
		sort.SliceStable(group, func(i, j int) bool {
			ri, rj := relInRoot(rep.Root, group[i].FilePath), relInRoot(rep.Root, group[j].FilePath)
			if ri != rj {
				return ri < rj
			}
			return group[i].Line < group[j].Line
		})
		fmt.Fprintf(out, "\n%s\n", sevAccent(sev, strings.ToUpper(sev)))
		lastFile := ""
		for _, f := range group {
			rel := relInRoot(rep.Root, f.FilePath)
			if rel != lastFile {
				fmt.Fprintf(out, "  %s\n", rel)
				lastFile = rel
			}
			cat := scanCategory(f.Scan)
			if f.Line > 0 {
				cat = fmt.Sprintf("%s:%d", cat, f.Line)
			}
			fmt.Fprintf(out, "    %s %s  %s\n", sevAccent(sev, "●"), f.Title, dim("("+cat+")"))
		}
	}

	if rep.Triaged > 0 {
		fmt.Fprintf(out, "\n%s\n", dim(fmt.Sprintf(
			"%d finding(s) triaged as likely fixtures — --no-triage to include, --format json for the list.", rep.Triaged)))
	}
	fmt.Fprintf(out, "\n%s\n", dim("Next: --report-dir out/ (HTML+PDF) · --fail-on high (gate CI) · --format json (rule IDs)"))
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
