package cmd

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/shieldnet-360/secure-vibe/internal/audit"
	"github.com/shieldnet-360/secure-vibe/internal/llm"
	"github.com/shieldnet-360/secure-vibe/internal/tools"
)

// auditCmd is the whole-tree orchestration layer above `gate`. It fans the same
// deterministic scanners out across an entire directory concurrently, then
// deduplicates, ranks, and triages the findings into one report. No new
// detection logic and no network — it is a strict superset of `gate` that runs
// offline. The model-pluggable LLM lanes and dynamic verify layer on top of the
// Report it produces (see later phases).
func auditCmd() *cobra.Command {
	var repoPath, severityFloor, format, vulnSource, sarifBase, report, model, diff, failOn string
	var liveTarget, liveParam, liveMethod string
	var jobs, votes int
	var thorough, confirm bool
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
			// Audit surface: the whole tree, or — with --diff — only the files
			// that changed vs a git ref (a PR's changed set).
			var targets []string
			if strings.TrimSpace(diff) != "" {
				changed, err := changedFiles(rootAbs, diff)
				if err != nil {
					return fmt.Errorf("--diff: %w", err)
				}
				if len(changed) == 0 {
					fmt.Fprintf(c.OutOrStdout(), "audit: no changed files vs %s.\n", diff)
					return nil
				}
				targets = changed
				fmt.Fprintf(c.ErrOrStderr(), "audit: diff mode vs %s — %d changed file(s)\n", diff, len(changed))
			} else {
				targets = []string{rootAbs}
			}
			files, err := tools.ExpandGateFiles(targets)
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

			// Optional model lane (BYO). Provider comes from SECURE_VIBE_MODEL_*,
			// with --model overriding the provider name. No provider => offline,
			// deterministic-only audit (Phase 1 behaviour).
			cfg := llm.FromEnv()
			if strings.TrimSpace(model) != "" {
				cfg.Provider = model
			}
			var (
				reviewer   audit.Reviewer
				sweepFiles []string
			)
			if cfg.Enabled() {
				prov, err := llm.New(cfg)
				if err != nil {
					return err
				}
				lensLib, err := newLibraryForCmd(repoPath, vulnSource, "")
				if err != nil {
					return err
				}
				reviewer = &audit.LLMReviewer{Provider: prov, Lens: buildLens(lensLib), Votes: votes}
				var capped int
				sweepFiles, capped = sourceFiles(files)
				fmt.Fprintf(c.ErrOrStderr(), "audit: model lane on (%s) — semantic sweep of %d source files, refute votes=%d\n",
					prov.Name(), len(sweepFiles), max(votes, 1))
				if capped > 0 {
					fmt.Fprintf(c.ErrOrStderr(), "audit: %d further source files skipped from the sweep (cap %d)\n", capped, maxSweepFiles)
				}
			}

			rep, err := audit.Run(c.Context(), files, newLib, audit.Options{
				Root:          rootAbs,
				SeverityFloor: severityFloor,
				Jobs:          jobs,
				Reviewer:      reviewer,
				SweepFiles:    sweepFiles,
				Thorough:      thorough,
			})
			if err != nil {
				return err
			}

			// Optional dynamic verify lane: probe dynamically-verifiable findings
			// against a live target. Dry-run unless --confirm AND the target is in
			// SECURE_VIBE_VERIFY_SCOPE.
			if strings.TrimSpace(liveTarget) != "" {
				n := runDynamicVerify(c.Context(), rep, liveTarget, liveParam, liveMethod, confirm)
				rep.Rebuild()
				mode := "dry-run"
				if confirm {
					mode = "live (scope-gated)"
				}
				fmt.Fprintf(c.ErrOrStderr(), "audit: dynamic verify probed %d finding(s) against %s [%s]\n", n, liveTarget, mode)
			}

			// Emit the report first (so a failing gate still publishes its
			// findings), then apply --fail-on.
			switch {
			case report != "":
				rep2 := newReport("audit", []string{root})
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
				// Full-lane: includes the model-semantic findings and excludes
				// triaged/refuted ones (see audit.Report.SARIF).
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
	c.Flags().StringVar(&model, "model", "",
		"enable the model lane with this provider: anthropic | openai | gemini | openai-compatible (model id + key come from SECURE_VIBE_MODEL / _API_KEY / _BASE_URL). Off by default")
	c.Flags().StringVar(&failOn, "fail-on", "",
		"exit non-zero when a confirmed finding is at or above this severity (critical|high|medium|low) — turns audit into a CI gate; empty = always exit 0")
	c.Flags().IntVar(&votes, "votes", 1, "adversarial refute rounds per finding in the model lane (majority rules)")
	c.Flags().BoolVar(&thorough, "thorough", false, "run completeness-critic sweep rounds (loop-until-dry); requires --model")
	c.Flags().StringVar(&liveTarget, "live-target", "", "base URL to dynamically probe dynamically-verifiable findings (ssrf/sqli/xss/…) against")
	c.Flags().StringVar(&liveParam, "live-param", "", "parameter believed injectable, for the dynamic verify probe")
	c.Flags().StringVar(&liveMethod, "live-method", "", "HTTP method for the dynamic verify probe (default GET)")
	c.Flags().BoolVar(&confirm, "confirm", false, "actually send verify probes (default dry-run); still gated by SECURE_VIBE_VERIFY_SCOPE")
	c.Flags().IntVar(&jobs, "jobs", 0, "concurrent scanner workers (default: min(NumCPU, 8))")
	c.Flags().StringVar(&sarifBase, "sarif-base", ".",
		"directory SARIF artifact URIs are made relative to; only used with --format sarif")
	addFormatFlag(c, &format, true)
	addReportFlag(c, &report)
	addVulnSourceFlag(c, &vulnSource)
	return c
}

// maxSweepFiles bounds how many source files the semantic sweep sends to the
// model, keeping a --model run's cost predictable on large repos.
const maxSweepFiles = 300

// sourceExts are the file types worth a semantic sweep (the deterministic lane
// already covers lockfiles, Dockerfiles, and workflow YAML).
var sourceExts = map[string]bool{
	".go": true, ".js": true, ".jsx": true, ".ts": true, ".tsx": true,
	".py": true, ".rb": true, ".php": true, ".java": true, ".kt": true,
	".rs": true, ".c": true, ".cc": true, ".cpp": true, ".h": true, ".hpp": true,
	".cs": true, ".scala": true, ".swift": true, ".m": true, ".mm": true,
	".sh": true, ".sql": true, ".vue": true, ".svelte": true,
}

// sourceFiles selects the source-code subset for the semantic sweep, capping the
// count. capped is how many eligible files were dropped past the cap.
func sourceFiles(files []string) (picked []string, capped int) {
	var all []string
	for _, f := range files {
		if sourceExts[strings.ToLower(filepath.Ext(f))] {
			all = append(all, f)
		}
	}
	if len(all) > maxSweepFiles {
		return all[:maxSweepFiles], len(all) - maxSweepFiles
	}
	return all, 0
}

// buildLens compiles a compact catalogue of the library's skills (title +
// description) to prime the model with SecureVibe's taxonomy of vulnerability
// classes. Capped so prompts stay bounded.
func buildLens(lib *tools.Library) string {
	res, err := lib.SearchSkills("")
	if err != nil {
		return ""
	}
	var sb strings.Builder
	for _, m := range res.Skills {
		fmt.Fprintf(&sb, "- %s: %s\n", m.Title, m.Description)
		if sb.Len() > 8000 {
			break
		}
	}
	return sb.String()
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
		fmt.Fprintf(out, "  %s  [%s]  %s%s\n", loc, f.RuleID, f.Title, verifyMarker(f.Verify))
	}
	if rep.Triaged > 0 {
		fmt.Fprintf(out, "\n%d finding(s) triaged as likely fixtures / refuted — see --format json.\n", rep.Triaged)
	}
	if n := dynamicVerifiable(rep); n > 0 && !anyVerified(rep) {
		fmt.Fprintf(out, "\n%d finding(s) are dynamically verifiable — re-run with --live-target <url> "+
			"(and SECURE_VIBE_VERIFY_SCOPE + --confirm to probe live).\n", n)
	}
}

// verifyMarker renders the dynamic verify verdict inline, e.g. " {verify: confirmed}".
func verifyMarker(v *audit.VerifyInfo) string {
	if v == nil {
		return ""
	}
	switch {
	case v.Confirmed:
		return "  {verify: CONFIRMED}"
	case v.Refuted:
		return "  {verify: refuted}"
	case v.DryRun:
		return "  {verify: dry-run plan}"
	default:
		return "  {verify: inconclusive}"
	}
}

func anyVerified(rep *audit.Report) bool {
	for _, f := range rep.Findings {
		if f.Verify != nil {
			return true
		}
	}
	return false
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
