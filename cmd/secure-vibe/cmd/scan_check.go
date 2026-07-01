package cmd

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/shieldnet-360/secure-vibe/internal/tools"
)

// scanCmd is the consolidated, report-only scanner. It auto-detects the right
// scanner per file (the same dispatch gate uses) and always exits 0 — the
// former scan-secrets / scan-dependencies / scan-dockerfile / scan-github-actions
// commands are folded into this one. Use `gate` for a CI-failing check.
func scanCmd() *cobra.Command {
	var repoPath, severityFloor, format, vulnSource, sarifBase, report string
	c := &cobra.Command{
		Use:   "scan <file-or-dir>...",
		Short: "Scan files for secrets, bad dependencies, and Dockerfile / GitHub Actions issues (auto-detect, report only)",
		Long: `scan walks the given files or directories, auto-picks the right
scanner per file — dependencies (lockfiles), Dockerfile, GitHub Actions
workflows, falling back to secret detection for any other text file — and
reports every finding. It always exits 0; use 'secure-vibe gate' when you
need a CI-failing check.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := validateFormat(format, true); err != nil {
				return err
			}
			files, err := tools.ExpandGateFiles(args)
			if err != nil {
				return err
			}
			if len(files) == 0 {
				fmt.Fprintf(c.OutOrStdout(), "scan: no scannable files found under %s.\n", strings.Join(args, " "))
				return nil
			}
			var results []*tools.PolicyCheckResult
			for _, file := range files {
				lib, err := newLibraryForCmd(repoPath, vulnSource, file)
				if err != nil {
					return err
				}
				fileAbs, _ := filepath.Abs(file)
				res, err := lib.PolicyCheck(fileAbs, severityFloor)
				if err != nil {
					return err
				}
				results = append(results, res)
			}
			if report != "" {
				rep := newReport("scan", args)
				for _, res := range results {
					rep.Sections = append(rep.Sections, gateSection(res))
				}
				return writeReport(c, report, rep)
			}
			switch format {
			case "json":
				if len(results) == 1 {
					return emitJSON(c.OutOrStdout(), results[0])
				}
				return emitJSON(c.OutOrStdout(), results)
			case "sarif":
				base, err := filepath.Abs(sarifBase)
				if err != nil {
					base = ""
				}
				return emitJSON(c.OutOrStdout(), tools.PolicyCheckSARIF(results, base))
			default:
				total := 0
				for i, res := range results {
					fmt.Fprintf(c.OutOrStdout(), "=== scan %s ===\n", files[i])
					fmt.Fprintf(c.OutOrStdout(), "Scanner used: %s\n", res.Scan)
					fmt.Fprintf(c.OutOrStdout(), "Findings: %d\n", len(res.Findings))
					for sev, n := range res.Counts {
						fmt.Fprintf(c.OutOrStdout(), "  %s: %d\n", sev, n)
					}
					total += len(res.Findings)
				}
				if len(results) > 1 {
					fmt.Fprintf(c.OutOrStdout(), "=== %d file(s), %d finding(s) ===\n", len(results), total)
				}
			}
			return nil
		},
	}
	c.Flags().StringVar(&repoPath, "path", ".", "secure-vibe checkout (default: $SECURE_VIBE_LIBRARY_PATH, else cwd)")
	c.Flags().StringVar(&severityFloor, "severity-floor", "low",
		"only report findings at or above this severity: critical | high | medium | low")
	c.Flags().StringVar(&sarifBase, "sarif-base", ".",
		"directory SARIF artifact URIs are made relative to; only used with --format sarif")
	addFormatFlag(c, &format, true)
	addReportFlag(c, &report)
	addVulnSourceFlag(c, &vulnSource)
	return c
}

// checkCmd is the consolidated single-package lookup. CheckDependency already
// covers malicious entries, typosquats, CVE patterns, and OSV advisories, so
// the former check-dependency / check-typosquat / lookup-vulnerability commands
// are folded into this one.
func checkCmd() *cobra.Command {
	var repoPath, ecosystem, format, vulnSource string
	c := &cobra.Command{
		Use:   "check <package>[@version]",
		Short: "Look up a package for malicious entries, typosquats, CVE patterns, and OSV advisories",
		Long: `check looks up a package in the malicious-packages corpus, the
typosquat database, the curated CVE-pattern list (ecosystem-filtered), and
the OSV advisory set. Pass name@version to constrain OSV matching; with
--vuln-source hybrid|external, live api.osv.dev results are merged in.
Exits 0 always — use 'secure-vibe gate' for a CI-failing scan.`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := validateFormat(format, true); err != nil {
				return err
			}
			if strings.TrimSpace(ecosystem) == "" {
				return fmt.Errorf("--ecosystem is required")
			}
			pkg, version := args[0], ""
			if i := strings.LastIndex(pkg, "@"); i > 0 {
				pkg, version = pkg[:i], pkg[i+1:]
			}
			lib, err := newLibraryForCmd(repoPath, vulnSource, "")
			if err != nil {
				return err
			}
			res, err := lib.CheckDependency(pkg, version, ecosystem)
			if err != nil {
				return err
			}
			switch format {
			case "json":
				return emitJSON(c.OutOrStdout(), res)
			case "sarif":
				return emitJSON(c.OutOrStdout(), tools.CheckDependencySARIF(res))
			default:
				return renderCheckDependencyText(c.OutOrStdout(), res)
			}
		},
	}
	c.Flags().StringVar(&repoPath, "path", ".", "secure-vibe checkout (default: $SECURE_VIBE_LIBRARY_PATH, else cwd)")
	c.Flags().StringVarP(&ecosystem, "ecosystem", "e", "",
		"package ecosystem: npm, pypi, crates, go, rubygems, maven, nuget, composer, pub, swift, github-actions, docker (required)")
	addFormatFlag(c, &format, true)
	addVulnSourceFlag(c, &vulnSource)
	return c
}
