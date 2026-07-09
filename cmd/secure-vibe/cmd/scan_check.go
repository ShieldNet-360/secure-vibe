package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/shieldnet-360/secure-vibe/internal/tools"
)

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
