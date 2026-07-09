// CLI wrappers around the eight secure-vibe mcp tools that operate on data
// or files: check-dependency, check-typosquat, lookup-vulnerability,
// scan-secrets, scan-dependencies, scan-dockerfile,
// scan-github-actions, and policy-check.
//
// These wrappers exist so contributors can drive the security tools
// from the terminal, shell scripts, and pre-commit hooks without
// having to speak JSON-RPC to secure-vibe mcp. The shared Library code
// path means the CLI and MCP server produce identical findings —
// these subcommands are 100% thin adapters, not a second
// implementation.
//
// Three concerns are common across the eight subcommands and live in
// helpers here:
//
//   * library construction with --vuln-source threading, so the new
//     "hybrid OSV.dev enrichment" path is reachable from the terminal
//     the same way it is from MCP;
//   * file-based scan path sandboxing — every file-taking command
//     scopes the Library's allowed-roots to the file's parent so the
//     CLI inherits the same fail-safe sensitive-path deny-list the
//     MCP server uses;
//   * output formatting — text (default, human-readable) / json
//     (machine-readable, identical schema to the MCP response) /
//     sarif (CI ingestion).

package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/shieldnet-360/secure-vibe/internal/tools"
)

// supportedOutputFormats enumerates the values accepted by the
// --format flag on every subcommand. text is the human-readable
// default; json mirrors the MCP server's response payload (same
// types, same field names); sarif is only emitted for the
// subcommands whose Library counterpart already ships a SARIF
// transformer (the five *SARIF functions in cmd/secure-vibe/internal/
// tools/sarif*.go).
var supportedOutputFormats = map[string]bool{
	"text":  true,
	"json":  true,
	"sarif": true,
}

// resolveLibraryRoot picks the secure-vibe checkout the file
// scanners read their rule data from. Precedence:
//
//  1. an explicit --path (anything other than the "." default);
//  2. $SECURE_VIBE_LIBRARY_PATH, so the CLI can run inside an arbitrary
//     project (CI, pre-commit, a hook) while pointed at a bundled data
//     tree — mirroring how cmd/secure-vibe resolves its own root;
//  3. the current working directory, when it is itself a checkout (the
//     in-repo contributor default — kept ahead of the data dir so a
//     contributor's working tree always wins);
//  4. the per-user default data dir (tools.DefaultDataDir), which
//     install.sh populates with the release data tarball — so a binary
//     installed via `curl | sh` works from any project without --path.
//
// Treating the "." default the same as "unset" is deliberate: a bare
// `secure-vibe scan-dockerfile Dockerfile` run from a user's project
// should fall through to the env / data dir, not fail because that
// project has no skills/ tree of its own. The final "." keeps the old
// behaviour (and surfaces the helpful "no skills/" error) when nothing
// is configured and no data dir exists.
func resolveLibraryRoot(flagVal string) string {
	if flagVal != "" && flagVal != "." {
		return flagVal
	}
	if env := strings.TrimSpace(os.Getenv("SECURE_VIBE_LIBRARY_PATH")); env != "" {
		return env
	}
	if tools.IsLibraryRoot(".") {
		return "."
	}
	if d := tools.DefaultDataDir(); tools.IsLibraryRoot(d) {
		return d
	}
	return "."
}

// newLibraryForCmd constructs a Library suitable for one CLI run.
// vulnSourceStr is parsed via tools.ParseVulnSource; an empty string
// resolves to SourceLocal, matching the secure-vibe mcp default. fileArg,
// when non-empty, contributes its parent directory to the Library's
// allowed-roots so file-based scanners can read it without the user
// having to remember the security flag dance.
func newLibraryForCmd(repoPath, vulnSourceStr, fileArg string) (*tools.Library, error) {
	root := resolveLibraryRoot(repoPath)
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve --path %q: %w", root, err)
	}
	vulnSource, err := tools.ParseVulnSource(vulnSourceStr)
	if err != nil {
		return nil, err
	}
	opts := []tools.LibraryOption{tools.WithVulnSource(vulnSource)}
	lib, err := tools.NewLibrary(abs, opts...)
	if err != nil {
		return nil, err
	}
	if fileArg != "" {
		fileAbs, err := filepath.Abs(fileArg)
		if err != nil {
			return nil, fmt.Errorf("resolve file path %q: %w", fileArg, err)
		}
		if err := lib.SetAllowedRoots([]string{filepath.Dir(fileAbs)}); err != nil {
			return nil, fmt.Errorf("scope library to %s: %w", filepath.Dir(fileAbs), err)
		}
	}
	return lib, nil
}

// emitJSON writes obj as indented JSON. Used by every subcommand when
// the user asked for --format json or when text formatting is not
// supported for this result shape.
func emitJSON(w io.Writer, obj any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(obj)
}

// addVulnSourceFlag registers --vuln-source on a Cobra command,
// targeting *dst. The flag is only meaningful for the subcommands
// whose Library counterpart consults OSV; we register it on the
// commands that do (everything operating on packages or lockfiles)
// and omit it from the file-only scanners (secrets, dockerfile,
// github-actions, policy-check) where OSV is not consulted.
func addVulnSourceFlag(c *cobra.Command, dst *string) {
	c.Flags().StringVar(dst, "vuln-source", "local",
		"where OSV advisory lookups read from: 'local' (no network), 'external' (api.osv.dev), or 'hybrid' (external first, fall back to local). Default 'local' matches secure-vibe mcp.")
}

// addFormatFlag registers --format on a Cobra command, validating
// against supportedOutputFormats. allowSARIF controls whether 'sarif'
// is an acceptable value — only the five subcommands whose Library
// has a SARIF transformer pass true.
func addFormatFlag(c *cobra.Command, dst *string, allowSARIF bool) {
	options := []string{"text", "json"}
	if allowSARIF {
		options = append(options, "sarif")
	}
	c.Flags().StringVar(dst, "format", "text",
		"output format: "+strings.Join(options, " | "))
}

// validateFormat rejects --format values the subcommand does not
// support. Done at the top of RunE so the failure mode is obvious
// before any library work happens.
func validateFormat(format string, allowSARIF bool) error {
	if !supportedOutputFormats[format] {
		return fmt.Errorf("unknown --format %q (want text, json%s)", format,
			ternary(allowSARIF, ", or sarif", ""))
	}
	if format == "sarif" && !allowSARIF {
		return fmt.Errorf("--format sarif is not supported for this command")
	}
	return nil
}

func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

// =============================================================================
// check-dependency
// =============================================================================

func checkDependencyCmd() *cobra.Command {
	var (
		repoPath, pkg, version, ecosystem, format, vulnSource string
	)
	c := &cobra.Command{
		Use:   "check-dependency",
		Short: "Check a package@version for known malicious entries, typosquats, CVE patterns, and OSV advisories",
		Long: `check-dependency wraps the secure-vibe mcp check_dependency tool.

It looks up the named package in the malicious-packages corpus, the
typosquat database, the curated CVE-pattern list (ecosystem-language
filtered to avoid false matches like Java CVEs for an npm query), and
the OSV advisory set. With --vuln-source hybrid (or external), live
api.osv.dev results are merged in too.

Returns exit 0 always; the result still lists findings — use
'secure-vibe gate' when you need a CI-failing scan.`,
		RunE: func(c *cobra.Command, args []string) error {
			if err := validateFormat(format, true); err != nil {
				return err
			}
			if strings.TrimSpace(pkg) == "" {
				return fmt.Errorf("--package is required")
			}
			if strings.TrimSpace(ecosystem) == "" {
				return fmt.Errorf("--ecosystem is required")
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
	c.Flags().StringVarP(&pkg, "package", "p", "", "package name (required)")
	c.Flags().StringVarP(&version, "version", "v", "", "package version (optional; constrains OSV matching)")
	c.Flags().StringVarP(&ecosystem, "ecosystem", "e", "", "package ecosystem: npm, pypi, crates, go, rubygems, maven, nuget, composer, pub, swift, github-actions, docker (required)")
	addFormatFlag(c, &format, true)
	addVulnSourceFlag(c, &vulnSource)
	return c
}

func renderCheckDependencyText(w io.Writer, res *tools.CheckDependencyResult) error {
	fmt.Fprintf(w, "=== check %s@%s (%s) ===\n", res.Package, res.Version, res.Ecosystem)
	fmt.Fprintf(w, "Malicious entries:  %d\n", len(res.Malicious))
	fmt.Fprintf(w, "Typosquat matches:  %d\n", len(res.Typosquats))
	fmt.Fprintf(w, "CVE pattern hits:   %d\n", len(res.CVEs))
	fmt.Fprintf(w, "OSV advisories:     %d\n", len(res.OSVAdvisories))
	for _, m := range res.Malicious {
		fmt.Fprintf(w, "  ! MALICIOUS  [%s]  %s — %s\n", m.Severity, m.Name, m.Description)
	}
	for _, t := range res.Typosquats {
		fmt.Fprintf(w, "  ! TYPOSQUAT  of %s (distance %d, %s)\n", t.Target, t.LevenshteinDistance, t.Status)
	}
	for _, cve := range res.CVEs {
		fmt.Fprintf(w, "  ! CVE        [%s]  %s — %s\n", cve.Severity, cve.CVE, cve.Name)
	}
	for _, a := range res.OSVAdvisories {
		fmt.Fprintf(w, "  ! OSV        [%s]  %s — %s\n", a.Severity, a.ID, a.Summary)
	}
	return nil
}

// =============================================================================
// check-typosquat
// =============================================================================

func checkTyposquatCmd() *cobra.Command {
	var repoPath, pkg, ecosystem, format string
	c := &cobra.Command{
		Use:   "check-typosquat",
		Short: "Flag candidate typosquats against the curated DB plus a Levenshtein-2 sweep over popular packages",
		RunE: func(c *cobra.Command, args []string) error {
			if err := validateFormat(format, false); err != nil {
				return err
			}
			if strings.TrimSpace(pkg) == "" {
				return fmt.Errorf("--package is required")
			}
			lib, err := newLibraryForCmd(repoPath, "", "")
			if err != nil {
				return err
			}
			res, err := lib.CheckTyposquat(pkg, ecosystem)
			if err != nil {
				return err
			}
			switch format {
			case "json":
				return emitJSON(c.OutOrStdout(), res)
			default:
				fmt.Fprintf(c.OutOrStdout(), "=== check-typosquat %s (%s) ===\n", res.Package, res.Ecosystem)
				fmt.Fprintf(c.OutOrStdout(), "Curated DB matches:        %d\n", len(res.Typosquats))
				fmt.Fprintf(c.OutOrStdout(), "Runtime Levenshtein hits:  %d\n", len(res.PotentialTyposquats))
				for _, t := range res.Typosquats {
					fmt.Fprintf(c.OutOrStdout(), "  ! curated: target=%s squat=%s ecosystem=%s status=%s\n", t.Target, t.Typosquat, t.Ecosystem, t.Status)
				}
				for _, p := range res.PotentialTyposquats {
					fmt.Fprintf(c.OutOrStdout(), "  ? potential: target=%s ecosystem=%s distance=%d confidence=%s\n", p.Target, p.Ecosystem, p.Distance, p.Confidence)
				}
				return nil
			}
		},
	}
	c.Flags().StringVar(&repoPath, "path", ".", "secure-vibe checkout (default: $SECURE_VIBE_LIBRARY_PATH, else cwd)")
	c.Flags().StringVarP(&pkg, "package", "p", "", "package name to check (required)")
	c.Flags().StringVarP(&ecosystem, "ecosystem", "e", "", "package ecosystem (optional; empty searches all)")
	addFormatFlag(c, &format, false)
	return c
}

// =============================================================================
// lookup-vulnerability
// =============================================================================

func lookupVulnerabilityCmd() *cobra.Command {
	var repoPath, pkg, ecosystem, version, format, vulnSource string
	c := &cobra.Command{
		Use:   "lookup-vulnerability",
		Short: "Search the supply-chain malicious-packages corpus + OSV advisories for a package",
		RunE: func(c *cobra.Command, args []string) error {
			if err := validateFormat(format, false); err != nil {
				return err
			}
			if strings.TrimSpace(pkg) == "" {
				return fmt.Errorf("--package is required")
			}
			lib, err := newLibraryForCmd(repoPath, vulnSource, "")
			if err != nil {
				return err
			}
			res, err := lib.LookupVulnerability(pkg, ecosystem, version)
			if err != nil {
				return err
			}
			switch format {
			case "json":
				return emitJSON(c.OutOrStdout(), res)
			default:
				fmt.Fprintf(c.OutOrStdout(), "=== lookup-vulnerability %s (%s) ===\n", res.Package, res.Ecosystem)
				fmt.Fprintf(c.OutOrStdout(), "Malicious matches:  %d\n", len(res.Matches))
				fmt.Fprintf(c.OutOrStdout(), "Typosquat matches:  %d\n", len(res.Typosquats))
				fmt.Fprintf(c.OutOrStdout(), "OSV advisories:     %d\n", len(res.OSVAdvisories))
				for _, m := range res.Matches {
					fmt.Fprintf(c.OutOrStdout(), "  ! [%s] %s — %s\n", m.Severity, m.Name, m.Description)
				}
				for _, a := range res.OSVAdvisories {
					fmt.Fprintf(c.OutOrStdout(), "  ! OSV [%s] %s — %s\n", a.Severity, a.ID, a.Summary)
				}
				return nil
			}
		},
	}
	c.Flags().StringVar(&repoPath, "path", ".", "secure-vibe checkout (default: $SECURE_VIBE_LIBRARY_PATH, else cwd)")
	c.Flags().StringVarP(&pkg, "package", "p", "", "package name (required)")
	c.Flags().StringVarP(&ecosystem, "ecosystem", "e", "", "ecosystem (optional; empty searches all)")
	c.Flags().StringVarP(&version, "version", "v", "", "version (optional)")
	addFormatFlag(c, &format, false)
	addVulnSourceFlag(c, &vulnSource)
	return c
}

// =============================================================================
// scan-secrets
// =============================================================================

func scanSecretsCmd() *cobra.Command {
	var repoPath, format, report string
	c := &cobra.Command{
		Use:   "scan-secrets <file-or-dir>",
		Short: "Secret-detection scan of a file (or, recursively, a directory of text files) for credentials, API keys, tokens, and PEM material",
		Long: `Secret-detection scan of a file, or recursively of a directory of text
files, for credentials, API keys, tokens, and PEM material.

` + reportHelpParagraph,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := validateFormat(format, true); err != nil {
				return err
			}
			target := args[0]
			lib, err := newLibraryForCmd(repoPath, "", target)
			if err != nil {
				return err
			}
			targetAbs, _ := filepath.Abs(target)
			info, err := os.Stat(targetAbs)
			if err != nil {
				return fmt.Errorf("scan-secrets: stat %s: %w", target, err)
			}

			// Single file: behaviour is unchanged from the original
			// implementation (label echoes the raw argument).
			if !info.IsDir() {
				res, err := lib.ScanSecrets("", targetAbs)
				if err != nil {
					return err
				}
				if report != "" {
					rep := newReport("scan-secrets", []string{target})
					rep.Sections = append(rep.Sections, secretSection(target, res))
					return writeReport(c, report, rep)
				}
				switch format {
				case "json":
					return emitJSON(c.OutOrStdout(), res)
				case "sarif":
					return emitJSON(c.OutOrStdout(), tools.ScanSecretsSARIF(res))
				default:
					printScanSecretsText(c.OutOrStdout(), target, res)
					return nil
				}
			}

			// Directory: scope the allow-list to the directory itself so
			// every descendant passes validateScanPath, then walk it and
			// scan each text file. Per-file ScanSecrets calls keep their
			// full policy enforcement (size cap, sensitive-path deny-list,
			// symlink resolution); files that fail are reported on stderr
			// and skipped so one bad file never aborts the whole scan.
			if err := lib.SetAllowedRoots([]string{targetAbs}); err != nil {
				return fmt.Errorf("scan-secrets: scope library to %s: %w", targetAbs, err)
			}
			results, err := scanSecretsDir(c, lib, targetAbs)
			if err != nil {
				return err
			}
			if report != "" {
				rep := newReport("scan-secrets", []string{target})
				for _, res := range results {
					rep.Sections = append(rep.Sections, secretSection(res.FilePath, res))
				}
				return writeReport(c, report, rep)
			}
			switch format {
			case "json":
				return emitJSON(c.OutOrStdout(), results)
			case "sarif":
				log := &tools.SARIFLog{
					Schema:  tools.SARIFSchema,
					Version: tools.SARIFVersion,
					Runs:    []tools.SARIFRun{},
				}
				for _, res := range results {
					log.Runs = append(log.Runs, tools.ScanSecretsSARIF(res).Runs...)
				}
				return emitJSON(c.OutOrStdout(), log)
			default:
				// Only files with matches are printed; clean files would
				// just be noise across a large tree. The summary still
				// reports the full count scanned.
				total := 0
				for _, res := range results {
					if len(res.Matches) == 0 {
						continue
					}
					printScanSecretsText(c.OutOrStdout(), res.FilePath, res)
					total += len(res.Matches)
				}
				fmt.Fprintf(c.OutOrStdout(), "Scanned %d text file(s); %d match(es) total\n",
					len(results), total)
				return nil
			}
		},
	}
	c.Flags().StringVar(&repoPath, "path", ".", "secure-vibe checkout for rule data (default: $SECURE_VIBE_LIBRARY_PATH, else cwd)")
	addFormatFlag(c, &format, true)
	addReportFlag(c, &report)
	return c
}

// printScanSecretsText renders one ScanSecretsResult in the
// human-readable --format text shape. Extracted so the single-file
// and directory code paths emit byte-identical per-file output.
func printScanSecretsText(w io.Writer, label string, res *tools.ScanSecretsResult) {
	fmt.Fprintf(w, "=== scan-secrets %s ===\n", label)
	fmt.Fprintf(w, "Matches: %d\n", len(res.Matches))
	for _, m := range res.Matches {
		kfp := ""
		if m.KnownFalsePositive {
			kfp = "  (known-FP)"
		}
		fmt.Fprintf(w, "  ! [%s] %s at offset %d-%d%s\n",
			m.Severity, m.Name, m.Start, m.End, kfp)
	}
}

// scanSecretsDir runs ScanSecrets on every text file beneath dir,
// discovered via the shared tools.WalkScanFiles walker (noise dirs,
// non-regular entries, and empty/oversized/binary files are pruned
// there). Per-file scan errors — e.g. a path inside a sensitive
// directory — are reported on stderr and skipped rather than aborting.
func scanSecretsDir(c *cobra.Command, lib *tools.Library, dir string) ([]*tools.ScanSecretsResult, error) {
	files, err := tools.WalkScanFiles(dir, nil)
	if err != nil {
		return nil, fmt.Errorf("scan-secrets: walk %s: %w", dir, err)
	}
	results := make([]*tools.ScanSecretsResult, 0, len(files))
	for _, path := range files {
		res, err := lib.ScanSecrets("", path)
		if err != nil {
			fmt.Fprintf(c.ErrOrStderr(), "scan-secrets: skip %s: %v\n", path, err)
			continue
		}
		results = append(results, res)
	}
	return results, nil
}

// =============================================================================
// scan-dependencies
// =============================================================================

func scanDependenciesCmd() *cobra.Command {
	var repoPath, format, vulnSource, report string
	c := &cobra.Command{
		Use:   "scan-dependencies <lockfile-or-dir>",
		Short: "Parse a lockfile (or auto-discover lockfiles under a directory) and check every resolved (name, version) against malicious / typosquat / CVE / OSV databases",
		Long: `Supported lockfiles: package-lock.json, npm-shrinkwrap.json,
yarn.lock, pnpm-lock.yaml, requirements*.txt, Pipfile.lock,
poetry.lock, go.sum, Cargo.lock, pom.xml, gradle.lockfile,
build.gradle.lockfile, packages.lock.json, *.csproj / *.fsproj /
*.vbproj, Gemfile.lock, composer.lock, Package.resolved, and
pubspec.lock.

Pass a single lockfile to scan just that file, or a directory to
auto-discover and scan every recognised lockfile beneath it
(node_modules, vendor, and .git are skipped). Scanning a directory
with no recognised lockfile is an error.

` + reportHelpParagraph,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := validateFormat(format, true); err != nil {
				return err
			}
			target := args[0]
			lib, err := newLibraryForCmd(repoPath, vulnSource, target)
			if err != nil {
				return err
			}
			targetAbs, _ := filepath.Abs(target)
			info, err := os.Stat(targetAbs)
			if err != nil {
				return fmt.Errorf("scan-dependencies: stat %s: %w", target, err)
			}

			// Single lockfile: behaviour is unchanged.
			if !info.IsDir() {
				res, err := lib.ScanDependencies(targetAbs)
				if err != nil {
					return err
				}
				if report != "" {
					rep := newReport("scan-dependencies", []string{target})
					rep.Sections = append(rep.Sections, dependencySection(res))
					return writeReport(c, report, rep)
				}
				switch format {
				case "json":
					return emitJSON(c.OutOrStdout(), res)
				case "sarif":
					return emitJSON(c.OutOrStdout(), tools.ScanDependenciesSARIF(res))
				default:
					printScanDependenciesText(c.OutOrStdout(), target, res)
					return nil
				}
			}

			// Directory: scope the allow-list to the directory and
			// auto-discover every recognised lockfile beneath it.
			if err := lib.SetAllowedRoots([]string{targetAbs}); err != nil {
				return fmt.Errorf("scan-dependencies: scope library to %s: %w", targetAbs, err)
			}
			lockfiles, err := discoverLockfiles(targetAbs)
			if err != nil {
				return err
			}
			if len(lockfiles) == 0 {
				return fmt.Errorf("scan-dependencies: no recognised lockfile found under %s", target)
			}
			results := make([]*tools.ScanDependenciesResult, 0, len(lockfiles))
			for _, lf := range lockfiles {
				res, err := lib.ScanDependencies(lf)
				if err != nil {
					fmt.Fprintf(c.ErrOrStderr(), "scan-dependencies: skip %s: %v\n", lf, err)
					continue
				}
				results = append(results, res)
			}
			if report != "" {
				rep := newReport("scan-dependencies", []string{target})
				for _, res := range results {
					rep.Sections = append(rep.Sections, dependencySection(res))
				}
				return writeReport(c, report, rep)
			}
			switch format {
			case "json":
				return emitJSON(c.OutOrStdout(), results)
			case "sarif":
				log := &tools.SARIFLog{
					Schema:  tools.SARIFSchema,
					Version: tools.SARIFVersion,
					Runs:    []tools.SARIFRun{},
				}
				for _, res := range results {
					log.Runs = append(log.Runs, tools.ScanDependenciesSARIF(res).Runs...)
				}
				return emitJSON(c.OutOrStdout(), log)
			default:
				// Only lockfiles with findings are printed; clean ones are
				// omitted. The summary still reports the full count scanned.
				totalFindings := 0
				for _, res := range results {
					if len(res.Findings) == 0 {
						continue
					}
					printScanDependenciesText(c.OutOrStdout(), res.FilePath, res)
					totalFindings += len(res.Findings)
				}
				fmt.Fprintf(c.OutOrStdout(), "Scanned %d lockfile(s); %d finding(s) total\n",
					len(results), totalFindings)
				return nil
			}
		},
	}
	c.Flags().StringVar(&repoPath, "path", ".", "secure-vibe checkout (default: $SECURE_VIBE_LIBRARY_PATH, else cwd)")
	addFormatFlag(c, &format, true)
	addVulnSourceFlag(c, &vulnSource)
	addReportFlag(c, &report)
	return c
}

// printScanDependenciesText renders one ScanDependenciesResult in the
// human-readable --format text shape. Extracted so the single-file and
// directory code paths emit byte-identical per-lockfile output.
func printScanDependenciesText(w io.Writer, label string, res *tools.ScanDependenciesResult) {
	fmt.Fprintf(w, "=== scan-dependencies %s ===\n", label)
	fmt.Fprintf(w, "Dependencies parsed: %d  ecosystem=%s\n", res.Dependencies, res.Ecosystem)
	fmt.Fprintf(w, "Findings: %d\n", len(res.Findings))
	for _, f := range res.Findings {
		fmt.Fprintf(w, "  ! [%s] %s@%s — %s: %s\n",
			f.Severity, f.Package, f.Version, f.Category, f.Message)
	}
}

// discoverLockfiles returns the paths of every recognised dependency
// lockfile beneath dir, via the shared tools.WalkScanFiles walker. The
// keep predicate narrows the walk to known lockfile names; the walker
// handles the noise-dir pruning (node_modules, vendor, build output, …)
// and the non-regular / oversized / binary skips so a project's own
// manifests are scanned without descending into installed-dependency
// trees.
func discoverLockfiles(dir string) ([]string, error) {
	found, err := tools.WalkScanFiles(dir, func(path string) bool {
		return knownLockfileName(filepath.Base(path))
	})
	if err != nil {
		return nil, fmt.Errorf("scan-dependencies: walk %s: %w", dir, err)
	}
	return found, nil
}

// knownLockfileName reports whether base is a lockfile name that
// parsers.Parse recognises. Kept in sync with the dispatch table in
// internal/tools/parsers/parsers.go; if a parser is added there, add
// its base name here so directory discovery picks it up.
func knownLockfileName(base string) bool {
	switch base {
	case "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
		"Pipfile.lock", "poetry.lock", "go.sum", "Cargo.lock",
		"pom.xml", "gradle.lockfile", "build.gradle.lockfile",
		"packages.lock.json", "Gemfile.lock",
		"composer.lock", "Package.resolved", "pubspec.lock":
		return true
	}
	lower := strings.ToLower(base)
	if strings.HasSuffix(lower, ".csproj") ||
		strings.HasSuffix(lower, ".fsproj") ||
		strings.HasSuffix(lower, ".vbproj") {
		return true
	}
	if strings.HasSuffix(base, ".txt") && strings.HasPrefix(base, "requirements") {
		return true
	}
	return false
}

// =============================================================================
// scan-dockerfile
// =============================================================================

func scanDockerfileCmd() *cobra.Command {
	var repoPath, format, report string
	c := &cobra.Command{
		Use:   "scan-dockerfile <Dockerfile>",
		Short: "Hardening pass over a Dockerfile (USER root, unpinned base, ADD remote, curl|sh, secrets in env, etc.)",
		Long: `Hardening pass over a Dockerfile (USER root, unpinned base, ADD
remote, curl|sh, secrets in env, etc.).

` + reportHelpParagraph,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := validateFormat(format, true); err != nil {
				return err
			}
			file := args[0]
			lib, err := newLibraryForCmd(repoPath, "", file)
			if err != nil {
				return err
			}
			fileAbs, _ := filepath.Abs(file)
			res, err := lib.ScanDockerfile(fileAbs)
			if err != nil {
				return err
			}
			if report != "" {
				rep := newReport("scan-dockerfile", []string{file})
				rep.Sections = append(rep.Sections, dockerfileSection(file, res))
				return writeReport(c, report, rep)
			}
			switch format {
			case "json":
				return emitJSON(c.OutOrStdout(), res)
			case "sarif":
				return emitJSON(c.OutOrStdout(), tools.ScanDockerfileSARIF(res))
			default:
				fmt.Fprintf(c.OutOrStdout(), "=== scan-dockerfile %s ===\n", file)
				fmt.Fprintf(c.OutOrStdout(), "Findings: %d\n", len(res.Findings))
				for _, f := range res.Findings {
					fmt.Fprintf(c.OutOrStdout(), "  ! [%s] %s:%d  %s\n", f.Severity, f.RuleID, f.Line, f.Title)
					if f.Fix != "" {
						fmt.Fprintf(c.OutOrStdout(), "        fix: %s\n", f.Fix)
					}
				}
				return nil
			}
		},
	}
	c.Flags().StringVar(&repoPath, "path", ".", "secure-vibe checkout (default: $SECURE_VIBE_LIBRARY_PATH, else cwd)")
	addFormatFlag(c, &format, true)
	addReportFlag(c, &report)
	return c
}

// =============================================================================
// scan-github-actions
// =============================================================================

func scanGitHubActionsCmd() *cobra.Command {
	var repoPath, format, report string
	c := &cobra.Command{
		Use:   "scan-github-actions <workflow.yml>",
		Short: "Lint a GitHub Actions workflow for pwn-request, script-injection, unpinned actions, missing permissions, and credential exposure",
		Long: `Lint a GitHub Actions workflow for pwn-request, script-injection,
unpinned actions, missing permissions, and credential exposure.

` + reportHelpParagraph,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := validateFormat(format, true); err != nil {
				return err
			}
			file := args[0]
			lib, err := newLibraryForCmd(repoPath, "", file)
			if err != nil {
				return err
			}
			fileAbs, _ := filepath.Abs(file)
			res, err := lib.ScanGitHubActions(fileAbs)
			if err != nil {
				return err
			}
			if report != "" {
				rep := newReport("scan-github-actions", []string{file})
				rep.Sections = append(rep.Sections, githubActionsSection(file, res))
				return writeReport(c, report, rep)
			}
			switch format {
			case "json":
				return emitJSON(c.OutOrStdout(), res)
			case "sarif":
				return emitJSON(c.OutOrStdout(), tools.ScanGitHubActionsSARIF(res))
			default:
				fmt.Fprintf(c.OutOrStdout(), "=== scan-github-actions %s ===\n", file)
				fmt.Fprintf(c.OutOrStdout(), "Findings: %d\n", len(res.Findings))
				for _, f := range res.Findings {
					fmt.Fprintf(c.OutOrStdout(), "  ! [%s] %s  (line %d) — %s\n", f.Severity, f.RuleID, f.Line, f.Title)
					if f.Fix != "" {
						fmt.Fprintf(c.OutOrStdout(), "        fix: %s\n", f.Fix)
					}
				}
				return nil
			}
		},
	}
	c.Flags().StringVar(&repoPath, "path", ".", "secure-vibe checkout (default: $SECURE_VIBE_LIBRARY_PATH, else cwd)")
	addFormatFlag(c, &format, true)
	addReportFlag(c, &report)
	return c
}

// policyFailureError is the sentinel returned by policy-check when at
// least one finding meets the severity floor. We give it a dedicated
// type so the binary's top-level error handler (cmd.Execute in
// main.go) can convert it to a non-zero exit without dumping the
// flag-usage block to stderr.
type policyFailureError struct {
	count int
	floor string
}

func (e *policyFailureError) Error() string {
	return fmt.Sprintf("gate: %d finding(s) at or above %s", e.count, e.floor)
}

// IsPolicyFailure reports whether err is the sentinel above. Used by
// callers that want to distinguish "the policy check returned
// findings" from "the policy check itself errored". Exported so
// outboard test harnesses can branch on it without relying on
// errors.As against an unexported type.
func IsPolicyFailure(err error) bool {
	_, ok := err.(*policyFailureError)
	return ok
}
