package cmd

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/shieldnet-360/secure-vibe/cmd/secure-vibe/internal/manifest"
	"github.com/shieldnet-360/secure-vibe/cmd/secure-vibe/internal/updater"
)

// DefaultUpdateSource is the canonical update channel. Operators can override
// via --source. It points at the single secure-vibe-data.tar.gz asset
// the release workflow publishes alongside the binaries: the archive
// bundles manifest.json plus the distributable tree (skills/,
// vulnerabilities/, dictionaries/, dist/, rules/, compliance/, profiles/)
// so the updater can pull the whole library in one HTTP request.
// Individual library files are not published as separate release assets,
// so a per-file URL scheme like
// .../releases/latest/download/skills/foo/SKILL.md would 404.
// Keep this list in sync with the `tar -czf` command in
// .github/workflows/release.yml.
const DefaultUpdateSource = "https://github.com/shieldnet-360/secure-vibe/releases/latest/download/secure-vibe-data.tar.gz"

func updateCmd() *cobra.Command {
	var (
		regenerate    bool
		checkOnly     bool
		rollback      bool
		source        string
		path          string
		publicKeyPath string
		skipSignature bool
		quiet         bool
		fullInline    bool
		legacy        bool
		self          bool
		selfBaseURL   string
		selfDryRun    bool
		selfRequire   bool
	)
	c := &cobra.Command{
		Use:   "update",
		Short: "Pull the latest signed skills and vulnerability data (or, with --self, the binary itself)",
		Long: "Verifies the signed manifest published at --source, downloads only the files " +
			"whose SHA-256 differs from the local copy, and atomically writes them into the " +
			"library root. --check-only reports without applying; --rollback restores the " +
			"previous applied update.",
		RunE: func(c *cobra.Command, args []string) error {
			out := c.OutOrStdout()

			// --self replaces the running binary (formerly `self-update`).
			if self {
				if selfBaseURL == "" {
					selfBaseURL = DefaultSelfUpdateBaseURL
				}
				exe, err := os.Executable()
				if err != nil {
					return fmt.Errorf("resolve current binary: %w", err)
				}
				res, err := runSelfUpdate(out, selfBaseURL, runtime.GOOS, runtime.GOARCH, exe, selfDryRun, selfRequire)
				if err != nil {
					return err
				}
				sigNote := "unsigned"
				if res.SignatureVerified {
					sigNote = "signature verified"
				}
				fmt.Fprintf(out, "verified %s (sha256 %s, %s)\n", res.BinaryName, res.SHA256, sigNote)
				if selfDryRun {
					fmt.Fprintln(out, "dry-run: not replacing on-disk binary")
					return nil
				}
				fmt.Fprintf(out, "replaced %s\n", exe)
				return nil
			}

			root, err := filepath.Abs(path)
			if err != nil {
				return err
			}

			if rollback {
				if err := updater.Rollback(root); err != nil {
					return err
				}
				fmt.Fprintln(out, "rollback complete")
				return nil
			}

			if source == "" {
				source = DefaultUpdateSource
			}
			src, err := updater.NewSource(source)
			if err != nil {
				return fmt.Errorf("source %s: %w", source, err)
			}
			defer src.Close()

			var pub ed25519.PublicKey
			if publicKeyPath != "" {
				pub, err = manifest.LoadPublicKey(publicKeyPath)
				if err != nil {
					return err
				}
			}
			opts := updater.Options{PublicKey: pub, SkipSignature: skipSignature}

			if checkOnly {
				res, err := updater.CheckOnly(root, src, opts)
				if err != nil {
					return err
				}
				if !quiet {
					fmt.Fprintf(out, "source: %s\n", src.Description())
					fmt.Fprintf(out, "remote version: %s\n", res.RemoteManifest.Version)
				}
				fmt.Fprint(out, updater.FormatChanges(res.Changes))
				return nil
			}

			res, err := updater.Apply(root, src, opts)
			if err != nil {
				return err
			}
			if !quiet {
				fmt.Fprintf(out, "source: %s\n", src.Description())
				fmt.Fprintf(out, "updated to version %s\n", res.RemoteManifest.Version)
			}
			fmt.Fprint(out, updater.FormatChanges(res.Changes))
			if regenerate {
				// Propagate --full-inline / --legacy through so the
				// caller can keep the legacy monolithic AGENTS.md
				// output after an update. Without this, `update
				// --regenerate` silently downgrades the consumer's
				// AGENTS.md to the minimal pointer file (matches the
				// flag-parity fix made to `init` in PR #15).
				if err := regenerateAfterUpdate(root, out, fullInline || legacy); err != nil {
					return err
				}
			}
			return nil
		},
	}
	c.Flags().BoolVar(&regenerate, "regenerate", false, "regenerate dist/ from skills/ after applying the update")
	c.Flags().BoolVar(&checkOnly, "check-only", false, "fetch and verify the manifest, then print available updates without applying")
	c.Flags().BoolVar(&rollback, "rollback", false, "restore the previous applied update from .secure-vibe-previous/")
	c.Flags().StringVar(&source, "source", "", "update source: https URL, file:///path, local directory, or .tar.gz tarball")
	c.Flags().StringVar(&path, "path", ".", "library root to apply the update into")
	c.Flags().StringVar(&publicKeyPath, "public-key", "", "Ed25519 public key file used to verify the manifest (default: embedded)")
	c.Flags().BoolVar(&skipSignature, "skip-signature", false, "skip signature verification (testing / bootstrap only)")
	c.Flags().BoolVar(&quiet, "quiet", false, "suppress non-essential output")
	c.Flags().BoolVar(&fullInline, "full-inline", false, "with --regenerate, keep the legacy AGENTS.md output that inlines every skill body (default is the minimal pointer file)")
	c.Flags().BoolVar(&legacy, "legacy", false, "alias for --full-inline")
	// Binary self-update (formerly the `self-update` command).
	c.Flags().BoolVar(&self, "self", false, "update the secure-vibe binary itself instead of the library data")
	c.Flags().StringVar(&selfBaseURL, "self-base-url", DefaultSelfUpdateBaseURL, "with --self: override the base URL the binary and checksum file are fetched from")
	c.Flags().BoolVar(&selfDryRun, "self-dry-run", false, "with --self: verify the download without replacing the on-disk binary")
	c.Flags().BoolVar(&selfRequire, "self-require-signature", false, "with --self: fail unless the checksum file carries a valid Ed25519 signature")
	return c
}

// regenerateAfterUpdate runs the same logic as `secure-vibe dev regenerate` so
// dist/ stays in sync after an update brings in new skill content. We do not
// share the cobra.Command instance here because both commands accept their
// own --path flag; instead we drive the package APIs directly.
//
// fullInline mirrors `regenerate --full-inline` (alias --legacy): when true,
// the agents formatter emits the pre-v2 monolithic AGENTS.md instead of the
// minimal pointer file. Plumbed through so `update --regenerate` doesn't
// silently downgrade a consumer that pinned the legacy shape.
func regenerateAfterUpdate(root string, out interface{ Write(p []byte) (int, error) }, fullInline bool) error {
	cmd := regenerateCmd()
	args := []string{"--path", root}
	if fullInline {
		args = append(args, "--full-inline")
	}
	cmd.SetArgs(args)
	cmd.SetOut(out)
	return cmd.Execute()
}
