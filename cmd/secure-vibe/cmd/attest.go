package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/shieldnet-360/secure-vibe/internal/attest"
	"github.com/shieldnet-360/secure-vibe/internal/tools"
)

// attestCmd is the `secure-vibe attest` group: attach and check a tamper-evident
// USAGE WATERMARK proving a commit's code was scanned by secure-vibe.
//
// This is a usage signal, not a security guarantee — see internal/attest for
// the threat model. Every path is fail-open: missing git, no repo, or no
// SecureVibe material means the attestation is skipped, never that work is
// blocked.
func attestCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "attest",
		Short: "Attach or verify a SecureVibe usage attestation on commits (watermark, not a security control)",
		Long: `attest signs a content-addressed subject (the git tree of the staged
commit) together with the scan verdict, and records it as a
SecureVibe-Attestation git trailer. Detecting whether a developer used
secure-vibe is then a one-liner:

  git log --grep '^SecureVibe-Attestation:'

The signing key is an Ed25519 watermark key shipped in the binary: this proves
USAGE by an honest developer, not un-forgeability against a malicious one.
Verification needs only the public key, so the private signer can later move
server-side without changing the format.`,
	}
	c.AddCommand(attestSignCmd())
	c.AddCommand(attestVerifyCmd())
	c.AddCommand(attestInstallHooksCmd())
	return c
}

// scanForAttest runs the same detection as `gate` over paths and returns the
// aggregate verdict and per-severity counts. It reuses ExpandGateFiles +
// PolicyCheck so the attestation records exactly what the gate would.
func scanForAttest(paths []string, floor string) (verdict string, counts map[string]int, err error) {
	files, err := tools.ExpandGateFiles(paths)
	if err != nil {
		return "", nil, err
	}
	counts = map[string]int{}
	pass := true
	for _, file := range files {
		lib, err := newLibraryForCmd("", "", file)
		if err != nil {
			return "", nil, err
		}
		fileAbs, _ := filepath.Abs(file)
		res, err := lib.PolicyCheck(fileAbs, floor)
		if err != nil {
			return "", nil, err
		}
		for sev, n := range res.Counts {
			counts[sev] += n
		}
		if !res.Pass {
			pass = false
		}
	}
	if pass {
		return "pass", counts, nil
	}
	return "fail", counts, nil
}

func attestSignCmd() *cobra.Command {
	var floor, messageFile, path string
	var ifMaterial, block bool
	c := &cobra.Command{
		Use:   "sign [path...]",
		Short: "Scan the staged commit and emit a signed attestation trailer",
		Long: `sign computes the staged git tree (git write-tree), runs the scanners
over the working tree, and emits a signed SecureVibe-Attestation trailer that
binds the tree SHA to the scan verdict.

With no --message-file it prints the trailer to stdout. With --message-file it
appends the trailer to that file (this is how the prepare-commit-msg hook wires
it in). Findings never block the commit unless --block is set; the verdict is
recorded either way.`,
		RunE: func(c *cobra.Command, args []string) error {
			out := c.OutOrStdout()
			cwd := path
			if cwd == "" {
				cwd, _ = os.Getwd()
			}

			// Fail-open bypasses: no git, not a repo.
			if !attest.HaveGit() {
				fmt.Fprintln(c.ErrOrStderr(), "secure-vibe attest: git not found; skipping attestation.")
				return nil
			}
			if !attest.IsGitRepo(cwd) {
				fmt.Fprintln(c.ErrOrStderr(), "secure-vibe attest: not a git repository; skipping attestation.")
				return nil
			}
			repoRoot, err := attest.RepoRoot(cwd)
			if err != nil {
				return err
			}
			if ifMaterial {
				if present, _ := attest.DetectMaterial(repoRoot); !present {
					// The hook path: silently skip repos that never opted in.
					return nil
				}
			}

			treeSHA, err := attest.StagedTreeSHA(cwd)
			if err != nil {
				return fmt.Errorf("compute staged tree: %w", err)
			}

			scanPaths := args
			if len(scanPaths) == 0 {
				scanPaths = []string{repoRoot}
			}
			verdict, counts, err := scanForAttest(scanPaths, floor)
			if err != nil {
				return err
			}

			att, err := attest.Sign(attest.Attestation{
				Tool:     CLIVersion,
				Subject:  attest.TreeSubject(treeSHA),
				Verdict:  verdict,
				Floor:    floor,
				Findings: attest.CountsFromMap(counts),
			})
			if err != nil {
				return err
			}

			if messageFile != "" {
				if err := appendTrailerToMessage(messageFile, att); err != nil {
					return err
				}
			} else {
				fmt.Fprintln(out, att.TrailerLine())
			}

			if block && verdict == "fail" {
				c.SilenceUsage = true
				return fmt.Errorf("attest: scan verdict is FAIL at floor %q (--block set)", floor)
			}
			return nil
		},
	}
	c.Flags().StringVar(&floor, "severity-floor", "high", "severity floor for the recorded verdict: critical|high|medium|low")
	c.Flags().StringVar(&messageFile, "message-file", "", "append the trailer to this commit-message file instead of stdout")
	c.Flags().StringVar(&path, "path", "", "repository directory (default: current directory)")
	c.Flags().BoolVar(&ifMaterial, "if-material", false, "do nothing unless the repo has SecureVibe material (used by the hook)")
	c.Flags().BoolVar(&block, "block", false, "exit non-zero when the scan verdict is FAIL (enforcement, not just watermarking)")
	return c
}

// appendTrailerToMessage appends the attestation trailer to a commit-message
// file as its own trailer paragraph. It is idempotent: if the file already
// carries a SecureVibe-Attestation trailer it is left unchanged.
func appendTrailerToMessage(messageFile string, att attest.Attestation) error {
	raw, err := os.ReadFile(messageFile)
	if err != nil {
		return fmt.Errorf("read message file: %w", err)
	}
	if _, ok, _ := attest.ParseTrailer(string(raw)); ok {
		return nil
	}
	body := strings.TrimRight(string(raw), "\n")
	var next string
	if body == "" {
		next = att.TrailerLine() + "\n"
	} else {
		next = body + "\n\n" + att.TrailerLine() + "\n"
	}
	return os.WriteFile(messageFile, []byte(next), 0o644)
}

func attestVerifyCmd() *cobra.Command {
	var revRange, path string
	c := &cobra.Command{
		Use:   "verify [commit]",
		Short: "Verify SecureVibe attestations on a commit or a commit range",
		Long: `verify checks the signature on each commit's attestation and confirms
the signed subject matches the commit's actual tree. With no argument it checks
HEAD; --range checks a rev-range (e.g. origin/main..HEAD). Exit code is non-zero
only when a PRESENT attestation fails to verify (a missing attestation is
reported, not an error).`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			out := c.OutOrStdout()
			cwd := path
			if cwd == "" {
				cwd, _ = os.Getwd()
			}
			if !attest.HaveGit() || !attest.IsGitRepo(cwd) {
				return fmt.Errorf("verify needs a git repository")
			}

			var commits []string
			var err error
			switch {
			case revRange != "":
				commits, err = attest.CommitsInRange(cwd, revRange)
			case len(args) == 1:
				commits = []string{args[0]}
			default:
				commits = []string{"HEAD"}
			}
			if err != nil {
				return err
			}
			if len(commits) == 0 {
				fmt.Fprintln(out, "no commits in range.")
				return nil
			}

			var attested, verified, bad int
			for _, commit := range commits {
				short := commit
				if len(short) > 12 {
					short = short[:12]
				}
				msg, err := attest.CommitMessage(cwd, commit)
				if err != nil {
					return err
				}
				att, ok, perr := attest.ParseTrailer(msg)
				if perr != nil {
					bad++
					fmt.Fprintf(out, "  %s  ✗ malformed attestation: %v\n", short, perr)
					continue
				}
				if !ok {
					fmt.Fprintf(out, "  %s  ·  no attestation\n", short)
					continue
				}
				attested++
				if err := attest.Verify(att); err != nil {
					bad++
					fmt.Fprintf(out, "  %s  ✗ signature invalid: %v\n", short, err)
					continue
				}
				// Confirm the signed subject matches the commit's real tree.
				realTree, err := attest.CommitTreeSHA(cwd, commit)
				if err != nil {
					return err
				}
				if attest.SubjectTreeSHA(att.Subject) != realTree {
					bad++
					fmt.Fprintf(out, "  %s  ✗ subject/tree mismatch (attestation not for this content)\n", short)
					continue
				}
				verified++
				fmt.Fprintf(out, "  %s  ✔ verified  verdict=%s floor=%s findings=%s  (secure-vibe %s)\n",
					short, att.Verdict, att.Floor, att.Findings, att.Tool)
			}

			fmt.Fprintf(out, "\n%d commit(s): %d attested, %d verified, %d bad.\n",
				len(commits), attested, verified, bad)
			if bad > 0 {
				c.SilenceUsage = true
				return fmt.Errorf("%d attestation(s) failed verification", bad)
			}
			return nil
		},
	}
	c.Flags().StringVar(&revRange, "range", "", "verify a git rev-range instead of a single commit (e.g. origin/main..HEAD)")
	c.Flags().StringVar(&path, "path", "", "repository directory (default: current directory)")
	return c
}

func attestInstallHooksCmd() *cobra.Command {
	var path string
	c := &cobra.Command{
		Use:   "install-hooks",
		Short: "Install the prepare-commit-msg hook that attests each commit",
		RunE: func(c *cobra.Command, args []string) error {
			cwd := path
			if cwd == "" {
				cwd, _ = os.Getwd()
			}
			installed, err := InstallAttestHook(cwd)
			if err != nil {
				return err
			}
			if installed {
				fmt.Fprintln(c.OutOrStdout(), "installed .git/hooks/prepare-commit-msg — commits will now carry a SecureVibe attestation.")
			} else {
				fmt.Fprintln(c.OutOrStdout(), "prepare-commit-msg hook already attests; nothing to do.")
			}
			return nil
		},
	}
	c.Flags().StringVar(&path, "path", "", "repository directory (default: current directory)")
	return c
}
