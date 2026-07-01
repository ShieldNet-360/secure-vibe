package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/shieldnet-360/secure-vibe/internal/skill"
	"github.com/shieldnet-360/secure-vibe/internal/tools"
)

type corpusFixture struct {
	ID              string `json:"id"`
	Text            string `json:"text"`
	Expected        string `json:"expected"` // "detect" or "ignore"
	ExpectedPattern string `json:"expected_pattern,omitempty"`
	// Filename and ExpectedRule belong to the gate-driven shape:
	// Filename is the path the fixture text is written to before the
	// gate scans it (the basename drives scanner dispatch, so lockfiles
	// and workflows must use their real names, e.g. "package-lock.json"
	// or ".github/workflows/ci.yml"); ExpectedRule, when set, requires
	// that specific finding rule_id among the results of a "detect".
	Filename     string `json:"filename,omitempty"`
	ExpectedRule string `json:"expected_rule,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

type corpusFile struct {
	SchemaVersion string `json:"schema_version"`
	Description   string `json:"description"`
	// Scanner selects the corpus shape. Empty = legacy behavior
	// (regex-driven when the skill has secret_pattern checklist
	// entries, schema-only smoke otherwise). "gate" = each fixture is
	// written to a temp file and run through the same Library
	// PolicyCheck the `gate` command uses, judged against
	// SeverityFloor ("high" when empty) — the corpus literally tests
	// what the CI gate would block.
	Scanner       string          `json:"scanner,omitempty"`
	SeverityFloor string          `json:"severity_floor,omitempty"`
	Fixtures      []corpusFixture `json:"fixtures"`
}

// rulePatternEntry mirrors the subset of fields the test runner needs
// from one `checks:` entry of checklists/secret_detection.yaml. It is
// intentionally narrower than internal/tools.Pattern: the runner only
// applies regex + hotword + denylist gating, not score / entropy
// thresholds (those belong to CheckSecretPattern's full pipeline).
type rulePatternEntry struct {
	ID                 string   `yaml:"id"`
	Type               string   `yaml:"type"`
	Title              string   `yaml:"title"`
	Pattern            string   `yaml:"pattern"`
	Hotwords           []string `yaml:"hotwords"`
	HotwordWindow      int      `yaml:"hotword_window"`
	RequireHotword     bool     `yaml:"require_hotword"`
	DenylistSubstrings []string `yaml:"denylist_substrings"`
}

type rulePatternFile struct {
	Checks []rulePatternEntry `yaml:"checks"`
}

func testCmd() *cobra.Command {
	var libraryPath string
	var verbose bool

	c := &cobra.Command{
		Use:   "test <skill-id>",
		Short: "Run the per-skill test corpus and report pass/fail",
		Long: `Load skills/<id>/tests/corpus.json and validate each fixture
against the skill's bundled rule files.

The runner supports three corpus shapes:

  * Gate-driven ("scanner": "gate"): each fixture's text is written to
    its "filename" in a temp dir and run through the same PolicyCheck
    the gate command uses. "detect" expects the gate to FAIL the file at
    the corpus severity_floor (default high), optionally requiring a
    specific "expected_rule"; "ignore" expects it to pass clean.
  * Regex-driven (e.g., secret-detection): the corpus declares "detect" or
    "ignore" per fixture, and the runner matches the text against any
    type: secret_pattern entry declared in
    skills/<id>/checklists/<framework>.yaml (with hotword window enforcement).
  * Schema-driven (other skills): the corpus is treated as a smoke test; the
    runner only verifies that fixtures parse and that "expected" is one of the
    accepted values.

Exits non-zero on any failure.
`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			id := strings.TrimSpace(args[0])

			lib, err := filepath.Abs(libraryPath)
			if err != nil {
				return err
			}
			skillDir := filepath.Join(lib, "skills", id)
			if _, err := os.Stat(skillDir); err != nil {
				return fmt.Errorf("skill %q not found at %s", id, skillDir)
			}
			s, err := skill.Parse(filepath.Join(skillDir, "SKILL.md"))
			if err != nil {
				return fmt.Errorf("load skill: %w", err)
			}

			corpusPath := filepath.Join(skillDir, "tests", "corpus.json")
			if _, err := os.Stat(corpusPath); err != nil {
				fmt.Fprintf(c.OutOrStdout(), "no tests/corpus.json for %s; nothing to test\n", id)
				return nil
			}

			data, err := os.ReadFile(corpusPath)
			if err != nil {
				return err
			}
			var corpus corpusFile
			if err := json.Unmarshal(data, &corpus); err != nil {
				return fmt.Errorf("parse corpus: %w", err)
			}

			passed, failed := 0, 0
			out := c.OutOrStdout()

			if corpus.Scanner == "gate" {
				passed, failed = runGateFixtures(out, lib, corpus, verbose)
				fmt.Fprintf(out, "%s: %d passed, %d failed (skill v%s)\n", id, passed, failed, s.Frontmatter.Version)
				if failed > 0 {
					return fmt.Errorf("%d fixture(s) failed", failed)
				}
				return nil
			}

			patterns := loadRulePatterns(skillDir)

			for _, fx := range corpus.Fixtures {
				if fx.Expected != "detect" && fx.Expected != "ignore" {
					failed++
					fmt.Fprintf(out, "FAIL [%s]: expected must be 'detect' or 'ignore', got %q\n", fx.ID, fx.Expected)
					continue
				}
				if len(patterns) == 0 {
					// Schema-only smoke pass
					passed++
					if verbose {
						fmt.Fprintf(out, "ok   [%s] (schema-only)\n", fx.ID)
					}
					continue
				}
				match, matchedName := matchAny(fx.Text, patterns)
				wantDetect := fx.Expected == "detect"
				if match != wantDetect {
					failed++
					fmt.Fprintf(out, "FAIL [%s]: expected=%s actual=%s pattern=%s\n", fx.ID, fx.Expected, boolStr(match), matchedName)
					continue
				}
				if match && fx.ExpectedPattern != "" && fx.ExpectedPattern != matchedName {
					failed++
					fmt.Fprintf(out, "FAIL [%s]: matched %q but expected_pattern was %q\n", fx.ID, matchedName, fx.ExpectedPattern)
					continue
				}
				passed++
				if verbose {
					fmt.Fprintf(out, "ok   [%s] -> %s\n", fx.ID, matchedName)
				}
			}

			fmt.Fprintf(out, "%s: %d passed, %d failed (skill v%s)\n", id, passed, failed, s.Frontmatter.Version)
			if failed > 0 {
				return fmt.Errorf("%d fixture(s) failed", failed)
			}
			return nil
		},
	}

	c.Flags().StringVar(&libraryPath, "library", ".", "Path to the skills library root")
	c.Flags().BoolVar(&verbose, "verbose", false, "Print one line per fixture")
	return c
}

// runGateFixtures executes a gate-driven corpus: each fixture is
// materialised under a temp dir at its declared filename (basename
// drives PolicyCheck's scanner dispatch; workflows need their
// .github/workflows/ prefix) and judged the way CI's gate would judge
// it. "detect" fixtures must FAIL the gate at the corpus floor —
// optionally with a specific rule id among the findings — and
// "ignore" fixtures must pass clean. libraryRoot is the secure-vibe
// checkout the scanners load their rule data from.
func runGateFixtures(out io.Writer, libraryRoot string, corpus corpusFile, verbose bool) (passed, failed int) {
	floor := corpus.SeverityFloor
	if floor == "" {
		floor = "high"
	}
	for _, fx := range corpus.Fixtures {
		fail := func(format string, args ...any) {
			failed++
			fmt.Fprintf(out, "FAIL [%s]: "+format+"\n", append([]any{fx.ID}, args...)...)
		}
		if fx.Expected != "detect" && fx.Expected != "ignore" {
			fail("expected must be 'detect' or 'ignore', got %q", fx.Expected)
			continue
		}
		if fx.Filename == "" {
			fail("gate-driven fixture needs a filename (it drives scanner dispatch)")
			continue
		}
		tmp, err := os.MkdirTemp("", "skills-corpus-*")
		if err != nil {
			fail("temp dir: %v", err)
			continue
		}
		full := filepath.Join(tmp, filepath.FromSlash(fx.Filename))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			fail("mkdir: %v", err)
			os.RemoveAll(tmp)
			continue
		}
		if err := os.WriteFile(full, []byte(fx.Text), 0o644); err != nil {
			fail("write fixture: %v", err)
			os.RemoveAll(tmp)
			continue
		}
		lib, err := newLibraryForCmd(libraryRoot, "", full)
		if err == nil {
			var res *tools.PolicyCheckResult
			res, err = lib.PolicyCheck(full, floor)
			if err == nil {
				gateFailed := !res.Pass
				wantDetect := fx.Expected == "detect"
				switch {
				case gateFailed != wantDetect:
					fail("expected=%s actual=%s (floor=%s, %d finding(s))",
						fx.Expected, boolStr(gateFailed), floor, len(res.Findings))
				case wantDetect && fx.ExpectedRule != "" && !hasRule(res.Findings, fx.ExpectedRule):
					fail("gate failed but rule %q not among findings %v",
						fx.ExpectedRule, ruleIDs(res.Findings))
				default:
					passed++
					if verbose {
						fmt.Fprintf(out, "ok   [%s] -> gate %s (%d finding(s))\n",
							fx.ID, boolStr(gateFailed), len(res.Findings))
					}
				}
			}
		}
		if err != nil {
			fail("gate run: %v", err)
		}
		os.RemoveAll(tmp)
	}
	return passed, failed
}

func hasRule(findings []tools.PolicyCheckFinding, rule string) bool {
	for _, f := range findings {
		if f.RuleID == rule {
			return true
		}
	}
	return false
}

func ruleIDs(findings []tools.PolicyCheckFinding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.RuleID)
	}
	return out
}

func boolStr(b bool) string {
	if b {
		return "detect"
	}
	return "ignore"
}

// loadRulePatterns reads the first checklists/*.yaml in skills/<id>/
// and returns every `type: secret_pattern` entry compiled into a
// runnable shape. Skills without a checklists/ directory or without
// any secret_pattern items return an empty slice and the test runner
// falls back to schema-only smoke validation.
func loadRulePatterns(skillDir string) []compiledPattern {
	checklistsDir := filepath.Join(skillDir, "checklists")
	entries, err := os.ReadDir(checklistsDir)
	if err != nil {
		return nil
	}
	out := []compiledPattern{}
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(checklistsDir, name))
		if err != nil {
			continue
		}
		var f rulePatternFile
		if err := yaml.Unmarshal(data, &f); err != nil {
			continue
		}
		for _, c := range f.Checks {
			if c.Type != "secret_pattern" {
				continue
			}
			re, err := regexp.Compile(c.Pattern)
			if err != nil {
				continue
			}
			out = append(out, compiledPattern{
				Name:               c.Title,
				Regex:              re,
				Hotwords:           c.Hotwords,
				HotwordWindow:      c.HotwordWindow,
				RequireHotword:     c.RequireHotword,
				DenylistSubstrings: c.DenylistSubstrings,
			})
		}
	}
	return out
}

type compiledPattern struct {
	Name               string
	Regex              *regexp.Regexp
	Hotwords           []string
	HotwordWindow      int
	RequireHotword     bool
	DenylistSubstrings []string
}

// matchAny returns whether the text matches any compiled pattern. When
// multiple patterns match, the most specific one (i.e. the last non-Generic
// pattern that matched) wins.
func matchAny(text string, patterns []compiledPattern) (bool, string) {
	bestName := ""
	for _, p := range patterns {
		loc := p.Regex.FindStringIndex(text)
		if loc == nil {
			continue
		}
		matchText := text[loc[0]:loc[1]]
		if denylisted(matchText, p.DenylistSubstrings) {
			continue
		}
		if p.RequireHotword || len(p.Hotwords) > 0 {
			if !hotwordNear(text, loc, p.Hotwords, p.HotwordWindow) {
				if p.RequireHotword {
					continue
				}
			}
		}
		isGeneric := strings.HasPrefix(p.Name, "Generic ")
		// Selection rule (per the doc comment above):
		//   - The first match seeds the best (Generic or not).
		//   - Any later non-Generic match replaces the current best,
		//     so the LAST non-Generic in iteration order wins.
		//   - Generic matches after the first never replace, keeping
		//     the earliest seed stable when no non-Generic matches.
		if bestName == "" || !isGeneric {
			bestName = p.Name
		}
	}
	if bestName == "" {
		return false, ""
	}
	return true, bestName
}

func denylisted(matchText string, denylist []string) bool {
	if len(denylist) == 0 {
		return false
	}
	lower := strings.ToLower(matchText)
	for _, sub := range denylist {
		if strings.Contains(lower, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

// hotwordNear returns true if any hotword appears within `window` bytes of the
// regex match indicated by matchIdx, where matchIdx is a [start, end) byte
// range over the original-case `text`. The window is lowered together with the
// slice so the byte indices and the lowered string come from the same byte
// space — strings.ToLower is not length-preserving (e.g. U+2126 OHM SIGN →
// U+03C9, 3 → 2 bytes; Turkish İ → i, 2 → 1 byte), so pre-lowering the full
// text would shift the window relative to the match and produce false
// negatives (or panics) on non-ASCII input.
func hotwordNear(text string, matchIdx []int, hotwords []string, window int) bool {
	if window <= 0 {
		window = 80
	}
	start := matchIdx[0] - window
	if start < 0 {
		start = 0
	}
	if start > len(text) {
		start = len(text)
	}
	end := matchIdx[1] + window
	if end > len(text) {
		end = len(text)
	}
	if end < start {
		end = start
	}
	region := strings.ToLower(text[start:end])
	for _, h := range hotwords {
		if strings.Contains(region, strings.ToLower(h)) {
			return true
		}
	}
	return false
}
