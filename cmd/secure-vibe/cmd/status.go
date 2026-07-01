package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/shieldnet-360/secure-vibe/cmd/secure-vibe/internal/manifest"
)

// Freshness thresholds (days). Security data ages fast: an AI assistant
// fed a stale skill set or vulnerability database is reasoning about a
// world that has moved on. These bands turn "when did I last update?"
// into a verdict.
const (
	freshDays = 7
	agingDays = 30
)

// statusReport is the machine-readable shape emitted by --json.
type statusReport struct {
	LibraryVersion    string         `json:"library_version"`
	LibraryReleasedAt string         `json:"library_released_at,omitempty"`
	LibraryAgeDays    int            `json:"library_age_days"`
	VulnNewest        string         `json:"vuln_data_newest,omitempty"`
	VulnAgeDays       int            `json:"vuln_data_age_days"`
	VulnAdvisories    int            `json:"vuln_advisories"`
	VulnEcosystems    int            `json:"vuln_ecosystems"`
	Skills            int            `json:"skills"`
	Freshness         string         `json:"freshness"`
	PerEcosystem      map[string]int `json:"per_ecosystem_advisories,omitempty"`
}

func statusCmd() *cobra.Command {
	var path string
	var asJSON bool
	var nowOverride string // RFC3339; testing seam
	var failIfStale bool
	var maxAgeDays int
	c := &cobra.Command{
		Use:   "status",
		Short: "Report how fresh the local skills + vulnerability data is",
		Long: `Summarise the locally-installed library: its version, how many days old the
skills and vulnerability data are, and a freshness verdict. The premise of
prevention-first security is that an AI assistant is only as current as the
knowledge it is fed — "status" makes that staleness visible so you know when to
run "secure-vibe update".`,
		RunE: func(cmd *cobra.Command, args []string) error {
			root := resolveLibraryRoot(path)
			now := time.Now().UTC()
			if nowOverride != "" {
				t, err := time.Parse(time.RFC3339, nowOverride)
				if err != nil {
					return fmt.Errorf("parse --now: %w", err)
				}
				now = t.UTC()
			}
			rep := buildStatusReport(root, now)
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(rep); err != nil {
					return err
				}
			} else {
				renderStatus(cmd.OutOrStdout(), rep)
			}
			// CI gate: fail when the vulnerability data is older than the
			// allowed budget. --max-age-days takes precedence; otherwise
			// --fail-if-stale uses the "stale" threshold. A run with no
			// dated index (age -1) cannot be judged, so it never fails the
			// gate on its own.
			limit := -1
			if cmd.Flags().Changed("max-age-days") {
				limit = maxAgeDays
			} else if failIfStale {
				limit = agingDays
			}
			if limit >= 0 && rep.VulnAgeDays > limit {
				return fmt.Errorf("vulnerability data is %d days old (limit %d); run `secure-vibe update`", rep.VulnAgeDays, limit)
			}
			return nil
		},
	}
	c.Flags().StringVar(&path, "path", ".", "library root (default: $SECURE_VIBE_LIBRARY_PATH, else cwd)")
	c.Flags().BoolVar(&asJSON, "json", false, "emit the report as JSON")
	c.Flags().StringVar(&nowOverride, "now", "", "override the current time (RFC3339) for reproducible output")
	c.Flags().BoolVar(&failIfStale, "fail-if-stale", false, fmt.Sprintf("exit non-zero when the vulnerability data is older than %d days (CI gate)", agingDays))
	c.Flags().IntVar(&maxAgeDays, "max-age-days", 0, "exit non-zero when the vulnerability data is older than this many days (overrides --fail-if-stale)")
	_ = c.Flags().MarkHidden("now")
	return c
}

// daysBetween returns the whole-day age from t to now, floored at 0.
// A zero/unparseable timestamp yields -1 so callers can render "unknown".
func daysBetween(now time.Time, ts string) int {
	if strings.TrimSpace(ts) == "" {
		return -1
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		// Tolerate a date-only stamp (YYYY-MM-DD).
		if t, err = time.Parse("2006-01-02", ts); err != nil {
			return -1
		}
	}
	d := int(now.Sub(t).Hours() / 24)
	if d < 0 {
		return 0
	}
	return d
}

// osvIndexHead is the minimal projection of an OSV index needed for the
// freshness report: when it was built and how many distinct advisories
// it carries.
type osvIndexHead struct {
	LastUpdated string `json:"last_updated"`
	ByPackage   map[string][]struct {
		ID string `json:"id"`
	} `json:"by_package"`
}

// buildStatusReport gathers the freshness facts from disk. Missing data
// degrades gracefully to zero/empty rather than erroring — `status`
// should always render something useful.
func buildStatusReport(root string, now time.Time) statusReport {
	rep := statusReport{PerEcosystem: map[string]int{}}

	if m, err := manifest.Load(filepath.Join(root, "manifest.json")); err == nil {
		rep.LibraryVersion = m.Version
		rep.LibraryReleasedAt = m.ReleasedAt
		rep.LibraryAgeDays = daysBetween(now, m.ReleasedAt)
	} else {
		rep.LibraryVersion = "unknown"
		rep.LibraryAgeDays = -1
	}

	// Vulnerability data: newest OSV index timestamp + distinct advisory
	// IDs across every ecosystem.
	osvRoot := filepath.Join(root, "vulnerabilities", "osv")
	entries, _ := os.ReadDir(osvRoot)
	seen := map[string]struct{}{}
	var newest time.Time
	var newestStr string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		eco := e.Name()
		body, err := os.ReadFile(filepath.Join(osvRoot, eco, "index.json"))
		if err != nil {
			continue
		}
		var idx osvIndexHead
		if json.Unmarshal(body, &idx) != nil {
			continue
		}
		rep.VulnEcosystems++
		ecoIDs := map[string]struct{}{}
		for _, list := range idx.ByPackage {
			for _, adv := range list {
				if adv.ID == "" {
					continue
				}
				seen[adv.ID] = struct{}{}
				ecoIDs[adv.ID] = struct{}{}
			}
		}
		rep.PerEcosystem[eco] = len(ecoIDs)
		if t, err := time.Parse(time.RFC3339, idx.LastUpdated); err == nil {
			if t.After(newest) {
				newest = t
				newestStr = idx.LastUpdated
			}
		}
	}
	rep.VulnAdvisories = len(seen)
	rep.VulnNewest = newestStr
	rep.VulnAgeDays = daysBetween(now, newestStr)

	// Skills: count skills/<id>/ directories that hold a SKILL.md.
	if skillDirs, err := os.ReadDir(filepath.Join(root, "skills")); err == nil {
		for _, d := range skillDirs {
			if !d.IsDir() {
				continue
			}
			if _, err := os.Stat(filepath.Join(root, "skills", d.Name(), "SKILL.md")); err == nil {
				rep.Skills++
			}
		}
	}

	rep.Freshness = freshnessVerdict(rep.VulnAgeDays)
	return rep
}

// freshnessVerdict maps the vulnerability-data age (the most
// security-relevant clock) to a verdict word.
func freshnessVerdict(vulnAgeDays int) string {
	switch {
	case vulnAgeDays < 0:
		return "unknown"
	case vulnAgeDays <= freshDays:
		return "fresh"
	case vulnAgeDays <= agingDays:
		return "aging"
	default:
		return "stale"
	}
}

func renderStatus(w interface{ Write([]byte) (int, error) }, rep statusReport) {
	ageStr := func(d int) string {
		if d < 0 {
			return "unknown"
		}
		if d == 0 {
			return "today"
		}
		if d == 1 {
			return "1 day old"
		}
		return fmt.Sprintf("%d days old", d)
	}
	fmt.Fprintf(w, "SecureVibe library status\n")
	fmt.Fprintf(w, "  version            %s", rep.LibraryVersion)
	if rep.LibraryReleasedAt != "" {
		fmt.Fprintf(w, "  (released %s, %s)", shortDate(rep.LibraryReleasedAt), ageStr(rep.LibraryAgeDays))
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  skills             %d\n", rep.Skills)
	fmt.Fprintf(w, "  vuln advisories    %d across %d ecosystems\n", rep.VulnAdvisories, rep.VulnEcosystems)
	fmt.Fprintf(w, "  vuln data          %s", ageStr(rep.VulnAgeDays))
	if rep.VulnNewest != "" {
		fmt.Fprintf(w, "  (newest index %s)", shortDate(rep.VulnNewest))
	}
	fmt.Fprintln(w)

	switch rep.Freshness {
	case "fresh":
		fmt.Fprintf(w, "  freshness          ✅ fresh — your AI's security knowledge is current\n")
	case "aging":
		fmt.Fprintf(w, "  freshness          ⚠️  aging — run `secure-vibe update` to refresh\n")
	case "stale":
		fmt.Fprintf(w, "  freshness          ❌ stale — your AI is reasoning about an outdated threat landscape; run `secure-vibe update`\n")
	default:
		fmt.Fprintf(w, "  freshness          ❔ unknown — no dated vulnerability index found\n")
	}

	if len(rep.PerEcosystem) > 0 {
		ecos := make([]string, 0, len(rep.PerEcosystem))
		for e := range rep.PerEcosystem {
			ecos = append(ecos, e)
		}
		sort.Strings(ecos)
		parts := make([]string, 0, len(ecos))
		for _, e := range ecos {
			parts = append(parts, fmt.Sprintf("%s:%d", e, rep.PerEcosystem[e]))
		}
		fmt.Fprintf(w, "  by ecosystem       %s\n", strings.Join(parts, "  "))
	}
}

// shortDate renders an RFC3339 (or date-only) timestamp as YYYY-MM-DD.
func shortDate(ts string) string {
	if len(ts) >= 10 {
		return ts[:10]
	}
	return ts
}
