// Package audit is the deterministic DETECT/VERIFY orchestration layer that
// sits above `gate`. Where `gate` runs the scanners over a named set of files
// and returns a CI pass/fail, audit fans the same scanners out across a whole
// tree concurrently, deduplicates and ranks the findings by severity, and
// applies a first, deterministic false-positive triage pass (test / fixture /
// example paths are reported but demoted). It reuses tools.Library.PolicyCheck
// verbatim — no new detection logic — so a finding audit surfaces is exactly a
// finding `gate` would surface, just gathered repo-wide and ordered.
//
// This package deliberately holds only the orchestration. The model-pluggable
// LLM lanes (semantic sweep + adversarial verify) and the dynamic verify lane
// layer on top of the Report this produces; the deterministic engine here runs
// with zero network and zero model, so `secure-vibe audit` is a strict
// superset of `gate` that works offline and on every platform.
package audit

import (
	"context"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/shieldnet-360/secure-vibe/internal/tools"
)

// defaultFloor mirrors scan's default: audit reports everything low and up,
// then ranks. gate is the place for a high floor + non-zero exit.
const defaultFloor = "low"

// maxJobs caps the worker pool. Each worker owns its own *tools.Library so no
// mutable library state is shared across goroutines; a higher cap would only
// multiply the per-library data load for little wall-clock gain.
const maxJobs = 8

// LibraryFactory builds a fresh *tools.Library scoped to the audit target. The
// engine calls it once per worker, so PolicyCheck never runs concurrently on a
// shared library instance.
type LibraryFactory func() (*tools.Library, error)

// Options configures an audit run.
type Options struct {
	Root          string // audit target root (recorded on the Report)
	SeverityFloor string // lowest severity to collect; default "low"
	Jobs          int    // worker count; <= 0 picks min(NumCPU, maxJobs)

	// Reviewer, when non-nil, runs the LLM lanes after the deterministic pass:
	// a semantic sweep of SweepFiles adds candidate findings and an adversarial
	// refute pass demotes likely false positives. Nil keeps the run offline.
	Reviewer   Reviewer
	SweepFiles []string
}

// Finding is one deduplicated, triaged audit finding: a PolicyCheckFinding plus
// the file it came from, the scanner that produced it, and a deterministic
// false-positive hint.
type Finding struct {
	tools.PolicyCheckFinding
	FilePath string `json:"file_path"`
	Scan     string `json:"scan"`
	// Triage is the deterministic false-positive hint. "" means the finding
	// stands; "likely-fixture" means it sits in a test / fixture / example path
	// and is reported but demoted below confirmed findings. This is the seed the
	// LLM adversarial-verify lane later refines or overturns.
	Triage string `json:"triage,omitempty"`
}

// Report is the result of a whole-tree audit.
type Report struct {
	Root         string                     `json:"root"`
	FilesScanned int                        `json:"files_scanned"`
	Findings     []Finding                  `json:"findings"`
	Counts       map[string]int             `json:"counts"` // by severity, confirmed (non-triaged) only
	Triaged      int                        `json:"triaged"`
	Results      []*tools.PolicyCheckResult `json:"-"` // raw per-file results, for SARIF / HTML report reuse
}

// Confirmed returns the findings the triage pass did not demote.
func (r *Report) Confirmed() []Finding {
	out := make([]Finding, 0, len(r.Findings))
	for _, f := range r.Findings {
		if f.Triage == "" {
			out = append(out, f)
		}
	}
	return out
}

// Total is the count of confirmed (non-triaged) findings.
func (r *Report) Total() int {
	n := 0
	for _, f := range r.Findings {
		if f.Triage == "" {
			n++
		}
	}
	return n
}

// Run scans every file concurrently with the given library factory, then
// deduplicates, triages, and ranks the findings into a Report. ctx cancellation
// stops the walk and returns ctx.Err(). A per-file scanner error skips that
// file rather than aborting the whole audit — a single unreadable file must not
// sink a repo-wide run.
func Run(ctx context.Context, files []string, newLib LibraryFactory, opts Options) (*Report, error) {
	floor := strings.ToLower(strings.TrimSpace(opts.SeverityFloor))
	if floor == "" {
		floor = defaultFloor
	}

	jobs := opts.Jobs
	if jobs <= 0 {
		jobs = runtime.NumCPU()
	}
	jobs = min(jobs, maxJobs)
	jobs = max(jobs, 1)
	if len(files) > 0 {
		jobs = min(jobs, len(files))
	}

	// Build one library per worker up front so a factory error fails fast,
	// before any scanning starts.
	libs := make([]*tools.Library, jobs)
	for i := range libs {
		lib, err := newLib()
		if err != nil {
			return nil, err
		}
		libs[i] = lib
	}

	in := make(chan string)
	var (
		mu      sync.Mutex
		results []*tools.PolicyCheckResult
		wg      sync.WaitGroup
	)
	wg.Add(jobs)
	for i := 0; i < jobs; i++ {
		lib := libs[i]
		go func() {
			defer wg.Done()
			for file := range in {
				if ctx.Err() != nil {
					return
				}
				abs, err := filepath.Abs(file)
				if err != nil {
					abs = file
				}
				res, err := lib.PolicyCheck(abs, floor)
				if err != nil || res == nil {
					continue
				}
				mu.Lock()
				results = append(results, res)
				mu.Unlock()
			}
		}()
	}

feed:
	for _, f := range files {
		select {
		case <-ctx.Done():
			break feed
		case in <- f:
		}
	}
	close(in)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	rep := build(opts.Root, results)
	if opts.Reviewer != nil {
		if err := enrich(ctx, rep, opts.SweepFiles, opts.Reviewer, jobs); err != nil {
			return rep, err
		}
	}
	return rep, nil
}

// build turns raw per-file results into a deduplicated, triaged, ranked Report.
func build(root string, results []*tools.PolicyCheckResult) *Report {
	rep := &Report{
		Root:         root,
		FilesScanned: len(results),
		Counts:       map[string]int{},
		Results:      results,
	}
	seen := make(map[string]bool)
	for _, res := range results {
		triage := triagePath(res.FilePath)
		for _, pf := range res.Findings {
			f := Finding{
				PolicyCheckFinding: pf,
				FilePath:           res.FilePath,
				Scan:               res.Scan,
				Triage:             triage,
			}
			k := findingKey(f)
			if seen[k] {
				continue
			}
			seen[k] = true
			rep.Findings = append(rep.Findings, f)
		}
	}
	for _, f := range rep.Findings {
		if f.Triage != "" {
			rep.Triaged++
			continue
		}
		sev := strings.ToLower(strings.TrimSpace(f.Severity))
		if sev == "" {
			sev = "info"
		}
		rep.Counts[sev]++
	}
	sortFindings(rep.Findings)
	return rep
}

// findingKey is the deduplication identity of a finding: file, rule, line, and
// package/version. Used by both the deterministic build and the LLM merge.
func findingKey(f Finding) string {
	return f.FilePath + "\x00" + f.RuleID + "\x00" +
		strconv.Itoa(f.Line) + "\x00" + f.Package + "\x00" + f.Version
}

// newSemanticFinding turns a model sweep item into a PolicyCheckFinding, namespacing
// the rule id under secure-vibe.llm and defaulting an unknown severity to medium.
func newSemanticFinding(it sweepItem) tools.PolicyCheckFinding {
	sev := strings.ToLower(strings.TrimSpace(it.Severity))
	if severityRank(sev) == 0 {
		sev = "medium"
	}
	rule := strings.TrimSpace(it.RuleID)
	if rule == "" {
		rule = "finding"
	}
	return tools.PolicyCheckFinding{
		RuleID:     "secure-vibe.llm." + rule,
		Severity:   sev,
		Confidence: "model",
		Title:      strings.TrimSpace(it.Title),
		Line:       it.Line,
	}
}

// sortFindings orders confirmed findings before triaged ones, then by severity
// (critical first), then by file and line for a stable, readable report.
func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if at, bt := a.Triage != "", b.Triage != ""; at != bt {
			return !at // confirmed (non-triaged) first
		}
		if ra, rb := severityRank(a.Severity), severityRank(b.Severity); ra != rb {
			return ra > rb
		}
		if a.FilePath != b.FilePath {
			return a.FilePath < b.FilePath
		}
		return a.Line < b.Line
	})
}

// severityRank weights severities so higher is worse. It mirrors the private
// ranking in internal/tools (critical=4 … low=1) without exporting it.
func severityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 4
	case "high", "error":
		return 3
	case "medium", "moderate", "warning":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// fixtureSegments are path segments that mark a file as test / fixture / example
// data. A finding inside one is real code the scanner matched, but overwhelmingly
// a deliberate sample rather than a shipped vulnerability, so audit demotes it.
// These are generic dev conventions — the semantic verify lane does the nuanced
// judgement; this is only the cheap deterministic first pass.
var fixtureSegments = map[string]bool{
	"test": true, "tests": true, "__tests__": true, "testdata": true,
	"fixture": true, "fixtures": true, "spec": true, "specs": true,
	"mock": true, "mocks": true, "example": true, "examples": true,
	"sample": true, "samples": true, "corpus": true, "e2e": true,
}

// triagePath returns "likely-fixture" when any path segment is a fixture/test
// convention, else "".
func triagePath(p string) string {
	for _, seg := range strings.Split(filepath.ToSlash(p), "/") {
		if fixtureSegments[strings.ToLower(seg)] {
			return "likely-fixture"
		}
	}
	return ""
}
