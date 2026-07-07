package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/shieldnet-360/secure-vibe/internal/llm"
)

// Reviewer is the optional model-backed lane layered on top of the deterministic
// audit. It is nil for a deterministic-only run, so an audit with no model
// configured behaves exactly as Phase 1.
type Reviewer interface {
	// Sweep reads one file through the security lens and returns extra candidate
	// findings the pattern scanners cannot see (semantic sinks, authz gaps, …).
	Sweep(ctx context.Context, path, content string) ([]Finding, error)
	// Refute adversarially checks a candidate finding against its code context,
	// returning whether it is a likely false positive and why.
	Refute(ctx context.Context, f Finding, content string) (refuted bool, reason string, err error)
}

// semanticScan tags findings produced by the LLM sweep lane.
const semanticScan = "llm-semantic"

// contentLimit caps how much of a file is sent to the model per call, keeping
// prompts bounded on large files.
const contentLimit = 24 * 1024

// LLMReviewer implements Reviewer against any llm.Provider. It injects SecureVibe
// skill knowledge (Lens) so the model judges with the same rules the prevention
// side ships. Votes controls the adversarial refute rounds — a finding is
// refuted only when a strict majority of votes say so.
type LLMReviewer struct {
	Provider llm.Provider
	Lens     string
	Votes    int
}

type sweepItem struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Line     int    `json:"line"`
}

// Sweep asks the model for concrete, high-confidence vulnerabilities in one file.
func (r *LLMReviewer) Sweep(ctx context.Context, path, content string) ([]Finding, error) {
	if len(content) > contentLimit {
		content = content[:contentLimit]
	}
	system := "You are a precise application-security auditor. Using the security" +
		" knowledge below, read the file and report ONLY concrete, high-confidence" +
		" vulnerabilities a reviewer could act on. Do not report style or hypotheticals.\n\n" +
		"=== SECURITY KNOWLEDGE ===\n" + r.Lens
	user := fmt.Sprintf(
		"Report findings as a JSON array; each item: "+
			`{"rule_id":"short-slug","severity":"critical|high|medium|low","title":"one line","line":<int>}.`+
			" Return [] if there are none. Output JSON only, no prose.\n\nFILE: %s\n```\n%s\n```",
		path, content)

	out, err := r.Provider.Complete(ctx, llm.Request{System: system, User: user, Temperature: 0})
	if err != nil {
		return nil, err
	}
	var items []sweepItem
	if err := json.Unmarshal([]byte(extractJSON(out, '[')), &items); err != nil {
		return nil, fmt.Errorf("sweep: parse model output: %w", err)
	}
	findings := make([]Finding, 0, len(items))
	for _, it := range items {
		if strings.TrimSpace(it.Title) == "" {
			continue
		}
		findings = append(findings, Finding{
			PolicyCheckFinding: newSemanticFinding(it),
			FilePath:           path,
			Scan:               semanticScan,
			Triage:             triagePath(path),
		})
	}
	return findings, nil
}

type verdict struct {
	Refuted bool   `json:"refuted"`
	Reason  string `json:"reason"`
}

// Refute runs Votes adversarial rounds; the finding is refuted on a strict
// majority. Each round is prompted to default to "refuted" under uncertainty, so
// only findings that survive skeptical scrutiny stand.
func (r *LLMReviewer) Refute(ctx context.Context, f Finding, content string) (bool, string, error) {
	votes := r.Votes
	if votes < 1 {
		votes = 1
	}
	if len(content) > contentLimit {
		content = content[:contentLimit]
	}
	system := "You are a skeptical security reviewer. Your job is to REFUTE the" +
		" candidate finding: decide whether it is a false positive — a test/fixture," +
		" unreachable code, an example, a value that is not actually secret/exploitable," +
		" or otherwise not a real shippable vulnerability. Default to refuted=true when" +
		" genuinely uncertain."
	loc := f.FilePath
	if f.Line > 0 {
		loc = fmt.Sprintf("%s:%d", f.FilePath, f.Line)
	}
	user := fmt.Sprintf(
		`Respond with JSON only: {"refuted":true|false,"reason":"one line"}.`+
			"\n\nFINDING: [%s] %s (severity %s) at %s\n\nCODE:\n```\n%s\n```",
		f.RuleID, f.Title, f.Severity, loc, content)

	refutes := 0
	var reason string
	for i := 0; i < votes; i++ {
		if ctx.Err() != nil {
			return false, "", ctx.Err()
		}
		out, err := r.Provider.Complete(ctx, llm.Request{System: system, User: user, Temperature: 0, MaxTokens: 512})
		if err != nil {
			return false, "", err
		}
		var v verdict
		if err := json.Unmarshal([]byte(extractJSON(out, '{')), &v); err != nil {
			// A malformed verdict is inconclusive; count it as "not refuted"
			// rather than fail the whole audit.
			continue
		}
		if v.Refuted {
			refutes++
			if strings.TrimSpace(v.Reason) != "" {
				reason = v.Reason
			}
		}
	}
	return refutes*2 > votes, reason, nil
}

// enrich runs the LLM lanes over a deterministic Report in place: a semantic
// sweep of the given source files adds candidate findings, then an adversarial
// refute pass demotes likely false positives. Counts and ordering are rebuilt.
func enrich(ctx context.Context, rep *Report, sweepFiles []string, rev Reviewer, jobs int) error {
	if rev == nil {
		return nil
	}
	cache := &contentCache{m: map[string]string{}}

	// Lane B — semantic sweep (concurrent, best-effort per file).
	var (
		mu    sync.Mutex
		swept []Finding
	)
	parallelDo(ctx, sweepFiles, jobs, func(path string) {
		content := cache.get(path)
		if content == "" {
			return
		}
		found, err := rev.Sweep(ctx, path, content)
		if err != nil || len(found) == 0 {
			return
		}
		mu.Lock()
		swept = append(swept, found...)
		mu.Unlock()
	})
	mergeFindings(rep, swept)

	// Adversarial verify — refute pass over every not-yet-triaged finding.
	targets := make([]int, 0, len(rep.Findings))
	for i, f := range rep.Findings {
		if f.Triage == "" {
			targets = append(targets, i)
		}
	}
	parallelDo(ctx, targets, jobs, func(idx int) {
		f := rep.Findings[idx]
		content := cache.get(f.FilePath)
		refuted, reason, err := rev.Refute(ctx, f, content)
		if err != nil || !refuted {
			return
		}
		tag := "refuted"
		if strings.TrimSpace(reason) != "" {
			tag = "refuted: " + reason
		}
		mu.Lock()
		rep.Findings[idx].Triage = tag
		mu.Unlock()
	})

	recount(rep)
	sortFindings(rep.Findings)
	return ctx.Err()
}

// mergeFindings adds swept candidates that are not already present (same file /
// rule / line / package), respecting fixture triage.
func mergeFindings(rep *Report, extra []Finding) {
	seen := make(map[string]bool, len(rep.Findings))
	for _, f := range rep.Findings {
		seen[findingKey(f)] = true
	}
	for _, f := range extra {
		k := findingKey(f)
		if seen[k] {
			continue
		}
		seen[k] = true
		rep.Findings = append(rep.Findings, f)
	}
}

// recount rebuilds Counts (confirmed only) and Triaged from the finding set.
func recount(rep *Report) {
	rep.Counts = map[string]int{}
	rep.Triaged = 0
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
}

// contentCache reads and caps file contents once per path, shared across the
// sweep and refute passes.
type contentCache struct {
	mu sync.Mutex
	m  map[string]string
}

func (c *contentCache) get(path string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.m[path]; ok {
		return v
	}
	b, err := os.ReadFile(path)
	s := ""
	if err == nil {
		if len(b) > contentLimit {
			b = b[:contentLimit]
		}
		s = string(b)
	}
	c.m[path] = s
	return s
}

// parallelDo runs fn over items with a bounded worker pool, stopping early on
// context cancellation.
func parallelDo[T any](ctx context.Context, items []T, jobs int, fn func(T)) {
	if jobs < 1 {
		jobs = 1
	}
	sem := make(chan struct{}, jobs)
	var wg sync.WaitGroup
	for _, it := range items {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(it T) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(it)
		}(it)
	}
	wg.Wait()
}

// extractJSON pulls the first JSON value of the given opening delimiter ('[' or
// '{') out of a model response, tolerating ```json fences and surrounding prose.
func extractJSON(s string, open byte) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	close := byte(']')
	if open == '{' {
		close = '}'
	}
	i := strings.IndexByte(s, open)
	j := strings.LastIndexByte(s, close)
	if i >= 0 && j > i {
		return s[i : j+1]
	}
	return s
}
