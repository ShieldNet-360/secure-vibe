// SARIF 2.1.0 converters for the project-scoped scanners introduced
// in v3 of the MCP server: scan_dependencies, scan_github_actions,
// and scan_dockerfile. Mirrors the shape of CheckDependencySARIF /
// ScanSecretsSARIF so a CI consumer can ingest any of them through
// the same SARIF pipeline.
package tools

import (
	"fmt"
	"sort"
	"strings"
)

// ScanDependenciesSARIF converts a ScanDependenciesResult into a
// SARIF 2.1.0 log. Each (category, severity) pair becomes one SARIF
// rule so a CI dashboard can filter on
// `secure-vibe.malicious-package`, `secure-vibe.typosquat`,
// `secure-vibe.cve-pattern`, or `secure-vibe.scan-error`.
func ScanDependenciesSARIF(res *ScanDependenciesResult) *SARIFLog {
	if res == nil {
		return emptyLog("scan_dependencies")
	}
	rules := make([]SARIFRule, 0)
	ruleIndex := map[string]int{}
	ensureRule := func(category, descr, level string) string {
		id := "secure-vibe mcp." + category
		if _, ok := ruleIndex[id]; ok {
			return id
		}
		ruleIndex[id] = len(rules)
		rules = append(rules, SARIFRule{
			ID:               id,
			Name:             category,
			ShortDescription: &SARIFMultiformat{Text: descr},
			DefaultConfig:    &SARIFRuleConfig{Level: level},
		})
		return id
	}
	uri := fileURI(res.FilePath)
	results := make([]SARIFResult, 0, len(res.Findings))
	for _, f := range res.Findings {
		descr := "Project dependency scan finding."
		switch f.Category {
		case "malicious-package":
			descr = "Package matched against the supply-chain malicious-packages database."
		case "typosquat":
			descr = "Package matched against the curated typosquat database."
		case "cve-pattern":
			descr = "Package name or description matched a tracked CVE pattern."
		case "scan-error":
			descr = "scan_dependencies could not evaluate this row."
		}
		id := ensureRule(f.Category, descr, sarifLevel(f.Severity))
		results = append(results, SARIFResult{
			RuleID:    id,
			RuleIndex: ruleIndex[id],
			Level:     sarifLevel(f.Severity),
			Message: SARIFMultiformat{
				Text: fmt.Sprintf("%s@%s [%s] — %s", f.Package, f.Version, f.Ecosystem, f.Message),
			},
			Locations: []SARIFLocation{{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: uri},
				},
			}},
			Properties: depsProperties(f),
		})
	}
	sortRulesAndResults(rules, ruleIndex, results)
	return &SARIFLog{
		Schema:  SARIFSchema,
		Version: SARIFVersion,
		Runs: []SARIFRun{{
			Tool: SARIFTool{Driver: SARIFDriver{
				Name:           SARIFToolName,
				InformationURI: "https://github.com/shieldnet-360/secure-vibe",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
}

func depsProperties(f DependencyFinding) map[string]any {
	p := map[string]any{
		"package":   f.Package,
		"version":   f.Version,
		"ecosystem": f.Ecosystem,
		"category":  f.Category,
		"severity":  f.Severity,
	}
	if f.Source != "" {
		p["source"] = f.Source
	}
	if f.CVE != "" {
		p["cve"] = f.CVE
	}
	if f.AttackType != "" {
		p["attack_type"] = f.AttackType
	}
	if len(f.References) > 0 {
		p["references"] = f.References
	}
	for k, v := range f.Extra {
		p[k] = v
	}
	return p
}

// ScanGitHubActionsSARIF converts a ScanGitHubActionsResult into a
// SARIF 2.1.0 log. Each hardening rule ID becomes one SARIF rule;
// findings carry the line number from the matched workflow file.
func ScanGitHubActionsSARIF(res *ScanGitHubActionsResult) *SARIFLog {
	if res == nil {
		return emptyLog("scan_github_actions")
	}
	rules := make([]SARIFRule, 0)
	ruleIndex := map[string]int{}
	uri := fileURI(res.FilePath)
	results := make([]SARIFResult, 0, len(res.Findings))
	for _, f := range res.Findings {
		id := "secure-vibe mcp." + f.RuleID
		if _, ok := ruleIndex[id]; !ok {
			ruleIndex[id] = len(rules)
			rules = append(rules, SARIFRule{
				ID:               id,
				Name:             f.RuleID,
				ShortDescription: &SARIFMultiformat{Text: f.Title},
				FullDescription:  &SARIFMultiformat{Text: f.Rationale},
				DefaultConfig:    &SARIFRuleConfig{Level: sarifLevel(f.Severity)},
				Properties: map[string]any{
					"source": "skills/cicd-security/SKILL.md",
				},
			})
		}
		region := &SARIFRegion{StartLine: f.Line}
		results = append(results, SARIFResult{
			RuleID:    id,
			RuleIndex: ruleIndex[id],
			Level:     sarifLevel(f.Severity),
			Message:   SARIFMultiformat{Text: f.Title},
			Locations: []SARIFLocation{{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: uri},
					Region:           region,
				},
			}},
			Properties: map[string]any{
				"severity": f.Severity,
				"fix":      f.Fix,
				"snippet":  f.Snippet,
			},
		})
	}
	sortRulesAndResults(rules, ruleIndex, results)
	return &SARIFLog{
		Schema:  SARIFSchema,
		Version: SARIFVersion,
		Runs: []SARIFRun{{
			Tool: SARIFTool{Driver: SARIFDriver{
				Name:           SARIFToolName,
				InformationURI: "https://github.com/shieldnet-360/secure-vibe",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
}

// ScanDockerfileSARIF converts a ScanDockerfileResult into a SARIF
// 2.1.0 log.
func ScanDockerfileSARIF(res *ScanDockerfileResult) *SARIFLog {
	if res == nil {
		return emptyLog("scan_dockerfile")
	}
	rules := make([]SARIFRule, 0)
	ruleIndex := map[string]int{}
	uri := fileURI(res.FilePath)
	results := make([]SARIFResult, 0, len(res.Findings))
	for _, f := range res.Findings {
		id := "secure-vibe mcp." + f.RuleID
		if _, ok := ruleIndex[id]; !ok {
			ruleIndex[id] = len(rules)
			rules = append(rules, SARIFRule{
				ID:               id,
				Name:             f.RuleID,
				ShortDescription: &SARIFMultiformat{Text: f.Title},
				DefaultConfig:    &SARIFRuleConfig{Level: sarifLevel(f.Severity)},
				Properties: map[string]any{
					"source": "skills/container-security/SKILL.md",
				},
			})
		}
		region := &SARIFRegion{StartLine: f.Line}
		results = append(results, SARIFResult{
			RuleID:    id,
			RuleIndex: ruleIndex[id],
			Level:     sarifLevel(f.Severity),
			Message:   SARIFMultiformat{Text: f.Title},
			Locations: []SARIFLocation{{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: uri},
					Region:           region,
				},
			}},
			Properties: map[string]any{
				"severity": f.Severity,
				"fix":      f.Fix,
				"snippet":  f.Snippet,
			},
		})
	}
	sortRulesAndResults(rules, ruleIndex, results)
	return &SARIFLog{
		Schema:  SARIFSchema,
		Version: SARIFVersion,
		Runs: []SARIFRun{{
			Tool: SARIFTool{Driver: SARIFDriver{
				Name:           SARIFToolName,
				InformationURI: "https://github.com/shieldnet-360/secure-vibe",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
}

// sortRulesAndResults sorts the rules slice alphabetically by ID and
// rewrites every result's RuleIndex so it still points at the same
// rule after the sort. Without this the rule order would follow
// finding-discovery order, which is not stable across runs (the
// underlying maps iterate non-deterministically). A stable rule
// order is what makes SARIF diffs reviewable.
func sortRulesAndResults(rules []SARIFRule, ruleIndex map[string]int, results []SARIFResult) {
	if len(rules) <= 1 {
		return
	}
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	newIndex := map[string]int{}
	for i, r := range rules {
		newIndex[r.ID] = i
	}
	for i := range results {
		if v, ok := newIndex[results[i].RuleID]; ok {
			results[i].RuleIndex = v
		}
	}
	// Sort results by (RuleID, then message) for stability.
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].RuleID != results[j].RuleID {
			return results[i].RuleID < results[j].RuleID
		}
		return results[i].Message.Text < results[j].Message.Text
	})
	// Touch ruleIndex so the original caller still sees the
	// post-sort indices if they later iterate it. (Currently no
	// caller does — the map is local to each converter — but
	// keeping it consistent prevents foot-guns if a future converter
	// reuses the map after sorting.)
	for k := range ruleIndex {
		delete(ruleIndex, k)
	}
	for k, v := range newIndex {
		ruleIndex[k] = v
	}
	// Hide noisy lint about strings; the loops above already
	// reference the package via SARIFMultiformat.
	_ = strings.TrimSpace
}
