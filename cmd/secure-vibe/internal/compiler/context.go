package compiler

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// LoadContext assembles the vulnerability summary and dictionary callouts that
// every formatter receives. Missing files are skipped silently so the compiler
// works on partial repositories.
func LoadContext(repoRoot string) (Context, error) {
	var ctx Context

	vuln, err := loadVulnerabilitySummary(repoRoot)
	if err != nil {
		return ctx, err
	}
	ctx.VulnerabilitySummary = vuln

	glossary, err := loadGlossary(repoRoot)
	if err != nil {
		return ctx, err
	}
	ctx.GlossaryEntries = glossary

	attack, err := loadAttackTechniques(repoRoot)
	if err != nil {
		return ctx, err
	}
	ctx.AttackTechniques = attack

	return ctx, nil
}

type vulnEntry struct {
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	AttackType  string `json:"attack_type"`
	Discovered  string `json:"discovered"`
}

type vulnFile struct {
	Ecosystem string      `json:"ecosystem"`
	Entries   []vulnEntry `json:"entries"`
}

func loadVulnerabilitySummary(repoRoot string) (string, error) {
	dir := filepath.Join(repoRoot, "vulnerabilities", "supply-chain", "malicious-packages")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}

	type item struct {
		ecosystem string
		entry     vulnEntry
	}
	var items []item
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return "", err
		}
		var vf vulnFile
		if err := json.Unmarshal(data, &vf); err != nil {
			return "", fmt.Errorf("vulnerability file %s: %w", e.Name(), err)
		}
		for _, ent := range vf.Entries {
			items = append(items, item{ecosystem: vf.Ecosystem, entry: ent})
		}
	}
	if len(items) == 0 {
		return "", nil
	}
	severityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	sort.Slice(items, func(i, j int) bool {
		si, sj := severityOrder[items[i].entry.Severity], severityOrder[items[j].entry.Severity]
		if si != sj {
			return si < sj
		}
		if items[i].entry.Discovered != items[j].entry.Discovered {
			return items[i].entry.Discovered > items[j].entry.Discovered
		}
		// Deterministic tiebreak so the top-N summary is byte-identical
		// across platforms — without it, sort.Slice leaves entries that
		// share a severity and discovered date in an unstable order, and
		// the top-8 cutoff would pick different ties on arm64 vs amd64,
		// drifting dist/SECURITY-SKILLS.md between local and CI.
		if items[i].ecosystem != items[j].ecosystem {
			return items[i].ecosystem < items[j].ecosystem
		}
		return items[i].entry.Name < items[j].entry.Name
	})

	max := 8
	if len(items) < max {
		max = len(items)
	}
	var b []byte
	for i := 0; i < max; i++ {
		it := items[i]
		line := fmt.Sprintf("- **%s** (%s, %s) — %s\n",
			it.entry.Name, it.ecosystem, it.entry.Severity, it.entry.Description)
		b = append(b, line...)
	}
	return string(b), nil
}

type termEntry struct {
	Term       string `yaml:"term"`
	Definition string `yaml:"definition"`
}

type termsFile struct {
	Terms []termEntry `yaml:"terms"`
}

func loadGlossary(repoRoot string) ([]string, error) {
	path := filepath.Join(repoRoot, "dictionaries", "security_terms.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var tf termsFile
	if err := yaml.Unmarshal(data, &tf); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	priority := map[string]bool{
		"secret": true, "credential": true, "SBOM": true,
		"SAST": true, "DAST": true, "SCA": true,
		"BOLA": true, "IDOR": true, "SSRF": true,
		"XSS": true, "CSRF": true, "RCE": true,
		"MITRE ATT&CK": true,
	}
	var out []string
	for _, t := range tf.Terms {
		if priority[t.Term] {
			out = append(out, fmt.Sprintf("**%s** — %s", t.Term, t.Definition))
		}
	}
	return out, nil
}

type attackEntry struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
}

type attackFile struct {
	Techniques []attackEntry `yaml:"techniques"`
}

func loadAttackTechniques(repoRoot string) ([]string, error) {
	path := filepath.Join(repoRoot, "dictionaries", "attack_techniques.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var af attackFile
	if err := yaml.Unmarshal(data, &af); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	// Pick the 8 most universally-applicable techniques.
	primary := map[string]bool{
		"T1195": true, "T1195.001": true, "T1059": true,
		"T1552": true, "T1552.001": true, "T1554": true,
		"T1190": true, "T1496": true,
	}
	var out []string
	for _, t := range af.Techniques {
		if primary[t.ID] {
			out = append(out, fmt.Sprintf("`%s` %s — %s", t.ID, t.Name, t.Description))
		}
	}
	return out, nil
}
