// Package proposal is the LEARN loop for knowledge: an append-only,
// local, UNSIGNED log of agent-recorded suggestions that a signed skill
// is missing a fact, wrong, or stale.
//
// The store is deliberately inert. Recording a proposal never edits the
// signed SKILL.md, never signs anything, and never opens a pull request.
// That inertness is the trust boundary: skills are Ed25519-signed, so a
// model (which can be steered by prompt injection in the code it is
// reading) must not be able to mutate trusted knowledge. Instead the
// proposal lands in .secure-vibe/skill-proposals.jsonl, a human reviews
// it (`secure-vibe contribute skill`), and — only if it holds up — edits
// the skill by hand and re-runs the signing pipeline. The human review +
// re-sign is the gate.
//
// It sits beside the contribution overlay (.secure-vibe/overlay.json) so
// the same "commit it to share with the team" workflow covers knowledge
// and vuln data alike.
package proposal

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// RelPath is the project-local proposal log, under the same .secure-vibe/
// directory as the contribution overlay.
const RelPath = ".secure-vibe/skill-proposals.jsonl"

// EnvFile, when set, overrides the proposal log location with an absolute
// path (e.g. a shared review inbox). Mirrors SECURE_VIBE_OVERLAY's intent.
const EnvFile = "SECURE_VIBE_PROPOSALS_FILE"

// The kinds a proposal may carry: knowledge the skill lacks, knowledge
// the skill states incorrectly, or knowledge that has gone stale.
const (
	KindMissing  = "missing"
	KindWrong    = "wrong"
	KindOutdated = "outdated"
)

// Proposal is one agent-recorded suggestion about a skill's knowledge.
// It is inert until a human reviews it; see the package comment.
type Proposal struct {
	// ID is a stable, content-derived identifier (sp-<hex>) over
	// (skill_id, kind, claim), so re-recording the same suggestion is
	// idempotent instead of piling up duplicates.
	ID      string `json:"id"`
	SkillID string `json:"skill_id"`
	Kind    string `json:"kind"`
	// Claim is the new/corrected knowledge, stated plainly.
	Claim string `json:"claim"`
	// Evidence is why the claim holds — a source, a repro, a CVE, a spec
	// link. Required, so a proposal is reviewable rather than a bare
	// assertion (and harder to fabricate).
	Evidence string `json:"evidence"`
	// SuggestedText is an optional drop-in edit for the SKILL.md.
	SuggestedText string `json:"suggested_text,omitempty"`
	// Source records who recorded it (e.g. "agent"), for the audit trail.
	Source string `json:"source,omitempty"`
	// Recorded is the UTC date the proposal was logged.
	Recorded string `json:"recorded"`
}

// ValidKind reports whether k is one of the recognised kinds.
func ValidKind(k string) bool {
	switch strings.ToLower(strings.TrimSpace(k)) {
	case KindMissing, KindWrong, KindOutdated:
		return true
	}
	return false
}

// idFor derives the content-addressed proposal id. Provenance fields
// (evidence, timestamp, source) are excluded so the same underlying
// suggestion dedups even if the evidence is reworded.
func idFor(skillID, kind, claim string) string {
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(skillID)) + "\x00" +
		strings.ToLower(strings.TrimSpace(kind)) + "\x00" +
		strings.TrimSpace(claim)))
	return "sp-" + hex.EncodeToString(h[:6])
}

// PathFor resolves the proposal log inside dir (default cwd). The
// SECURE_VIBE_PROPOSALS_FILE env override wins outright when set.
func PathFor(dir string) (string, error) {
	if env := strings.TrimSpace(os.Getenv(EnvFile)); env != "" {
		return env, nil
	}
	if strings.TrimSpace(dir) == "" {
		wd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		dir = wd
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	return filepath.Join(abs, RelPath), nil
}

// Record validates, normalises, and appends p to the log at path,
// returning the stored proposal and whether it was newly added. It is
// idempotent: a proposal whose content id already exists is left as-is
// (isNew=false) so an agent that re-reports the same gap does not
// duplicate it. now is injected so callers/tests control the timestamp.
func Record(path string, p Proposal, now time.Time) (stored Proposal, isNew bool, err error) {
	p.SkillID = strings.TrimSpace(p.SkillID)
	p.Kind = strings.ToLower(strings.TrimSpace(p.Kind))
	p.Claim = strings.TrimSpace(p.Claim)
	p.Evidence = strings.TrimSpace(p.Evidence)
	p.SuggestedText = strings.TrimSpace(p.SuggestedText)
	if p.Source = strings.TrimSpace(p.Source); p.Source == "" {
		p.Source = "agent"
	}
	if p.SkillID == "" {
		return Proposal{}, false, fmt.Errorf("skill_id is required")
	}
	if !ValidKind(p.Kind) {
		return Proposal{}, false, fmt.Errorf("kind must be one of %s, %s, %s", KindMissing, KindWrong, KindOutdated)
	}
	if p.Claim == "" {
		return Proposal{}, false, fmt.Errorf("claim is required (what the skill should say)")
	}
	if p.Evidence == "" {
		return Proposal{}, false, fmt.Errorf("evidence is required (why the claim holds — a source, repro, or spec)")
	}
	p.ID = idFor(p.SkillID, p.Kind, p.Claim)
	p.Recorded = now.UTC().Format("2006-01-02")

	existing, err := Load(path)
	if err != nil {
		return Proposal{}, false, err
	}
	for _, e := range existing {
		if e.ID == p.ID {
			return e, false, nil // already recorded — idempotent
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return Proposal{}, false, err
	}
	line, err := json.Marshal(p)
	if err != nil {
		return Proposal{}, false, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return Proposal{}, false, err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return Proposal{}, false, err
	}
	return p, true, nil
}

// Load reads every proposal from the JSONL log at path. A missing file
// yields an empty slice (the log is optional); a malformed line is
// skipped rather than failing the read, so one bad append never blocks
// review of the rest.
func Load(path string) ([]Proposal, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []Proposal
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var p Proposal
		if json.Unmarshal([]byte(line), &p) != nil {
			continue
		}
		out = append(out, p)
	}
	return out, sc.Err()
}

// Get returns the proposal with the given id, or (nil, nil) if none
// matches. A short unique prefix of an id is accepted for convenience.
func Get(path, id string) (*Proposal, error) {
	id = strings.TrimSpace(id)
	all, err := Load(path)
	if err != nil {
		return nil, err
	}
	var match *Proposal
	for i := range all {
		if all[i].ID == id {
			p := all[i]
			return &p, nil
		}
		if id != "" && strings.HasPrefix(all[i].ID, id) {
			if match != nil {
				return nil, fmt.Errorf("id prefix %q is ambiguous", id)
			}
			p := all[i]
			match = &p
		}
	}
	return match, nil
}
