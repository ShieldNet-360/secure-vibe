package compiler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shieldnet-360/secure-vibe/internal/skill"
)

// repoRoot walks upward from the test binary cwd to find the repository root.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for dir := wd; dir != "/"; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
	}
	t.Fatal("could not find repository root from " + wd)
	return ""
}

func loadAllSkills(t *testing.T) []*skill.Skill {
	t.Helper()
	root := repoRoot(t)
	skills, err := skill.LoadAll(filepath.Join(root, "skills"))
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(skills) == 0 {
		t.Fatal("no skills found")
	}
	return skills
}

func TestEachFormatterProducesOutput(t *testing.T) {
	skills := loadAllSkills(t)
	for _, f := range AllTools() {
		t.Run(f.Name(), func(t *testing.T) {
			out, report, _, err := Compile(skills, f.Name(), f.DefaultTier(), Context{})
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			if len(out) < 200 {
				t.Errorf("output suspiciously small: %d bytes", len(out))
			}
			// Since v3 every per-tool formatter defaults to the
			// minimal pointer file (no inlined skill bodies); only
			// the universal SECURITY-SKILLS.md output still inlines
			// bodies by default. So the inlined "Always" / "REQUIRE"
			// imperatives are only required from universal here.
			if f.Name() == "universal" {
				if !strings.Contains(out, "Always") && !strings.Contains(out, "ALWAYS") && !strings.Contains(out, "REQUIRE") {
					t.Errorf("universal output missing always-style rules")
				}
			}
			if report.Total.OpenAI == 0 {
				t.Errorf("token count not populated")
			}
		})
	}
}

// TestPerToolDefaultIsPointer locks in the v3 behaviour that every
// per-tool formatter (everything except universal) emits the minimal
// pointer body by default — no inlined skill bodies, mentions the
// MCP server, and stays under 4 KiB.
func TestPerToolDefaultIsPointer(t *testing.T) {
	skills := loadAllSkills(t)
	perTool := []string{"claude", "cursor", "copilot", "agents", "windsurf", "devin", "cline"}
	for _, name := range perTool {
		t.Run(name, func(t *testing.T) {
			out, _, _, err := Compile(skills, name, Registry[name].DefaultTier(), Context{})
			if err != nil {
				t.Fatalf("compile %s: %v", name, err)
			}
			if len(out) >= 4*1024 {
				t.Errorf("%s default = %d bytes; pointer body should stay under 4 KiB", name, len(out))
			}
			for _, want := range []string{"search_skills", "get_skill", "SAST, SCA", "skills/<skill-id>/SKILL.md"} {
				if !strings.Contains(out, want) {
					t.Errorf("%s pointer body missing %q", name, want)
				}
			}
		})
	}
}

// TestPerToolFullInlineRestoresBodies locks in that --full-inline (the
// Context.FullInline flag) brings back the pre-v3 monolithic output
// for every per-tool formatter, not only AGENTS.md.
func TestPerToolFullInlineRestoresBodies(t *testing.T) {
	skills := loadAllSkills(t)
	perTool := []string{"claude", "cursor", "copilot", "agents", "windsurf", "devin", "cline"}
	for _, name := range perTool {
		t.Run(name, func(t *testing.T) {
			out, _, _, err := Compile(skills, name, Registry[name].DefaultTier(), Context{FullInline: true})
			if err != nil {
				t.Fatalf("compile %s full-inline: %v", name, err)
			}
			if len(out) < 4*1024 {
				t.Errorf("%s full-inline = %d bytes; legacy output should be substantially larger", name, len(out))
			}
			if !strings.Contains(out, "Always") && !strings.Contains(out, "ALWAYS") && !strings.Contains(out, "REQUIRE") {
				t.Errorf("%s full-inline must inline always-style bullets", name)
			}
		})
	}
}

// The minimal AGENTS.md is the new default. It is a pointer file
// directed at LLMs that reaches into the MCP server and skills/
// directory rather than inlining every skill body. The output
// MUST stay under 4 KiB and MUST mention the MCP server.
func TestAgentsMinimalIsUnder4KiB(t *testing.T) {
	skills := loadAllSkills(t)
	out, _, _, err := Compile(skills, "agents", skill.TierCompact, Context{})
	if err != nil {
		t.Fatalf("compile agents: %v", err)
	}
	if len(out) >= 4*1024 {
		t.Errorf("minimal AGENTS.md = %d bytes; must stay under 4 KiB", len(out))
	}
	for _, want := range []string{
		"local skills MCP server",
		"SAST, SCA",
		"search_skills",
		"get_skill",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("minimal AGENTS.md missing %q", want)
		}
	}
	if strings.Contains(out, "Operating contract: you are an autonomous coding agent") {
		t.Errorf("minimal output should not include the legacy operating-contract preamble")
	}
}

// The legacy full-inline path remains available behind
// Context.AgentsFullInline so that operators who depend on the
// pre-v2 monolithic format can opt back in.
func TestAgentsFullInlineRestoresLegacyOutput(t *testing.T) {
	skills := loadAllSkills(t)
	out, _, _, err := Compile(skills, "agents", skill.TierCompact, Context{AgentsFullInline: true})
	if err != nil {
		t.Fatalf("compile agents full-inline: %v", err)
	}
	if len(out) < 4*1024 {
		t.Errorf("full-inline AGENTS.md = %d bytes; legacy output should be substantially larger", len(out))
	}
	if !strings.Contains(out, "Operating contract: you are an autonomous coding agent") {
		t.Errorf("full-inline output should include the legacy operating-contract preamble")
	}
	if !strings.Contains(out, "Always") {
		t.Errorf("full-inline output must inline always-style bullets")
	}
}

func TestAllSeventSkillsCompile(t *testing.T) {
	skills := loadAllSkills(t)
	if len(skills) < 7 {
		t.Fatalf("expected at least 7 skills, got %d", len(skills))
	}
	for _, tier := range []skill.Tier{skill.TierMinimal, skill.TierCompact, skill.TierFull} {
		_, _, _, err := Compile(skills, "universal", tier, Context{})
		if err != nil {
			t.Errorf("compile universal %s: %v", tier, err)
		}
	}
}

func TestPerSkillBudgetRespected(t *testing.T) {
	skills := loadAllSkills(t)
	_, report, warnings, err := Compile(skills, "claude", skill.TierCompact, Context{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, s := range skills {
		c := report.PerSkill[s.Frontmatter.ID]
		if c.Claude > s.Frontmatter.TokenBudget.Compact {
			t.Errorf("%s compact %d exceeds budget %d", s.Frontmatter.ID, c.Claude, s.Frontmatter.TokenBudget.Compact)
		}
	}
	for _, w := range warnings {
		if strings.Contains(w, "exceeds declared compact budget") {
			t.Errorf("unexpected per-skill warning: %s", w)
		}
	}
}

func TestMissingSkillsDirectory(t *testing.T) {
	dir := t.TempDir()
	skills, err := skill.LoadAll(filepath.Join(dir, "skills"))
	if err == nil && skills != nil {
		// LoadAll should error on missing directory.
	}
	if err == nil {
		t.Errorf("expected error from LoadAll on missing directory")
	}
}

func TestUnknownToolErrors(t *testing.T) {
	skills := loadAllSkills(t)
	_, _, _, err := Compile(skills, "fictional", skill.TierCompact, Context{})
	if err == nil {
		t.Fatalf("expected error for unknown tool")
	}
	if !strings.Contains(err.Error(), "unknown tool") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWriteAllRegeneratesAllEightFiles(t *testing.T) {
	skills := loadAllSkills(t)
	outDir := t.TempDir()
	reports, _, err := WriteAll(skills, Context{}, outDir)
	if err != nil {
		t.Fatalf("WriteAll: %v", err)
	}
	if len(reports) != 8 {
		t.Errorf("expected 8 reports, got %d", len(reports))
	}
	expected := []string{
		"CLAUDE.md", ".cursorrules", "copilot-instructions.md", "AGENTS.md",
		".windsurfrules", "devin.md", ".clinerules", "SECURITY-SKILLS.md",
	}
	for _, name := range expected {
		p := filepath.Join(outDir, name)
		info, err := os.Stat(p)
		if err != nil {
			t.Errorf("missing %s: %v", name, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("%s is empty", name)
		}
	}
}

func TestDevinFormatterDefaultsToFull(t *testing.T) {
	if Registry["devin"].DefaultTier() != skill.TierFull {
		t.Errorf("devin should default to full tier")
	}
	for name, f := range Registry {
		if name == "devin" {
			continue
		}
		if f.DefaultTier() == skill.TierFull {
			t.Logf("note: %s also defaults to full tier", name)
		}
	}
}

func TestContextInjection(t *testing.T) {
	skills := loadAllSkills(t)
	ctx := Context{
		VulnerabilitySummary: "- example-package — example description\n",
		GlossaryEntries:      []string{"**SBOM** — bill of materials"},
		AttackTechniques:     []string{"`T1195` Supply Chain Compromise"},
		// Vulnerability / glossary / ATT&CK callouts are only
		// emitted in the monolithic full-inline output. The
		// default pointer file is intentionally body-less; it
		// points consumers at the MCP server for these data
		// instead. Lock the injection invariant down with the
		// flag set so the test stays meaningful post-v3.
		FullInline: true,
	}
	out, _, _, err := Compile(skills, "claude", skill.TierCompact, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "example-package") {
		t.Errorf("vulnerability summary not injected")
	}
	if !strings.Contains(out, "SBOM") {
		t.Errorf("glossary not injected")
	}
	if !strings.Contains(out, "T1195") {
		t.Errorf("attack techniques not injected")
	}
}

func TestDeterministicOutput(t *testing.T) {
	skills := loadAllSkills(t)
	a, _, _, err := Compile(skills, "claude", skill.TierCompact, Context{})
	if err != nil {
		t.Fatal(err)
	}
	b, _, _, err := Compile(skills, "claude", skill.TierCompact, Context{})
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("compile output is not deterministic")
	}
}
