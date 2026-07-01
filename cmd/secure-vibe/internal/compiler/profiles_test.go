package compiler

import (
	"testing"

	"github.com/shieldnet-360/secure-vibe/internal/skill"
)

// TestFilterSkillsByProfileDoesNotMutateCaller is the regression test for
// the bug where FilterSkillsByProfile used `out := allSkills[:0]` and
// therefore wrote into the caller's backing array. Two consecutive calls
// on the same input would silently corrupt the second call's view of the
// original slice.
//
// The fix is a fresh `make([]*skill.Skill, 0, len(allSkills))` allocation
// inside FilterSkillsByProfile, so this test invokes the function twice
// with overlapping-but-different filters and verifies the second call
// observes the original input — not the in-place-mutated leftovers from
// the first call.
func TestFilterSkillsByProfileDoesNotMutateCaller(t *testing.T) {
	all := []*skill.Skill{
		{Frontmatter: skill.Frontmatter{ID: "a"}},
		{Frontmatter: skill.Frontmatter{ID: "b"}},
		{Frontmatter: skill.Frontmatter{ID: "c"}},
		{Frontmatter: skill.Frontmatter{ID: "d"}},
		{Frontmatter: skill.Frontmatter{ID: "e"}},
	}

	// Snapshot the IDs as the caller would see them BEFORE filtering.
	wantOriginal := []string{"a", "b", "c", "d", "e"}

	profileAC := &Profile{Skills: []string{"a", "c"}}
	first := FilterSkillsByProfile(all, profileAC)
	if got := ids(first); !equalStringSlices(got, []string{"a", "c"}) {
		t.Fatalf("first call: want [a c], got %v", got)
	}

	// Critical assertion: the input slice's view of its elements must
	// be UNCHANGED. The pre-fix code mutated `all`'s backing array
	// during the first call, so `b` (at index 1) would have been
	// overwritten with `c` and `e` (at index 4) would have retained a
	// stale value. Either way, `all`'s IDs would no longer equal
	// wantOriginal.
	if got := ids(all); !equalStringSlices(got, wantOriginal) {
		t.Fatalf("input slice mutated by first call: want %v, got %v", wantOriginal, got)
	}

	// Second call on the same input with a different (overlapping)
	// filter must succeed independently. On the pre-fix code, this
	// second call sees the corrupted backing array and returns the
	// wrong result.
	profileABD := &Profile{Skills: []string{"a", "b", "d"}}
	second := FilterSkillsByProfile(all, profileABD)
	if got := ids(second); !equalStringSlices(got, []string{"a", "b", "d"}) {
		t.Fatalf("second call: want [a b d], got %v (input corrupted by first call?)", got)
	}

	// Final sanity: input is STILL unchanged after the second call too.
	if got := ids(all); !equalStringSlices(got, wantOriginal) {
		t.Fatalf("input slice mutated by second call: want %v, got %v", wantOriginal, got)
	}
}

// TestFilterSkillsByProfileEmptyProfilePassesThrough confirms the
// passthrough contract: a nil profile or a profile with no Skills list
// returns the input unchanged.
func TestFilterSkillsByProfileEmptyProfilePassesThrough(t *testing.T) {
	all := []*skill.Skill{
		{Frontmatter: skill.Frontmatter{ID: "a"}},
		{Frontmatter: skill.Frontmatter{ID: "b"}},
	}
	if got := FilterSkillsByProfile(all, nil); len(got) != 2 {
		t.Errorf("nil profile: want 2 skills, got %d", len(got))
	}
	if got := FilterSkillsByProfile(all, &Profile{}); len(got) != 2 {
		t.Errorf("empty profile.Skills: want 2 skills, got %d", len(got))
	}
}

func ids(skills []*skill.Skill) []string {
	out := make([]string, 0, len(skills))
	for _, s := range skills {
		out = append(out, s.Frontmatter.ID)
	}
	return out
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
