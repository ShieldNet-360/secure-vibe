package proposal

import (
	"path/filepath"
	"testing"
	"time"
)

var fixedTime = time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)

func tmpLog(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), RelPath)
}

func TestRecordValidatesRequiredFields(t *testing.T) {
	path := tmpLog(t)
	cases := []Proposal{
		{Kind: KindMissing, Claim: "c", Evidence: "e"},           // no skill_id
		{SkillID: "s", Kind: "bogus", Claim: "c", Evidence: "e"}, // bad kind
		{SkillID: "s", Kind: KindWrong, Evidence: "e"},           // no claim
		{SkillID: "s", Kind: KindWrong, Claim: "c"},              // no evidence
	}
	for i, p := range cases {
		if _, _, err := Record(path, p, fixedTime); err == nil {
			t.Errorf("case %d: expected validation error, got nil", i)
		}
	}
}

func TestRecordAppendsAndIsIdempotent(t *testing.T) {
	path := tmpLog(t)
	p := Proposal{
		SkillID:  "xss-prevention",
		Kind:     KindMissing,
		Claim:    "Trusted Types blocks DOM XSS sinks in Chromium.",
		Evidence: "https://web.dev/trusted-types",
	}
	stored, isNew, err := Record(path, p, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	if !isNew {
		t.Fatal("first record should be new")
	}
	if stored.ID == "" || stored.Recorded != "2026-07-09" || stored.Source != "agent" {
		t.Fatalf("normalisation off: %+v", stored)
	}

	// Same (skill,kind,claim) re-recorded — even with different evidence
	// wording — dedups on the content id.
	p2 := p
	p2.Evidence = "reworded but same underlying claim"
	again, isNew2, err := Record(path, p2, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	if isNew2 {
		t.Error("re-recording the same claim should not be new")
	}
	if again.ID != stored.ID {
		t.Errorf("dedup id mismatch: %s vs %s", again.ID, stored.ID)
	}

	all, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 proposal after idempotent re-record, got %d", len(all))
	}
}

func TestGetByIDAndPrefix(t *testing.T) {
	path := tmpLog(t)
	a, _, _ := Record(path, Proposal{SkillID: "s1", Kind: KindWrong, Claim: "a", Evidence: "e"}, fixedTime)
	_, _, _ = Record(path, Proposal{SkillID: "s2", Kind: KindOutdated, Claim: "b", Evidence: "e"}, fixedTime)

	got, err := Get(path, a.ID)
	if err != nil || got == nil || got.ID != a.ID {
		t.Fatalf("get by full id failed: %v %+v", err, got)
	}
	// Full-prefix (whole id) resolves; a missing id yields (nil,nil).
	miss, err := Get(path, "sp-doesnotexist")
	if err != nil || miss != nil {
		t.Fatalf("expected clean miss, got %v %+v", err, miss)
	}
}

func TestLoadMissingFileIsEmpty(t *testing.T) {
	all, err := Load(tmpLog(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 0 {
		t.Fatalf("expected empty, got %d", len(all))
	}
}

func TestPathForEnvOverride(t *testing.T) {
	t.Setenv(EnvFile, "/tmp/shared/inbox.jsonl")
	got, err := PathFor("/ignored")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/tmp/shared/inbox.jsonl" {
		t.Fatalf("env override ignored: %s", got)
	}
}
