package token

import (
	"strings"
	"testing"
)

func TestCountKnownString(t *testing.T) {
	// "hello world" is two cl100k_base tokens.
	c, err := Count("hello world")
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if c.OpenAI != 2 {
		t.Errorf("openai count = %d, want 2", c.OpenAI)
	}
}

func TestCountClaudeMultiplier(t *testing.T) {
	s := strings.Repeat("the quick brown fox jumps over the lazy dog ", 25)
	c, err := Count(s)
	if err != nil {
		t.Fatal(err)
	}
	want := int(float64(c.OpenAI)*ClaudeMultiplier + 0.5)
	if c.Claude != want {
		t.Errorf("claude count = %d, want %d (openai=%d * %.2f)", c.Claude, want, c.OpenAI, ClaudeMultiplier)
	}
	if c.Claude <= c.OpenAI {
		t.Errorf("claude estimate (%d) should exceed openai count (%d)", c.Claude, c.OpenAI)
	}
}

func TestEnforceBudgetWithinLimit(t *testing.T) {
	c, err := EnforceBudget("test", "hello world", 100)
	if err != nil {
		t.Fatalf("budget should pass: %v", err)
	}
	if c.OpenAI == 0 {
		t.Errorf("expected non-zero count")
	}
}

func TestEnforceBudgetExceedsLimit(t *testing.T) {
	big := strings.Repeat("the quick brown fox jumps over the lazy dog ", 200)
	_, err := EnforceBudget("test", big, 50)
	if err == nil {
		t.Fatalf("budget should fail")
	}
	if !strings.Contains(err.Error(), "exceeds token budget") {
		t.Errorf("error should mention budget, got %v", err)
	}
}

func TestEnforceBudgetDisabled(t *testing.T) {
	c, err := EnforceBudget("test", "anything", 0)
	if err != nil {
		t.Fatalf("zero limit should disable check: %v", err)
	}
	if c.OpenAI == 0 {
		t.Errorf("expected non-zero count")
	}
}
