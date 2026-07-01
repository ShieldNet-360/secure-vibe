// Package token counts tokens for compiled skill output.
//
// OpenAI-family counts use the `cl100k_base` encoding via tiktoken-go and are
// authoritative. Claude-family counts apply a conservative 1.3x multiplier on
// top of the OpenAI count; this consistently overestimates rather than
// underestimates so budget checks remain safe.
package token

import (
	"fmt"
	"sync"

	"github.com/pkoukk/tiktoken-go"
)

// ClaudeMultiplier is the safety multiplier applied to cl100k_base counts to
// estimate Claude-family token consumption.
const ClaudeMultiplier = 1.3

// Counts captures both vendor-family token counts for the same input.
type Counts struct {
	OpenAI int
	Claude int
}

var (
	encOnce sync.Once
	enc     *tiktoken.Tiktoken
	encErr  error
)

func encoder() (*tiktoken.Tiktoken, error) {
	encOnce.Do(func() {
		enc, encErr = tiktoken.GetEncoding("cl100k_base")
	})
	return enc, encErr
}

// Count returns OpenAI + Claude token estimates for s.
func Count(s string) (Counts, error) {
	e, err := encoder()
	if err != nil {
		return Counts{}, fmt.Errorf("load cl100k_base: %w", err)
	}
	ids := e.Encode(s, nil, nil)
	openai := len(ids)
	claude := int(float64(openai)*ClaudeMultiplier + 0.5)
	return Counts{OpenAI: openai, Claude: claude}, nil
}

// MustCount panics if Count errors. Convenient for hot paths that have already
// validated the encoder once.
func MustCount(s string) Counts {
	c, err := Count(s)
	if err != nil {
		panic(err)
	}
	return c
}

// EnforceBudget compares the worst-case (Claude) token count for s against
// limit. Returns the counts and a non-nil error when the budget is exceeded.
// A non-positive limit disables the check.
func EnforceBudget(label string, s string, limit int) (Counts, error) {
	c, err := Count(s)
	if err != nil {
		return c, err
	}
	if limit <= 0 {
		return c, nil
	}
	if c.Claude > limit {
		return c, fmt.Errorf("%s exceeds token budget: %d > %d (claude estimate)", label, c.Claude, limit)
	}
	return c, nil
}
