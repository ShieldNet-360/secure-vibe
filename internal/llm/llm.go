// Package llm is SecureVibe's model-pluggable reasoning adapter. It is the
// bring-your-own-model layer that keeps `secure-vibe audit`'s LLM lanes
// (semantic sweep, adversarial verify) provider-agnostic: the deterministic
// core never touches it, and when no provider is configured the audit runs
// offline exactly as before. SecureVibe ships no key and no model — the user
// points this at their own endpoint via SECURE_VIBE_MODEL_* env vars, so the
// tool stays keyless while working identically across Claude, Codex, Gemini,
// and any OpenAI-compatible runtime (Ollama, vLLM, OpenRouter, Azure, …).
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// ErrNoProvider is returned by New when no provider is configured. Callers treat
// it as "run the deterministic lanes only", not as a fatal error.
var ErrNoProvider = fmt.Errorf("llm: no model provider configured")

// defaultTimeout bounds a single completion. Audits issue many calls; a slow or
// hung endpoint must not wedge the run.
const defaultTimeout = 90 * time.Second

// Per-provider default model. Overridable with SECURE_VIBE_MODEL. These are
// starting points, not guarantees — the user's account/endpoint decides what is
// actually available.
const (
	defaultAnthropicModel = "claude-sonnet-5"
	defaultOpenAIModel    = "gpt-4o"
	defaultGeminiModel    = "gemini-2.0-flash"
)

// Config selects and authenticates a provider. It is populated from flags or
// FromEnv; an empty Provider means "disabled".
type Config struct {
	Provider string // anthropic | openai | gemini | openai-compatible
	Model    string // provider model id; empty => a per-provider default
	APIKey   string // bring-your-own; never shipped or logged
	BaseURL  string // required for openai-compatible; overrides the default host otherwise
}

// FromEnv reads the SECURE_VIBE_MODEL_* environment. All fields are optional; an
// empty SECURE_VIBE_MODEL_PROVIDER yields a disabled Config.
func FromEnv() Config {
	return Config{
		Provider: strings.TrimSpace(os.Getenv("SECURE_VIBE_MODEL_PROVIDER")),
		Model:    strings.TrimSpace(os.Getenv("SECURE_VIBE_MODEL")),
		APIKey:   strings.TrimSpace(os.Getenv("SECURE_VIBE_MODEL_API_KEY")),
		BaseURL:  strings.TrimSpace(os.Getenv("SECURE_VIBE_MODEL_BASE_URL")),
	}
}

// Enabled reports whether a provider is configured.
func (c Config) Enabled() bool { return strings.TrimSpace(c.Provider) != "" }

// Request is one completion: a system instruction plus a user message. Audit
// prompts always ask for JSON, so callers keep Temperature low.
type Request struct {
	System      string
	User        string
	MaxTokens   int
	Temperature float64
}

func (r Request) maxTokens() int {
	if r.MaxTokens > 0 {
		return r.MaxTokens
	}
	return 2048
}

// Provider is a single-shot text completion backend.
type Provider interface {
	Name() string
	Complete(ctx context.Context, req Request) (string, error)
}

// New builds a Provider from cfg. Returns ErrNoProvider when disabled so callers
// can branch to the deterministic-only path without special-casing.
func New(cfg Config) (Provider, error) {
	if !cfg.Enabled() {
		return nil, ErrNoProvider
	}
	if strings.TrimSpace(cfg.APIKey) == "" && !isLocalBaseURL(cfg.BaseURL) {
		return nil, fmt.Errorf("llm: SECURE_VIBE_MODEL_API_KEY is required for provider %q", cfg.Provider)
	}
	client := &http.Client{Timeout: defaultTimeout}
	switch strings.ToLower(strings.TrimSpace(cfg.Provider)) {
	case "anthropic", "claude":
		return newAnthropic(cfg, client), nil
	case "openai":
		return newOpenAI(cfg, client, defaultOpenAIBase, defaultOpenAIModel), nil
	case "openai-compatible", "compatible", "openai_compatible":
		if strings.TrimSpace(cfg.BaseURL) == "" {
			return nil, fmt.Errorf("llm: SECURE_VIBE_MODEL_BASE_URL is required for the openai-compatible provider")
		}
		return newOpenAI(cfg, client, strings.TrimRight(cfg.BaseURL, "/"), defaultOpenAIModel), nil
	case "gemini", "google":
		return newGemini(cfg, client), nil
	default:
		return nil, fmt.Errorf("llm: unknown provider %q (want anthropic | openai | gemini | openai-compatible)", cfg.Provider)
	}
}

// isLocalBaseURL lets local openai-compatible runtimes (Ollama, LM Studio, vLLM)
// run without an API key.
func isLocalBaseURL(base string) bool {
	b := strings.ToLower(base)
	return strings.Contains(b, "localhost") || strings.Contains(b, "127.0.0.1") || strings.Contains(b, "0.0.0.0")
}

func pick(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// postJSON marshals body, POSTs it with the given headers, and decodes the JSON
// response into out. It centralises transport + error handling so each adapter
// only owns request shaping and response extraction.
func postJSON(ctx context.Context, client *http.Client, url string, headers map[string]string, body any, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("llm: encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("llm: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("llm: request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("llm: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("llm: %s returned %d: %s", url, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("llm: decode response: %w", err)
	}
	return nil
}
