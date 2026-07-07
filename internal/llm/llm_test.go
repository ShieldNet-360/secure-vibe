package llm

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

// roundTripFunc adapts a function to http.RoundTripper so tests can stub the
// transport and assert on the outgoing request without any network.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func jsonResp(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func TestFromEnv(t *testing.T) {
	t.Setenv("SECURE_VIBE_MODEL_PROVIDER", "openai")
	t.Setenv("SECURE_VIBE_MODEL", "gpt-x")
	t.Setenv("SECURE_VIBE_MODEL_API_KEY", "sk-1")
	t.Setenv("SECURE_VIBE_MODEL_BASE_URL", "https://example/v1")
	cfg := FromEnv()
	if cfg.Provider != "openai" || cfg.Model != "gpt-x" || cfg.APIKey != "sk-1" || cfg.BaseURL != "https://example/v1" {
		t.Fatalf("FromEnv = %+v", cfg)
	}
	if !cfg.Enabled() {
		t.Fatal("Enabled() = false, want true")
	}
}

func TestNewDispatch(t *testing.T) {
	if _, err := New(Config{}); err != ErrNoProvider {
		t.Errorf("New(empty) err = %v, want ErrNoProvider", err)
	}
	if _, err := New(Config{Provider: "anthropic"}); err == nil {
		t.Error("New(anthropic, no key) should require an API key")
	}
	if _, err := New(Config{Provider: "openai-compatible", APIKey: "k"}); err == nil {
		t.Error("openai-compatible without base URL should error")
	}
	if _, err := New(Config{Provider: "bogus", APIKey: "k"}); err == nil {
		t.Error("unknown provider should error")
	}

	cases := map[string]string{
		"anthropic": "anthropic/",
		"openai":    "openai/",
		"gemini":    "gemini/",
	}
	for provider, prefix := range cases {
		p, err := New(Config{Provider: provider, APIKey: "k"})
		if err != nil {
			t.Fatalf("New(%s) err = %v", provider, err)
		}
		if !strings.HasPrefix(p.Name(), prefix) {
			t.Errorf("New(%s).Name() = %q, want prefix %q", provider, p.Name(), prefix)
		}
	}

	// A local openai-compatible endpoint needs no key.
	if _, err := New(Config{Provider: "openai-compatible", BaseURL: "http://localhost:11434/v1"}); err != nil {
		t.Errorf("local openai-compatible without key err = %v", err)
	}
}

func TestAnthropicComplete(t *testing.T) {
	var gotURL, gotKey, gotVer, gotBody string
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotURL = r.URL.String()
		gotKey = r.Header.Get("x-api-key")
		gotVer = r.Header.Get("anthropic-version")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		return jsonResp(200, `{"content":[{"type":"text","text":"hello "},{"type":"text","text":"world"}]}`), nil
	})}
	p := newAnthropic(Config{APIKey: "sk-test", Model: "claude-x"}, client)
	out, err := p.Complete(context.Background(), Request{System: "sys", User: "hi"})
	if err != nil {
		t.Fatal(err)
	}
	if out != "hello world" {
		t.Errorf("out = %q, want %q", out, "hello world")
	}
	if !strings.HasSuffix(gotURL, "/messages") {
		t.Errorf("url = %q", gotURL)
	}
	if gotKey != "sk-test" {
		t.Errorf("x-api-key = %q", gotKey)
	}
	if gotVer != anthropicVersionHeader {
		t.Errorf("anthropic-version = %q", gotVer)
	}
	if !strings.Contains(gotBody, `"model":"claude-x"`) || !strings.Contains(gotBody, `"system":"sys"`) {
		t.Errorf("body = %s", gotBody)
	}
}

func TestOpenAIComplete(t *testing.T) {
	var gotURL, gotAuth, gotBody string
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotURL = r.URL.String()
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		return jsonResp(200, `{"choices":[{"message":{"content":"ok"}}]}`), nil
	})}
	p := newOpenAI(Config{APIKey: "sk-oai", Model: "gpt-x"}, client, defaultOpenAIBase, defaultOpenAIModel)
	out, err := p.Complete(context.Background(), Request{System: "sys", User: "hi"})
	if err != nil {
		t.Fatal(err)
	}
	if out != "ok" {
		t.Errorf("out = %q", out)
	}
	if !strings.HasSuffix(gotURL, "/chat/completions") {
		t.Errorf("url = %q", gotURL)
	}
	if gotAuth != "Bearer sk-oai" {
		t.Errorf("auth = %q", gotAuth)
	}
	if !strings.Contains(gotBody, `"role":"system"`) || !strings.Contains(gotBody, `"role":"user"`) {
		t.Errorf("body = %s", gotBody)
	}
}

func TestGeminiComplete(t *testing.T) {
	var gotURL, gotBody string
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotURL = r.URL.String()
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		return jsonResp(200, `{"candidates":[{"content":{"parts":[{"text":"gem"},{"text":"ini"}]}}]}`), nil
	})}
	p := newGemini(Config{APIKey: "k-goog", Model: "gemini-x"}, client)
	out, err := p.Complete(context.Background(), Request{System: "sys", User: "hi"})
	if err != nil {
		t.Fatal(err)
	}
	if out != "gemini" {
		t.Errorf("out = %q", out)
	}
	if !strings.Contains(gotURL, "/models/gemini-x:generateContent") || !strings.Contains(gotURL, "key=k-goog") {
		t.Errorf("url = %q", gotURL)
	}
	if !strings.Contains(gotBody, `"systemInstruction"`) {
		t.Errorf("body missing systemInstruction: %s", gotBody)
	}
}

func TestCompleteHTTPError(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return jsonResp(429, `{"error":{"message":"rate limited"}}`), nil
	})}
	p := newOpenAI(Config{APIKey: "k"}, client, defaultOpenAIBase, defaultOpenAIModel)
	if _, err := p.Complete(context.Background(), Request{User: "hi"}); err == nil {
		t.Fatal("expected error on 429")
	}
}
