package llm

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

const (
	defaultAnthropicBase   = "https://api.anthropic.com/v1"
	anthropicVersionHeader = "2023-06-01"
)

// anthropicProvider talks to the Anthropic Messages API.
type anthropicProvider struct {
	client *http.Client
	base   string
	model  string
	apiKey string
}

func newAnthropic(cfg Config, client *http.Client) *anthropicProvider {
	return &anthropicProvider{
		client: client,
		base:   strings.TrimRight(pick(cfg.BaseURL, defaultAnthropicBase), "/"),
		model:  pick(cfg.Model, defaultAnthropicModel),
		apiKey: cfg.APIKey,
	}
}

func (p *anthropicProvider) Name() string { return "anthropic/" + p.model }

type anthropicRequest struct {
	Model       string             `json:"model"`
	MaxTokens   int                `json:"max_tokens"`
	Temperature float64            `json:"temperature"`
	System      string             `json:"system,omitempty"`
	Messages    []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (p *anthropicProvider) Complete(ctx context.Context, req Request) (string, error) {
	body := anthropicRequest{
		Model:       p.model,
		MaxTokens:   req.maxTokens(),
		Temperature: req.Temperature,
		System:      req.System,
		Messages:    []anthropicMessage{{Role: "user", Content: req.User}},
	}
	headers := map[string]string{
		"x-api-key":         p.apiKey,
		"anthropic-version": anthropicVersionHeader,
	}
	var out anthropicResponse
	if err := postJSON(ctx, p.client, p.base+"/messages", headers, body, &out); err != nil {
		return "", err
	}
	if out.Error != nil {
		return "", fmt.Errorf("llm: anthropic: %s", out.Error.Message)
	}
	var sb strings.Builder
	for _, c := range out.Content {
		if c.Type == "text" {
			sb.WriteString(c.Text)
		}
	}
	return sb.String(), nil
}
