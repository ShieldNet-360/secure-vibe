package llm

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

const defaultOpenAIBase = "https://api.openai.com/v1"

// openaiProvider talks to the OpenAI Chat Completions API, which is also the de
// facto interface for Ollama, vLLM, LM Studio, OpenRouter, Azure OpenAI, and
// most local runtimes — hence it doubles as the "openai-compatible" provider
// with a custom base URL.
type openaiProvider struct {
	client *http.Client
	base   string
	model  string
	apiKey string
}

func newOpenAI(cfg Config, client *http.Client, base, defModel string) *openaiProvider {
	return &openaiProvider{
		client: client,
		base:   strings.TrimRight(base, "/"),
		model:  pick(cfg.Model, defModel),
		apiKey: cfg.APIKey,
	}
}

func (p *openaiProvider) Name() string { return "openai/" + p.model }

type openaiRequest struct {
	Model       string          `json:"model"`
	MaxTokens   int             `json:"max_tokens"`
	Temperature float64         `json:"temperature"`
	Messages    []openaiMessage `json:"messages"`
}

type openaiMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openaiResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (p *openaiProvider) Complete(ctx context.Context, req Request) (string, error) {
	msgs := make([]openaiMessage, 0, 2)
	if strings.TrimSpace(req.System) != "" {
		msgs = append(msgs, openaiMessage{Role: "system", Content: req.System})
	}
	msgs = append(msgs, openaiMessage{Role: "user", Content: req.User})
	body := openaiRequest{
		Model:       p.model,
		MaxTokens:   req.maxTokens(),
		Temperature: req.Temperature,
		Messages:    msgs,
	}
	headers := map[string]string{}
	if strings.TrimSpace(p.apiKey) != "" {
		headers["Authorization"] = "Bearer " + p.apiKey
	}
	var out openaiResponse
	if err := postJSON(ctx, p.client, p.base+"/chat/completions", headers, body, &out); err != nil {
		return "", err
	}
	if out.Error != nil {
		return "", fmt.Errorf("llm: openai: %s", out.Error.Message)
	}
	if len(out.Choices) == 0 {
		return "", fmt.Errorf("llm: openai: empty response")
	}
	return out.Choices[0].Message.Content, nil
}
