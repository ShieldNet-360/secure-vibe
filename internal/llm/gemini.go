package llm

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const defaultGeminiBase = "https://generativelanguage.googleapis.com/v1beta"

// geminiProvider talks to the Google Generative Language API (generateContent).
type geminiProvider struct {
	client *http.Client
	base   string
	model  string
	apiKey string
}

func newGemini(cfg Config, client *http.Client) *geminiProvider {
	return &geminiProvider{
		client: client,
		base:   strings.TrimRight(pick(cfg.BaseURL, defaultGeminiBase), "/"),
		model:  pick(cfg.Model, defaultGeminiModel),
		apiKey: cfg.APIKey,
	}
}

func (p *geminiProvider) Name() string { return "gemini/" + p.model }

type geminiRequest struct {
	SystemInstruction *geminiContent  `json:"systemInstruction,omitempty"`
	Contents          []geminiContent `json:"contents"`
	GenerationConfig  geminiGenConfig `json:"generationConfig"`
}

type geminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiGenConfig struct {
	MaxOutputTokens int     `json:"maxOutputTokens"`
	Temperature     float64 `json:"temperature"`
}

type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []geminiPart `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (p *geminiProvider) Complete(ctx context.Context, req Request) (string, error) {
	body := geminiRequest{
		Contents: []geminiContent{{
			Role:  "user",
			Parts: []geminiPart{{Text: req.User}},
		}},
		GenerationConfig: geminiGenConfig{
			MaxOutputTokens: req.maxTokens(),
			Temperature:     req.Temperature,
		},
	}
	if strings.TrimSpace(req.System) != "" {
		body.SystemInstruction = &geminiContent{Parts: []geminiPart{{Text: req.System}}}
	}
	// The API key rides as a query parameter, not a header.
	endpoint := fmt.Sprintf("%s/models/%s:generateContent?key=%s",
		p.base, url.PathEscape(p.model), url.QueryEscape(p.apiKey))
	var out geminiResponse
	if err := postJSON(ctx, p.client, endpoint, nil, body, &out); err != nil {
		return "", err
	}
	if out.Error != nil {
		return "", fmt.Errorf("llm: gemini: %s", out.Error.Message)
	}
	if len(out.Candidates) == 0 {
		return "", fmt.Errorf("llm: gemini: empty response")
	}
	var sb strings.Builder
	for _, part := range out.Candidates[0].Content.Parts {
		sb.WriteString(part.Text)
	}
	return sb.String(), nil
}
