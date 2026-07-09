package probe

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	maxBodyBytes   = 64 << 10 // response body cap returned to the agent
	defaultTimeout = 8 * time.Second
	maxTimeout     = 30 * time.Second
)

// Request is one probe the agent wants to send. The agent crafts everything; the
// scope decides whether it fires.
type Request struct {
	URL             string            `json:"url"`
	Method          string            `json:"method"`
	Headers         map[string]string `json:"headers,omitempty"`
	Body            string            `json:"body,omitempty"`
	FollowRedirects bool              `json:"follow_redirects,omitempty"`
	TimeoutMs       int               `json:"timeout_ms,omitempty"`
}

// Response is what the probe observed — or, when out of scope, the plan it would
// have sent (Sent=false).
type Response struct {
	Sent      bool                `json:"sent"`
	Note      string              `json:"note,omitempty"`
	Plan      string              `json:"plan"`
	Status    int                 `json:"status,omitempty"`
	Headers   map[string][]string `json:"headers,omitempty"`
	Body      string              `json:"body,omitempty"`
	Truncated bool                `json:"truncated,omitempty"`
	ElapsedMs int64               `json:"elapsed_ms,omitempty"`
	FinalURL  string              `json:"final_url,omitempty"`
}

// HTTPProbe sends req to an authorized target and returns what it observed. The
// two safety rails live here:
//
//	Rail 1 (dry-run default) — if scope is unconfigured, nothing is sent; the
//	   Response carries only the Plan so the agent can see what it *would* send.
//	Rail 2 (scope gate) — even configured, a request fires only if the target host
//	   is in scope. Operator-configured auth headers (scope file) are merged in.
//
// An optional client is injected in tests; nil uses a fresh client honouring the
// redirect + timeout policy.
func HTTPProbe(ctx context.Context, scope *Scope, req Request, client *http.Client) (Response, error) {
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}
	plan := fmt.Sprintf("%s %s", method, req.URL)
	if req.Body != "" {
		plan += fmt.Sprintf(" (body %d bytes)", len(req.Body))
	}

	if scope == nil || !scope.Configured() {
		return Response{Sent: false, Plan: plan, Note: "dry-run: no verify scope configured (set SECURE_VIBE_VERIFY_SCOPE); nothing sent"}, nil
	}
	if !scope.Allows(req.URL) {
		return Response{Sent: false, Plan: plan, Note: "dry-run: target not in the authorized scope; nothing sent"}, nil
	}

	timeout := defaultTimeout
	if req.TimeoutMs > 0 {
		timeout = time.Duration(req.TimeoutMs) * time.Millisecond
		if timeout > maxTimeout {
			timeout = maxTimeout
		}
	}
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	if !req.FollowRedirects {
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}

	var bodyReader io.Reader
	if req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, bodyReader)
	if err != nil {
		return Response{Sent: false, Plan: plan}, fmt.Errorf("build request: %w", err)
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}
	for k, v := range scope.Headers(req.URL) { // operator-resolved auth wins
		httpReq.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := client.Do(httpReq)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		return Response{Sent: true, Plan: plan, ElapsedMs: elapsed, Note: "request error: " + err.Error()}, nil
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	truncated := len(raw) > maxBodyBytes
	if truncated {
		raw = raw[:maxBodyBytes]
	}
	return Response{
		Sent:      true,
		Plan:      plan,
		Status:    resp.StatusCode,
		Headers:   resp.Header,
		Body:      string(raw),
		Truncated: truncated,
		ElapsedMs: elapsed,
		FinalURL:  resp.Request.URL.String(),
	}, nil
}
