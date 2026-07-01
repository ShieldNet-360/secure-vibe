package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultOSVBaseURL is the public OSV.dev API. Tests override this with
// httptest.Server.URL so they never hit the network.
const DefaultOSVBaseURL = "https://api.osv.dev"

// DefaultOSVUserAgent is sent on every outbound request. It identifies
// secure-vibe mcp to OSV.dev operators and points at the upstream repo for
// abuse reporting. Tests can override via WithUserAgent.
const DefaultOSVUserAgent = "secure-vibe/1.0 (+https://github.com/shieldnet-360/secure-vibe)"

// OSVClient queries vulnerability records from a remote OSV API.
//
// The interface is intentionally narrow: every method maps to one
// existing OSV.dev endpoint, returning the same OSVAdvisory shape the
// local cache emits so the rest of the codebase does not care where
// the data came from.
//
// Implementations must be safe to use concurrently — the HTTP-backed
// client below is, because *http.Client is goroutine-safe and the
// struct has no shared mutable state.
type OSVClient interface {
	// Query returns advisories for a single package+version+ecosystem
	// triple. An empty version means "any version" (OSV.dev's vector
	// query without a version field). When the ecosystem is not on
	// osv.dev (e.g. github-actions, docker), Query returns nil, nil
	// rather than an error so callers can fall back to local data.
	Query(ctx context.Context, pkg, version, ecosystem string) ([]OSVAdvisory, error)
}

// httpOSVClient is the production OSVClient backed by *http.Client.
type httpOSVClient struct {
	httpClient *http.Client
	baseURL    string
	userAgent  string
}

// OSVClientOption configures an httpOSVClient.
type OSVClientOption func(*httpOSVClient)

// WithBaseURL overrides the OSV API root. Used by tests with
// httptest.Server.URL; production callers should accept the default.
func WithBaseURL(url string) OSVClientOption {
	return func(c *httpOSVClient) { c.baseURL = strings.TrimRight(url, "/") }
}

// WithUserAgent overrides the User-Agent header.
func WithUserAgent(ua string) OSVClientOption {
	return func(c *httpOSVClient) { c.userAgent = ua }
}

// WithHTTPClient overrides the *http.Client. Tests use this to inject
// a client with a short timeout or a custom transport.
func WithHTTPClient(client *http.Client) OSVClientOption {
	return func(c *httpOSVClient) { c.httpClient = client }
}

// NewOSVClient returns an OSV.dev HTTP client with sensible defaults
// (10s timeout, public api.osv.dev base URL). Options override
// individual fields for tests or custom deployments.
func NewOSVClient(opts ...OSVClientOption) OSVClient {
	c := &httpOSVClient{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		baseURL:    DefaultOSVBaseURL,
		userAgent:  DefaultOSVUserAgent,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// osvEcosystemName translates secure-vibe's internal ecosystem ids
// to the canonical OSV.dev ecosystem names. OSV uses TitleCase with
// some idiosyncratic spellings (PyPI, RubyGems, crates.io, SwiftURL,
// Packagist for PHP/composer).
//
// An empty string return means "OSV.dev does not catalog this
// ecosystem" — callers should treat that as a zero-result hit, not an
// error, so behaviour matches the local cache (which also has no
// github-actions / docker advisory data on the OSV side).
//
// Reference: https://google.github.io/osv.dev/data/#ecosystems
func osvEcosystemName(eco string) string {
	switch strings.ToLower(strings.TrimSpace(eco)) {
	case "npm":
		return "npm"
	case "pypi":
		return "PyPI"
	case "crates":
		return "crates.io"
	case "go":
		return "Go"
	case "rubygems":
		return "RubyGems"
	case "maven":
		return "Maven"
	case "nuget":
		return "NuGet"
	case "composer":
		return "Packagist"
	case "pub":
		return "Pub"
	case "swift":
		return "SwiftURL"
	}
	return ""
}

// osvQueryRequest is the body of POST /v1/query.
type osvQueryRequest struct {
	Package osvPackageRef `json:"package"`
	Version string        `json:"version,omitempty"`
}

type osvPackageRef struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// osvVuln captures the subset of an OSV record we project onto
// OSVAdvisory. The full schema is much richer (affected, references,
// credits, …); we deliberately do not decode those fields so changes
// upstream do not break us. See https://ossf.github.io/osv-schema/.
type osvVuln struct {
	ID        string             `json:"id"`
	Summary   string             `json:"summary"`
	Details   string             `json:"details"`
	Aliases   []string           `json:"aliases"`
	Published string             `json:"published"`
	Modified  string             `json:"modified"`
	Severity  []osvSeverityScore `json:"severity"`
	// DatabaseSpecific carries GHSA's `severity: HIGH` qualitative band,
	// which we prefer over CVSS-vector parsing when present (it is the
	// GitHub-editor-canonical value, sometimes overriding the upstream
	// numeric score).
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

type osvSeverityScore struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvQueryResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

// Query implements OSVClient.Query.
//
// On OK, the response is decoded and each vuln projected onto an
// OSVAdvisory whose fields mirror the local cache so downstream code
// (severity bucketing, MCP tool output) is source-agnostic.
//
// Non-200 responses return an error containing the status code and up
// to 4 KB of response body for diagnostics. Empty `vulns` is not an
// error — it means "no advisories for this triple," and the function
// returns (nil, nil).
func (c *httpOSVClient) Query(ctx context.Context, pkg, version, ecosystem string) ([]OSVAdvisory, error) {
	if strings.TrimSpace(pkg) == "" {
		return nil, fmt.Errorf("osv query: package is required")
	}
	osvEco := osvEcosystemName(ecosystem)
	if osvEco == "" {
		// OSV.dev doesn't catalog this ecosystem. Treat as zero results
		// rather than an error so the dispatcher can transparently fall
		// back to local data (or just return empty) without surfacing
		// a confusing protocol-shaped error.
		return nil, nil
	}
	body, err := json.Marshal(osvQueryRequest{
		Package: osvPackageRef{Name: pkg, Ecosystem: osvEco},
		Version: strings.TrimSpace(version),
	})
	if err != nil {
		return nil, fmt.Errorf("osv query: marshal body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/query", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("osv query: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv query: do request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("osv query: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	var out osvQueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("osv query: decode body: %w", err)
	}
	advs := make([]OSVAdvisory, 0, len(out.Vulns))
	for _, v := range out.Vulns {
		advs = append(advs, OSVAdvisory{
			ID:        v.ID,
			Package:   pkg,
			Ecosystem: ecosystem, // keep caller's id (npm, not OSV's "npm" caps)
			Aliases:   v.Aliases,
			Summary:   osvSummary(v),
			Published: v.Published,
			Modified:  v.Modified,
			Reference: "https://osv.dev/vulnerability/" + v.ID,
			Severity:  osvVulnSeverity(v),
		})
	}
	return advs, nil
}

// osvSummary picks the most useful human-readable description: prefer
// the OSV one-liner `summary`, falling back to a truncated `details`
// (which can be Markdown). 240 chars matches our local cache style.
func osvSummary(v osvVuln) string {
	if s := strings.TrimSpace(v.Summary); s != "" {
		return s
	}
	d := strings.TrimSpace(v.Details)
	if len(d) > 240 {
		d = d[:237] + "..."
	}
	return d
}

// osvVulnSeverity buckets a vuln into critical/high/medium/low using
// the same precedence the on-disk loader uses (resolveOSVSeverity in
// osv_severity.go): GHSA database_specific.severity first, then the
// highest CVSS_V3/V2 score, then "" (callers default to "medium").
//
// We deliberately reuse the existing helpers rather than re-implement
// the CVSS formula, so behaviour stays identical regardless of whether
// an advisory was fetched live or read from the bundled cache.
func osvVulnSeverity(v osvVuln) string {
	if sev := normaliseSeverity(v.DatabaseSpecific.Severity); sev != "" {
		return sev
	}
	var best float64
	for _, s := range v.Severity {
		if score := scoreFromCVSS(s.Type, s.Score); score > best {
			best = score
		}
	}
	if best > 0 {
		return bucketFromScore(best)
	}
	return ""
}
