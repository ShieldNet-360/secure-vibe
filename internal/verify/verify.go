// Package verify runs active DAST probes that CONFIRM a finding produced by
// static/LLM detection against a live target — the "verify động" lane.
// Detection yields a *candidate*; a probe yields *confirmed | refuted* with
// reproducible evidence (build payload → fire → oracle → result).
//
// SAFETY — active probing sends attack payloads to a live target, so this is
// for AUTHORIZED testing only. Two rails are built into Run():
//
//	RAIL 1 (no auto-fire): nothing is sent unless Opts.Confirm is true. Default
//	        is dry-run — Run builds the attack plan and returns it, sending nothing.
//	RAIL 2 (scope gate):   even with Confirm, Run only fires when
//	        Opts.AllowTarget(target) returns true. A nil AllowTarget denies all
//	        live fires. The caller (CLI/MCP) wires this to a user-authored scope
//	        file — the LLM chooses WHAT to verify, never WHICH target/credential
//	        is in scope.
package verify

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Finding is the candidate to verify, produced by static/LLM detection.
type Finding struct {
	Type   string            // "ssrf", "sqli", "redirect", ...
	Target string            // vulnerable endpoint base URL
	Param  string            // the parameter believed injectable
	Method string            // GET/POST; default GET
	Query  map[string]string // other required params (e.g. symbol=AAPL)
	Header map[string]string // auth/session headers — resolved from scope, NOT from the LLM
}

// Result is the verdict for one probe run.
type Result struct {
	Type      string `json:"type"`
	Target    string `json:"target"`
	Param     string `json:"param"`
	Confirmed bool   `json:"confirmed"`
	Refuted   bool   `json:"refuted"`
	DryRun    bool   `json:"dry_run"`
	Payload   string `json:"payload"`            // what was (or would be) sent
	Evidence  string `json:"evidence,omitempty"` // why
}

// Opts controls a run.
type Opts struct {
	Confirm     bool                     // false ⇒ dry-run (build plan, send nothing)
	AllowTarget func(target string) bool // scope gate; nil ⇒ deny all live fires
	Timeout     time.Duration
	HTTPClient  *http.Client
}

// Plan is what a probe WOULD send. It is shown in dry-run and never fires by itself.
type Plan struct {
	Summary string
}

// Env is handed to Execute ONLY after both safety rails pass.
type Env struct {
	Ctx     context.Context
	Client  *http.Client // follows redirects by default; a probe may build its own
	Timeout time.Duration
	OOB     *OOBListener
}

// Probe is one bug-class verifier. Plan builds the payload without firing
// (dry-run); Execute fires it — possibly across multiple requests — and decides.
type Probe interface {
	Kind() string
	Plan(f Finding, oobURL string) Plan
	Execute(f Finding, env *Env) Result
}

var registry = map[string]Probe{}

// Register makes a probe available by Kind(); probes self-register in init().
func Register(p Probe) { registry[strings.ToLower(p.Kind())] = p }

// Kinds lists registered probe types.
func Kinds() []string {
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	return out
}

// Run executes build → (gated) fire → oracle → result.
func Run(ctx context.Context, f Finding, opts Opts) (Result, error) {
	p, ok := registry[strings.ToLower(f.Type)]
	if !ok {
		return Result{}, fmt.Errorf("verify: no probe registered for type %q (have: %v)", f.Type, Kinds())
	}

	oob := StartOOB()
	defer oob.Close()

	plan := p.Plan(f, oob.URL())
	base := Result{Type: f.Type, Target: f.Target, Param: f.Param, Payload: plan.Summary}

	// RAIL 1 + RAIL 2: never fire without explicit Confirm AND an in-scope target.
	if !opts.Confirm {
		base.DryRun = true
		base.Evidence = "dry-run: payload built, nothing sent (pass Confirm=true to fire)"
		return base, nil
	}
	if opts.AllowTarget == nil || !opts.AllowTarget(f.Target) {
		base.DryRun = true
		base.Evidence = "blocked by scope: target not in allow-list (no live request sent)"
		return base, nil
	}

	to := opts.Timeout
	if to == 0 {
		to = 8 * time.Second
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: to}
	}
	env := &Env{Ctx: ctx, Client: client, Timeout: to, OOB: oob}

	res := p.Execute(f, env)
	res.Type, res.Target, res.Param, res.Payload = f.Type, f.Target, f.Param, plan.Summary
	return res, nil
}

// do is a small helper probes use for a single request: send, read body (capped), close.
func (e *Env) do(req *http.Request) (*http.Response, string, error) {
	resp, err := e.Client.Do(req.WithContext(e.Ctx))
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	return resp, readBody(resp), nil
}

func readBody(resp *http.Response) string {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // cap 1 MiB
	return string(b)
}

// buildURL applies f.Query plus param=value onto f.Target.
func buildURL(f Finding, param, value string) (string, error) {
	u, err := url.Parse(f.Target)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for k, v := range f.Query {
		q.Set(k, v)
	}
	q.Set(param, value)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// methodOf returns f.Method or GET.
func methodOf(f Finding) string {
	if f.Method == "" {
		return http.MethodGet
	}
	return f.Method
}

// applyHeaders copies scope-resolved headers onto a request.
func applyHeaders(req *http.Request, f Finding) {
	for k, v := range f.Header {
		req.Header.Set(k, v)
	}
}
