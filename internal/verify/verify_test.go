package verify

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// vulnerableServer mimics NodeGoat /research: fetches ?url= and returns the
// body — an unvalidated server-side fetch (SSRF).
func vulnerableServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		if target == "" {
			_, _ = w.Write([]byte("home"))
			return
		}
		resp, err := http.Get(target) //nolint -- intentionally vulnerable test fixture
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		_, _ = w.Write(b)
	}))
}

// safeServer validates ?url= against an allowlist before fetching.
func safeServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		if target == "" {
			_, _ = w.Write([]byte("home"))
			return
		}
		if !strings.HasPrefix(target, "https://api.iextrading.com/") {
			http.Error(w, "blocked: not allowlisted", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte("quote"))
	}))
}

func allowAll(string) bool { return true }

func TestSSRFProbe_ConfirmsVulnerable(t *testing.T) {
	srv := vulnerableServer()
	defer srv.Close()
	f := Finding{Type: "ssrf", Target: srv.URL, Param: "url"}
	res, err := Run(context.Background(), f, Opts{Confirm: true, AllowTarget: allowAll})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Confirmed {
		t.Fatalf("expected confirmed, got %+v", res)
	}
	if res.DryRun {
		t.Error("must not be dry-run when Confirm + scope are satisfied")
	}
	t.Logf("evidence: %s", res.Evidence)
}

func TestSSRFProbe_RefutesSafe(t *testing.T) {
	srv := safeServer()
	defer srv.Close()
	f := Finding{Type: "ssrf", Target: srv.URL, Param: "url"}
	res, err := Run(context.Background(), f, Opts{Confirm: true, AllowTarget: allowAll})
	if err != nil {
		t.Fatal(err)
	}
	if res.Confirmed {
		t.Fatalf("safe (allowlisted) server must not confirm, got %+v", res)
	}
	if !res.Refuted {
		t.Errorf("expected refuted, got %+v", res)
	}
}

func TestSSRFProbe_DryRunNeverFires(t *testing.T) {
	fired := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("url") != "" {
			fired = true
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	f := Finding{Type: "ssrf", Target: srv.URL, Param: "url"}
	res, err := Run(context.Background(), f, Opts{Confirm: false}) // dry-run
	if err != nil {
		t.Fatal(err)
	}
	if !res.DryRun {
		t.Error("expected dry-run")
	}
	if res.Payload == "" {
		t.Error("dry-run should still build a payload to show")
	}
	if fired {
		t.Error("RAIL 1 violated: dry-run must NOT send an attack request")
	}
}

func TestScopeGateBlocksOutOfScope(t *testing.T) {
	srv := vulnerableServer()
	defer srv.Close()
	f := Finding{Type: "ssrf", Target: srv.URL, Param: "url"}
	// Confirm=true but scope denies the target → must not fire.
	res, err := Run(context.Background(), f, Opts{Confirm: true, AllowTarget: func(string) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	if res.Confirmed {
		t.Error("RAIL 2 violated: out-of-scope target was probed")
	}
	if !res.DryRun {
		t.Error("out-of-scope must be treated as no-fire (dry-run)")
	}
}
