package verify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- SQLi fixtures ---

// sqliVulnServer delays when a time-based payload reaches it (injectable).
func sqliVulnServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := strings.ToLower(r.URL.Query().Get("id"))
		if strings.Contains(v, "sleep") || strings.Contains(v, "waitfor") {
			time.Sleep(sqliSleep) // payload reached the "DB"
		}
		_, _ = w.Write([]byte("rows"))
	}))
}

// sqliSafeServer uses parameterized queries: payload is inert, no delay.
func sqliSafeServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("rows"))
	}))
}

func TestSQLiProbe_ConfirmsVulnerable(t *testing.T) {
	old := sqliSleep
	sqliSleep = 500 * time.Millisecond // keep the test fast
	defer func() { sqliSleep = old }()

	srv := sqliVulnServer()
	defer srv.Close()
	f := Finding{Type: "sqli", Target: srv.URL, Param: "id"}
	res, err := Run(context.Background(), f, Opts{Confirm: true, AllowTarget: allowAll, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Confirmed {
		t.Fatalf("expected confirmed, got %+v", res)
	}
	t.Logf("evidence: %s", res.Evidence)
}

func TestSQLiProbe_RefutesSafe(t *testing.T) {
	old := sqliSleep
	sqliSleep = 500 * time.Millisecond
	defer func() { sqliSleep = old }()

	srv := sqliSafeServer()
	defer srv.Close()
	f := Finding{Type: "sqli", Target: srv.URL, Param: "id"}
	res, err := Run(context.Background(), f, Opts{Confirm: true, AllowTarget: allowAll, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if res.Confirmed {
		t.Fatalf("parameterized server must not confirm, got %+v", res)
	}
	if !res.Refuted {
		t.Errorf("expected refuted, got %+v", res)
	}
}

// --- Open-redirect fixtures ---

// redirectVulnServer reflects the param into a 302 Location (open redirect).
func redirectVulnServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		to := r.URL.Query().Get("next")
		if to != "" {
			http.Redirect(w, r, to, http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("home"))
	}))
}

// redirectSafeServer always redirects to a fixed internal path.
func redirectSafeServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	}))
}

func TestRedirectProbe_ConfirmsVulnerable(t *testing.T) {
	srv := redirectVulnServer()
	defer srv.Close()
	f := Finding{Type: "redirect", Target: srv.URL, Param: "next"}
	res, err := Run(context.Background(), f, Opts{Confirm: true, AllowTarget: allowAll})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Confirmed {
		t.Fatalf("expected confirmed, got %+v", res)
	}
	t.Logf("evidence: %s", res.Evidence)
}

func TestRedirectProbe_RefutesSafe(t *testing.T) {
	srv := redirectSafeServer()
	defer srv.Close()
	f := Finding{Type: "redirect", Target: srv.URL, Param: "next"}
	res, err := Run(context.Background(), f, Opts{Confirm: true, AllowTarget: allowAll})
	if err != nil {
		t.Fatal(err)
	}
	if res.Confirmed {
		t.Fatalf("internal-only redirect must not confirm, got %+v", res)
	}
	if !res.Refuted {
		t.Errorf("expected refuted, got %+v", res)
	}
}

func TestRegistryHasAllProbes(t *testing.T) {
	for _, want := range []string{"ssrf", "sqli", "xss", "redirect", "path-traversal", "command-injection", "ssti", "xxe"} {
		if _, ok := registry[want]; !ok {
			t.Errorf("probe %q not registered", want)
		}
	}
}
