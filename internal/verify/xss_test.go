package verify

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"testing"
)

// xssVulnServer reflects the param raw into HTML (reflected XSS).
func xssVulnServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<div>Hello " + r.URL.Query().Get("q") + "</div>"))
	}))
}

// xssSafeServer HTML-escapes the param before reflecting (safe).
func xssSafeServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<div>Hello " + html.EscapeString(r.URL.Query().Get("q")) + "</div>"))
	}))
}

func TestXSSProbe_ConfirmsVulnerable(t *testing.T) {
	srv := xssVulnServer()
	defer srv.Close()
	f := Finding{Type: "xss", Target: srv.URL, Param: "q"}
	res, err := Run(context.Background(), f, Opts{Confirm: true, AllowTarget: allowAll})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Confirmed {
		t.Fatalf("expected confirmed, got %+v", res)
	}
	t.Logf("evidence: %s", res.Evidence)
}

func TestXSSProbe_RefutesSafe(t *testing.T) {
	srv := xssSafeServer()
	defer srv.Close()
	f := Finding{Type: "xss", Target: srv.URL, Param: "q"}
	res, err := Run(context.Background(), f, Opts{Confirm: true, AllowTarget: allowAll})
	if err != nil {
		t.Fatal(err)
	}
	if res.Confirmed {
		t.Fatalf("escaped output must not confirm, got %+v", res)
	}
	if !res.Refuted {
		t.Errorf("expected refuted, got %+v", res)
	}
}
