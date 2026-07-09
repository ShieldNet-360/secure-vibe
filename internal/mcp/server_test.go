package mcp

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shieldnet-360/secure-vibe/internal/audit"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for dir := wd; dir != "/"; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
	}
	t.Fatalf("could not find repo root from %s", wd)
	return ""
}

func newServer(t *testing.T) *Server {
	t.Helper()
	srv, err := NewServer(repoRoot(t))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}

func mustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestInitializeReturnsServerInfo(t *testing.T) {
	srv := newServer(t)
	req := mustMarshal(t, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
	})
	resp := srv.HandleLine(req)
	if resp == nil || resp.Error != nil {
		t.Fatalf("expected ok response, got %+v", resp)
	}
	result := resp.Result.(map[string]interface{})
	info := result["serverInfo"].(map[string]interface{})
	if info["name"] != "secure-vibe" {
		t.Errorf("serverInfo.name=%q", info["name"])
	}
	if got := result["protocolVersion"]; got != SupportedProtocolVersion {
		t.Errorf("protocolVersion=%v, want %s", got, SupportedProtocolVersion)
	}
	if _, ok := result["instructions"]; !ok {
		t.Errorf("initialize result missing instructions field")
	}
}

// Per the MCP lifecycle spec, the server MUST echo back a protocol
// version the client asked for if it supports it; otherwise return
// its own latest. Cover both branches plus the empty-string fallback.
func TestInitializeNegotiatesProtocolVersion(t *testing.T) {
	srv := newServer(t)
	cases := []struct {
		name      string
		requested string
		want      string
	}{
		{"latest", "2025-11-25", "2025-11-25"},
		{"older-supported", "2024-11-05", "2024-11-05"},
		{"unknown", "9999-01-01", SupportedProtocolVersion},
		{"empty", "", SupportedProtocolVersion},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := mustMarshal(t, map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      1,
				"method":  "initialize",
				"params": map[string]interface{}{
					"protocolVersion": tc.requested,
				},
			})
			resp := srv.HandleLine(req)
			if resp == nil || resp.Error != nil {
				t.Fatalf("expected ok response, got %+v", resp)
			}
			result := resp.Result.(map[string]interface{})
			if got := result["protocolVersion"]; got != tc.want {
				t.Errorf("requested %q: got %v, want %s", tc.requested, got, tc.want)
			}
		})
	}
}

// TestInitializeGatesNewerFieldsByNegotiatedVersion pins down that the
// server does not emit fields from newer MCP revisions in a response
// that claims an older protocolVersion. See review flag at server.go:159.
//
//   - instructions:        added in 2025-03-26
//   - serverInfo.title:    added in 2025-11-25
func TestInitializeGatesNewerFieldsByNegotiatedVersion(t *testing.T) {
	srv := newServer(t)
	cases := []struct {
		requested        string
		wantInstructions bool
		wantTitle        bool
	}{
		{"2024-11-05", false, false},
		{"2025-03-26", true, false},
		{"2025-06-18", true, false},
		{"2025-11-25", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.requested, func(t *testing.T) {
			req := mustMarshal(t, map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      1,
				"method":  "initialize",
				"params": map[string]interface{}{
					"protocolVersion": tc.requested,
				},
			})
			resp := srv.HandleLine(req)
			if resp == nil || resp.Error != nil {
				t.Fatalf("expected ok response, got %+v", resp)
			}
			result := resp.Result.(map[string]interface{})
			if got := result["protocolVersion"]; got != tc.requested {
				t.Fatalf("protocolVersion=%v, want %s", got, tc.requested)
			}
			_, hasInstructions := result["instructions"]
			if hasInstructions != tc.wantInstructions {
				t.Errorf("v=%s: hasInstructions=%v, want %v", tc.requested, hasInstructions, tc.wantInstructions)
			}
			info := result["serverInfo"].(map[string]interface{})
			_, hasTitle := info["title"]
			if hasTitle != tc.wantTitle {
				t.Errorf("v=%s: serverInfo.hasTitle=%v, want %v", tc.requested, hasTitle, tc.wantTitle)
			}
		})
	}
}

// TestAssertProtocolVersionShapePanicsOnNonDate locks in the defensive
// check around the lexicographic protocol-version comparison. The
// comparison `negotiated >= protocolVersionWithTitle` is only correct
// while all participating values are fixed-width YYYY-MM-DD strings;
// the init()-time assertion panics if a future contributor adds a
// non-date identifier, so the silent-miscompare risk flagged in the
// PR #15 review is converted to a loud build-time failure.
func TestAssertProtocolVersionShapePanicsOnNonDate(t *testing.T) {
	cases := []struct {
		v          string
		wantPanics bool
	}{
		{"2025-11-25", false},
		{"2024-11-05", false},
		{"v2.0", true},
		{"2025-1-25", true},   // not zero-padded
		{"2025-11-25T", true}, // trailing junk
		{"", true},
	}
	for _, tc := range cases {
		t.Run(tc.v, func(t *testing.T) {
			defer func() {
				r := recover()
				if (r != nil) != tc.wantPanics {
					t.Errorf("v=%q: panicked=%v, want %v (r=%v)", tc.v, r != nil, tc.wantPanics, r)
				}
			}()
			assertProtocolVersionShape("test", tc.v)
		})
	}
}

func TestToolsListReturnsExpectedTools(t *testing.T) {
	srv := newServer(t)
	req := mustMarshal(t, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
	})
	resp := srv.HandleLine(req)
	if resp == nil || resp.Error != nil {
		t.Fatalf("expected ok response, got %+v", resp)
	}
	result := resp.Result.(map[string]interface{})
	tools := result["tools"].([]map[string]interface{})
	want := map[string]bool{
		"lookup_vulnerability":   false,
		"check_secret_pattern":   false,
		"get_skill":              false,
		"search_skills":          false,
		"scan_secrets":           false,
		"check_dependency":       false,
		"check_typosquat":        false,
		"map_compliance_control": false,
		"get_sigma_rule":         false,
		"version_status":         false,
		"scan_dependencies":      false,
		"scan_github_actions":    false,
		"scan_dockerfile":        false,
		"list_external_tools":    false,
		"explain_finding":        false,
		"gate":                   false,
		"audit":                  false,
		"http_probe":             false,
		"oob_listener":           false,
	}
	if len(tools) != len(want) {
		t.Fatalf("expected %d tools, got %d", len(want), len(tools))
	}
	for _, tdef := range tools {
		name := tdef["name"].(string)
		if _, ok := want[name]; !ok {
			t.Errorf("unexpected tool %q", name)
		}
		want[name] = true
		if _, ok := tdef["inputSchema"]; !ok {
			t.Errorf("tool %q has no inputSchema", name)
		}
	}
	for name, ok := range want {
		if !ok {
			t.Errorf("tool %q missing from tools/list", name)
		}
	}
}

func TestToolsCallLookupVulnerability(t *testing.T) {
	srv := newServer(t)
	req := mustMarshal(t, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "lookup_vulnerability",
			"arguments": map[string]string{
				"package":   "event-stream",
				"ecosystem": "npm",
			},
		},
	})
	resp := srv.HandleLine(req)
	if resp == nil || resp.Error != nil {
		t.Fatalf("expected ok response, got %+v", resp)
	}
	res := resp.Result.(map[string]interface{})
	body, _ := json.Marshal(res)
	if !strings.Contains(string(body), "event-stream") {
		t.Errorf("response did not contain event-stream; got %s", body)
	}
}

func TestToolsCallSearchSkills(t *testing.T) {
	srv := newServer(t)
	req := mustMarshal(t, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      4,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      "search_skills",
			"arguments": map[string]string{"query": "secret"},
		},
	})
	resp := srv.HandleLine(req)
	if resp == nil || resp.Error != nil {
		t.Fatalf("expected ok response, got %+v", resp)
	}
	body, _ := json.Marshal(resp.Result)
	if !strings.Contains(string(body), "secret-detection") {
		t.Errorf("expected secret-detection in response, got %s", body)
	}
}

func TestUnknownMethodReturnsErr(t *testing.T) {
	srv := newServer(t)
	req := mustMarshal(t, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      5,
		"method":  "bogus",
	})
	resp := srv.HandleLine(req)
	if resp == nil || resp.Error == nil {
		t.Fatalf("expected error response; got %+v", resp)
	}
	if resp.Error.Code != codeMethodNotFound {
		t.Errorf("code=%d want %d", resp.Error.Code, codeMethodNotFound)
	}
}

func TestServeOverPipe(t *testing.T) {
	srv := newServer(t)
	in := bytes.NewBufferString(string(mustMarshal(t, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/list",
	})) + "\n")
	out := &bytes.Buffer{}
	if err := srv.Serve(in, out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if !strings.Contains(out.String(), "lookup_vulnerability") {
		t.Errorf("Serve output missing tool name: %s", out.String())
	}
}

func TestNotificationProducesNoResponse(t *testing.T) {
	srv := newServer(t)
	req := mustMarshal(t, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "initialize",
	})
	if resp := srv.HandleLine(req); resp != nil {
		t.Errorf("notification should not produce a response; got %+v", resp)
	}
}

// Per JSON-RPC 2.0 §4.1, a request with an explicit "id": null is NOT a
// notification and MUST receive a response (also with "id": null). Only
// a request lacking the "id" member entirely is a notification.
func TestExplicitNullIDProducesResponse(t *testing.T) {
	srv := newServer(t)
	req := []byte(`{"jsonrpc":"2.0","id":null,"method":"initialize"}`)
	resp := srv.HandleLine(req)
	if resp == nil {
		t.Fatal("request with explicit \"id\": null must receive a response")
	}
	if resp.Error != nil {
		t.Fatalf("expected ok response, got error %+v", resp.Error)
	}
	// The response id should preserve the null literal sent by the
	// client, and serialize as "id":null (not be omitted).
	if string(resp.ID) != "null" {
		t.Errorf("response.ID = %q, want \"null\"", string(resp.ID))
	}
	out, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(out), `"id":null`) {
		t.Errorf("serialized response should contain \"id\":null; got %s", out)
	}
}

func TestInvokeAuditRespectsSandbox(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.js"),
		[]byte("const gh = \"ghp_016C6eB6D6a1F2b3C4d5E6f7A8b9C0d1E2f3G4H5\";\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := newServer(t)
	if err := srv.SetAllowedRoots([]string{dir}); err != nil {
		t.Fatal(err)
	}
	res, err := srv.invokeTool("audit", map[string]interface{}{"path": dir})
	if err != nil {
		t.Fatalf("audit tool: %v", err)
	}
	rep, ok := res.(*audit.Report)
	if !ok {
		t.Fatalf("audit returned %T, want *audit.Report", res)
	}
	if rep.Total() < 1 {
		t.Errorf("expected at least one finding under the audited dir, got %d", rep.Total())
	}
}
