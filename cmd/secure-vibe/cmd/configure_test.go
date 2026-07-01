package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigureWritesFile(t *testing.T) {
	tmp := t.TempDir()
	stdout, _, err := executeRoot(t,
		"configure",
		"--dir", tmp,
		"--source", "https://skills.internal.example.com",
		"--bearer-token-env", "MY_TOKEN",
		"--trusted-key", "/etc/skills/orgkey.pem",
		"--profile", "financial-services",
	)
	if err != nil {
		t.Fatalf("configure: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, ".secure-vibe.yaml") {
		t.Errorf("unexpected stdout: %s", stdout)
	}

	body, err := os.ReadFile(filepath.Join(tmp, ".secure-vibe.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)
	for _, want := range []string{
		"schema_version: \"1.0\"",
		"source: https://skills.internal.example.com",
		"bearer_token_env: MY_TOKEN",
		"orgkey.pem",
		"profile: financial-services",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in config, got:\n%s", want, got)
		}
	}
}

func TestLoadConfigMissing(t *testing.T) {
	tmp := t.TempDir()
	cfg, exists, err := LoadConfig(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Error("expected exists=false")
	}
	if cfg.SchemaVersion == "" {
		t.Error("expected default schema_version")
	}
}

func TestResolveBearerTokenFromEnv(t *testing.T) {
	t.Setenv("MY_TOKEN_ENV", "secret-token-value")
	cfg := &SkillsCheckConfig{BearerTokenEnv: "MY_TOKEN_ENV"}
	if got := cfg.ResolveBearerToken(); got != "secret-token-value" {
		t.Errorf("got %q", got)
	}
	cfg.BearerToken = "literal"
	if got := cfg.ResolveBearerToken(); got != "literal" {
		t.Errorf("literal should win, got %q", got)
	}
}

func TestConfigureClearAll(t *testing.T) {
	tmp := t.TempDir()
	if _, _, err := executeRoot(t,
		"configure", "--dir", tmp,
		"--source", "https://a/", "--profile", "p1",
	); err != nil {
		t.Fatal(err)
	}
	if _, _, err := executeRoot(t,
		"configure", "--dir", tmp, "--clear",
	); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(filepath.Join(tmp, ".secure-vibe.yaml"))
	if strings.Contains(string(body), "profile: p1") {
		t.Errorf("expected profile cleared, got:\n%s", body)
	}
}

// TestConfigureClearRecoversFromCorruptedConfig verifies that --clear can
// recover from a malformed .secure-vibe.yaml. Without the fix, LoadConfig
// returns an error before clearAll is honored, so the documented reset
// workflow is unreachable in exactly the situation it is meant to handle.
func TestConfigureClearRecoversFromCorruptedConfig(t *testing.T) {
	t.Run("malformed yaml", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, ".secure-vibe.yaml")
		if err := os.WriteFile(path, []byte("schema_version: \"1.0\"\nsource: [unterminated\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := executeRoot(t, "configure", "--dir", tmp, "--clear"); err != nil {
			t.Fatalf("--clear should recover from malformed yaml, got: %v", err)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		got := string(body)
		if !strings.Contains(got, "schema_version: \"1.0\"") {
			t.Errorf("expected reset config, got:\n%s", got)
		}
		if strings.Contains(got, "[unterminated") {
			t.Errorf("expected corrupt content to be overwritten, got:\n%s", got)
		}
	})

	t.Run("missing schema_version", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, ".secure-vibe.yaml")
		if err := os.WriteFile(path, []byte("source: https://stale.example.com\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := executeRoot(t, "configure", "--dir", tmp, "--clear"); err != nil {
			t.Fatalf("--clear should recover from missing schema_version, got: %v", err)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		got := string(body)
		if !strings.Contains(got, "schema_version: \"1.0\"") {
			t.Errorf("expected reset config, got:\n%s", got)
		}
		if strings.Contains(got, "stale.example.com") {
			t.Errorf("expected stale source to be overwritten, got:\n%s", got)
		}
	})

	t.Run("clear plus new source in one invocation", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, ".secure-vibe.yaml")
		if err := os.WriteFile(path, []byte("source: [malformed\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := executeRoot(t,
			"configure", "--dir", tmp, "--clear",
			"--source", "https://fresh.example.com",
		); err != nil {
			t.Fatalf("--clear with new flags should succeed, got: %v", err)
		}
		body, _ := os.ReadFile(path)
		got := string(body)
		if !strings.Contains(got, "source: https://fresh.example.com") {
			t.Errorf("expected new source applied after clear, got:\n%s", got)
		}
	})

	t.Run("missing file still works without --clear", func(t *testing.T) {
		tmp := t.TempDir()
		if _, _, err := executeRoot(t,
			"configure", "--dir", tmp, "--source", "https://a/",
		); err != nil {
			t.Fatalf("missing config should not require --clear, got: %v", err)
		}
	})

	t.Run("corrupt config without --clear still errors", func(t *testing.T) {
		tmp := t.TempDir()
		if err := os.WriteFile(filepath.Join(tmp, ".secure-vibe.yaml"), []byte("source: [unterminated\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := executeRoot(t,
			"configure", "--dir", tmp, "--source", "https://b/",
		); err == nil {
			t.Errorf("expected error when running configure against corrupt config without --clear")
		}
	})
}

// TestConfigureRejectsHTTPSourceWithBearerToken verifies that configure
// refuses to write a config that would send a bearer token over plaintext
// http://. The check is enforced at write time (not just at update time) so
// that the .secure-vibe.yaml on disk is never in a state where the next
// `secure-vibe update` would leak the token.
func TestConfigureRejectsHTTPSourceWithBearerToken(t *testing.T) {
	t.Run("http+token without opt-in is rejected", func(t *testing.T) {
		tmp := t.TempDir()
		_, _, err := executeRoot(t,
			"configure",
			"--dir", tmp,
			"--source", "http://internal.corp.example.com/skills",
			"--bearer-token-env", "MY_TOKEN",
		)
		if err == nil {
			t.Fatal("expected configure to refuse http+bearer-token, got nil error")
		}
		if !strings.Contains(err.Error(), "plaintext http://") {
			t.Errorf("expected plaintext-http error, got: %v", err)
		}
		// No config should have been written.
		if _, statErr := os.Stat(filepath.Join(tmp, ".secure-vibe.yaml")); !os.IsNotExist(statErr) {
			t.Errorf("expected no .secure-vibe.yaml to be written, got: %v", statErr)
		}
	})

	t.Run("http+token with --insecure-allow-http-token opts in", func(t *testing.T) {
		tmp := t.TempDir()
		_, _, err := executeRoot(t,
			"configure",
			"--dir", tmp,
			"--source", "http://internal.corp.example.com/skills",
			"--bearer-token-env", "MY_TOKEN",
			"--insecure-allow-http-token",
		)
		if err != nil {
			t.Fatalf("expected --insecure-allow-http-token to bypass, got: %v", err)
		}
		body, _ := os.ReadFile(filepath.Join(tmp, ".secure-vibe.yaml"))
		got := string(body)
		if !strings.Contains(got, "insecure_allow_http_token: true") {
			t.Errorf("expected opt-in to be persisted, got:\n%s", got)
		}
		if !strings.Contains(got, "source: http://internal.corp.example.com/skills") {
			t.Errorf("expected source to be persisted, got:\n%s", got)
		}
	})

	t.Run("https+token is always allowed", func(t *testing.T) {
		tmp := t.TempDir()
		_, _, err := executeRoot(t,
			"configure",
			"--dir", tmp,
			"--source", "https://skills.internal.example.com",
			"--bearer-token-env", "MY_TOKEN",
		)
		if err != nil {
			t.Fatalf("https+token should be allowed, got: %v", err)
		}
	})

	t.Run("http without token emits a warning but succeeds", func(t *testing.T) {
		tmp := t.TempDir()
		_, stderr, err := executeRoot(t,
			"configure",
			"--dir", tmp,
			"--source", "http://anonymous.example.com/skills",
		)
		if err != nil {
			t.Fatalf("http without token should succeed, got: %v", err)
		}
		if !strings.Contains(stderr, "plaintext http://") {
			t.Errorf("expected stderr warning, got: %q", stderr)
		}
	})

	t.Run("http+token+opt-in does NOT emit the no-token-attached warning", func(t *testing.T) {
		// When the operator explicitly opts in to http+token via
		// --insecure-allow-http-token, the warning that claims "no
		// bearer token attached" would be factually wrong — the token IS
		// attached. Verify the warning is suppressed on this path so
		// stderr stays honest.
		tmp := t.TempDir()
		_, stderr, err := executeRoot(t,
			"configure",
			"--dir", tmp,
			"--source", "http://internal.corp.example.com/skills",
			"--bearer-token-env", "MY_TOKEN",
			"--insecure-allow-http-token",
		)
		if err != nil {
			t.Fatalf("http+token+opt-in should succeed, got: %v", err)
		}
		if strings.Contains(stderr, "no bearer token attached") {
			t.Errorf("misleading no-token warning fired on http+token+opt-in path; stderr:\n%s", stderr)
		}
		if strings.Contains(stderr, "plaintext http://") {
			t.Errorf("plaintext-http warning fired on http+token+opt-in path; stderr:\n%s", stderr)
		}
	})

	t.Run("http+token-on-disk+opt-in via existing config does NOT emit warning", func(t *testing.T) {
		// Same invariant when the http+token+opt-in config is loaded
		// from disk and the operator runs `configure` to update an
		// unrelated field (e.g. --profile).
		tmp := t.TempDir()
		path := filepath.Join(tmp, ".secure-vibe.yaml")
		body := "schema_version: \"1.0\"\n" +
			"source: http://internal.corp.example.com/skills\n" +
			"bearer_token_env: MY_TOKEN\n" +
			"insecure_allow_http_token: true\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		_, stderr, err := executeRoot(t,
			"configure",
			"--dir", tmp,
			"--profile", "financial-services",
		)
		if err != nil {
			t.Fatalf("updating an opted-in config should succeed, got: %v", err)
		}
		if strings.Contains(stderr, "no bearer token attached") {
			t.Errorf("misleading no-token warning fired when reloading opted-in config; stderr:\n%s", stderr)
		}
	})

	t.Run("file:// source bypasses the check", func(t *testing.T) {
		tmp := t.TempDir()
		_, _, err := executeRoot(t,
			"configure",
			"--dir", tmp,
			"--source", "file:///tmp/local-skills",
			"--bearer-token-env", "MY_TOKEN",
		)
		if err != nil {
			t.Fatalf("file:// source should be allowed with token, got: %v", err)
		}
	})

	t.Run("loading existing http+token config emits no extra checks", func(t *testing.T) {
		// Sanity check: the validation runs at write time only. A config
		// that already exists on disk with insecure_allow_http_token: true
		// must round-trip through configure without forcing the user to
		// pass --insecure-allow-http-token every time they update other
		// fields.
		tmp := t.TempDir()
		path := filepath.Join(tmp, ".secure-vibe.yaml")
		body := "schema_version: \"1.0\"\n" +
			"source: http://internal.corp.example.com/skills\n" +
			"bearer_token_env: MY_TOKEN\n" +
			"insecure_allow_http_token: true\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, err := executeRoot(t,
			"configure",
			"--dir", tmp,
			"--profile", "financial-services",
		)
		if err != nil {
			t.Fatalf("updating an opted-in config should succeed, got: %v", err)
		}
	})
}

// TestValidateSourceWithToken is a unit-level test for the pure function so
// future programmatic callers (not just the configure command) get the same
// guarantees.
func TestValidateSourceWithToken(t *testing.T) {
	cases := []struct {
		name            string
		source, tok, ev string
		allowInsecure   bool
		wantErr         bool
	}{
		{"empty source", "", "tok", "", false, false},
		{"https with token", "https://x/", "tok", "", false, false},
		{"https with env token", "https://x/", "", "ENV", false, false},
		{"https without token", "https://x/", "", "", false, false},
		{"http without token", "http://x/", "", "", false, false},
		{"http with token rejected", "http://x/", "tok", "", false, true},
		{"http with env token rejected", "http://x/", "", "ENV", false, true},
		{"http with token opted-in", "http://x/", "tok", "", true, false},
		{"file:// with token allowed", "file:///x", "tok", "", false, false},
		{"bare path allowed", "/tmp/x", "tok", "", false, false},
		{"unsupported scheme rejected", "ftp://x/", "tok", "", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSourceWithToken(tc.source, tc.tok, tc.ev, tc.allowInsecure)
			if tc.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected nil error, got: %v", err)
			}
		})
	}
}
