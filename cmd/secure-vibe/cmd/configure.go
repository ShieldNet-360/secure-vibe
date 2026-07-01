package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// SkillsCheckConfig is the on-disk representation of `.secure-vibe.yaml` that
// `secure-vibe configure` writes. The same struct is consumed by the update
// machinery so private-repo deployments stay byte-for-byte interoperable
// with the public default.
type SkillsCheckConfig struct {
	SchemaVersion          string            `yaml:"schema_version"`
	Source                 string            `yaml:"source,omitempty"`
	BearerTokenEnv         string            `yaml:"bearer_token_env,omitempty"`
	BearerToken            string            `yaml:"bearer_token,omitempty"`
	TrustedKeyPaths        []string          `yaml:"trusted_key_paths,omitempty"`
	Profile                string            `yaml:"profile,omitempty"`
	Skills                 []string          `yaml:"skills,omitempty"`
	Headers                map[string]string `yaml:"headers,omitempty"`
	InsecureAllowHTTPToken bool              `yaml:"insecure_allow_http_token,omitempty"`
}

// ValidateSourceWithToken enforces that a source URL transporting a bearer
// token uses HTTPS. The check is a defence-in-depth guard against a
// misconfigured `--source http://...` exfiltrating the bearer token in
// plaintext on every poll.
//
// Rules:
//   - https:// is always allowed.
//   - file:// and bare paths/tarballs are always allowed (no network).
//   - http:// without any bearer token configured is allowed (with a stderr
//     warning emitted by the caller).
//   - http:// with a bearer token is rejected unless allowInsecure=true.
//
// allowInsecure is the opt-in escape hatch (`--insecure-allow-http-token`)
// for internal-only setups that explicitly accept the risk.
func ValidateSourceWithToken(source, bearerToken, bearerTokenEnv string, allowInsecure bool) error {
	if source == "" {
		return nil
	}
	switch {
	case strings.HasPrefix(source, "https://"):
		return nil
	case strings.HasPrefix(source, "file://"):
		return nil // local file URL — no network transport for the token.
	case strings.HasPrefix(source, "http://"):
		// fall through to the http+token check below.
	default:
		// Reject any other URL-shaped source so a typo like ftp:// or
		// http:/x cannot silently bypass the token-transport check.
		// Bare paths and tarballs do not look like URLs (no "://").
		if strings.Contains(source, "://") {
			return fmt.Errorf("unsupported source scheme in %q (use https://, http://, or file://)", source)
		}
		return nil
	}
	hasToken := bearerToken != "" || bearerTokenEnv != ""
	if !hasToken {
		return nil
	}
	if allowInsecure {
		return nil
	}
	return fmt.Errorf(
		"refusing to attach bearer token to plaintext http:// source %q; "+
			"use https:// (recommended) or pass --insecure-allow-http-token to opt in for internal-only setups",
		source,
	)
}

// LoadConfig reads `.secure-vibe.yaml` from `dir`. If the file does not
// exist, an empty config (with schema_version "1.0") is returned and the
// `exists` return value is false.
func LoadConfig(dir string) (*SkillsCheckConfig, bool, error) {
	if dir == "" {
		dir = "."
	}
	p := filepath.Join(dir, ".secure-vibe.yaml")
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return &SkillsCheckConfig{SchemaVersion: "1.0"}, false, nil
		}
		return nil, false, err
	}
	var cfg SkillsCheckConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, true, fmt.Errorf("parse %s: %w", p, err)
	}
	if cfg.SchemaVersion == "" {
		return nil, true, fmt.Errorf("config %s missing schema_version", p)
	}
	return &cfg, true, nil
}

// ResolveBearerToken returns the bearer token to use. If BearerToken is set
// directly, it wins. Otherwise the value of the environment variable named
// by BearerTokenEnv is returned (empty string if unset). This lets users
// keep secrets out of the on-disk config.
func (c *SkillsCheckConfig) ResolveBearerToken() string {
	if c == nil {
		return ""
	}
	if c.BearerToken != "" {
		return c.BearerToken
	}
	if c.BearerTokenEnv != "" {
		return os.Getenv(c.BearerTokenEnv)
	}
	return ""
}

func configureCmd() *cobra.Command {
	var (
		dir               string
		source            string
		bearerTokenEnv    string
		trustedKey        []string
		profile           string
		skillList         string
		clearTrusted      bool
		clearAll          bool
		insecureAllowHTTP bool
	)

	c := &cobra.Command{
		Use:   "configure",
		Short: "Write or update .secure-vibe.yaml for private-repo / org deployments",
		Long: `Persist update-source, signing-key, and profile settings in
.secure-vibe.yaml at the given directory.

Typical workflows:

  # Point at an internal HTTPS mirror, signed with the org's public key.
  secure-vibe configure \
      --source https://skills.internal.example.com \
      --trusted-key /etc/skills/orgkey.pem \
      --bearer-token-env SECURE_VIBE_LIBRARY_TOKEN

  # Activate the financial-services enterprise profile by default.
  secure-vibe configure --profile financial-services

  # Reset.
  secure-vibe configure --clear
`,
		RunE: func(c *cobra.Command, args []string) error {
			cfg, _, err := LoadConfig(dir)
			if err != nil && !clearAll {
				return err
			}
			if clearAll || cfg == nil {
				cfg = &SkillsCheckConfig{SchemaVersion: "1.0"}
			}
			if cfg.SchemaVersion == "" {
				cfg.SchemaVersion = "1.0"
			}

			if source != "" {
				cfg.Source = source
			}
			if bearerTokenEnv != "" {
				cfg.BearerTokenEnv = bearerTokenEnv
			}
			if insecureAllowHTTP {
				cfg.InsecureAllowHTTPToken = true
			}
			if err := ValidateSourceWithToken(
				cfg.Source, cfg.BearerToken, cfg.BearerTokenEnv,
				cfg.InsecureAllowHTTPToken,
			); err != nil {
				return err
			}
			// Warn only on the http:// + no-token path. If a token is
			// attached and ValidateSourceWithToken accepted it (because
			// --insecure-allow-http-token opt-in is set), the operator has
			// explicitly accepted the risk — emitting "no bearer token
			// attached" in that case would be factually wrong and
			// misleading.
			if strings.HasPrefix(cfg.Source, "http://") && cfg.BearerToken == "" && cfg.BearerTokenEnv == "" {
				fmt.Fprintf(c.ErrOrStderr(),
					"warning: source %q uses plaintext http:// "+
						"(no bearer token attached; use https:// for confidentiality)\n",
					cfg.Source,
				)
			}
			if profile != "" {
				cfg.Profile = profile
			}
			if skillList != "" {
				items := []string{}
				for _, s := range strings.Split(skillList, ",") {
					s = strings.TrimSpace(s)
					if s != "" {
						items = append(items, s)
					}
				}
				cfg.Skills = items
			}
			if clearTrusted {
				cfg.TrustedKeyPaths = nil
			}
			if len(trustedKey) > 0 {
				seen := map[string]bool{}
				for _, k := range cfg.TrustedKeyPaths {
					seen[k] = true
				}
				for _, k := range trustedKey {
					if k = strings.TrimSpace(k); k != "" && !seen[k] {
						cfg.TrustedKeyPaths = append(cfg.TrustedKeyPaths, k)
						seen[k] = true
					}
				}
			}

			out, err := yaml.Marshal(cfg)
			if err != nil {
				return err
			}
			path := filepath.Join(dir, ".secure-vibe.yaml")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(path, out, 0o600); err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "wrote %s\n", path)
			return nil
		},
	}

	c.Flags().StringVar(&dir, "dir", ".", "Directory containing .secure-vibe.yaml")
	c.Flags().StringVar(&source, "source", "", "Custom update source URL (e.g. https://skills.internal/)")
	c.Flags().StringVar(&bearerTokenEnv, "bearer-token-env", "", "Env var holding bearer token (e.g. SECURE_VIBE_LIBRARY_TOKEN)")
	c.Flags().StringSliceVar(&trustedKey, "trusted-key", nil, "Additional Ed25519 public key file (repeatable)")
	c.Flags().StringVar(&profile, "profile", "", "Default enterprise profile name")
	c.Flags().StringVar(&skillList, "skills", "", "Comma-separated default skill set (narrows the --profile selection when both are set; both filters apply at init time)")
	c.Flags().BoolVar(&clearTrusted, "clear-trusted-keys", false, "Remove existing trusted_key_paths before adding new ones")
	c.Flags().BoolVar(&clearAll, "clear", false, "Reset the entire config to defaults before applying flags")
	c.Flags().BoolVar(&insecureAllowHTTP, "insecure-allow-http-token", false, "Permit bearer-token authentication over plaintext http:// (internal networks only; OFF by default)")
	return c
}
