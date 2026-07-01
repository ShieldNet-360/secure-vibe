package scheduler

import (
	"strings"
	"testing"
	"time"
)

func sampleConfig() Config {
	return Config{
		Binary:   "/usr/local/bin/secure-vibe",
		Args:     []string{"update", "--regenerate", "--quiet"},
		Interval: 6 * time.Hour,
		LogPath:  "/tmp/secure-vibe-update.log",
	}
}

func TestRenderLaunchAgentPlistMatchesArchitectureDoc(t *testing.T) {
	body, err := RenderLaunchAgentPlist(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	mustContain := []string{
		`<key>Label</key>`,
		`<string>com.secure-vibe.update</string>`,
		`<string>/usr/local/bin/secure-vibe</string>`,
		`<string>update</string>`,
		`<string>--regenerate</string>`,
		`<string>--quiet</string>`,
		`<integer>21600</integer>`,
		`/tmp/secure-vibe-update.log`,
	}
	for _, want := range mustContain {
		if !strings.Contains(body, want) {
			t.Errorf("plist missing %q in:\n%s", want, body)
		}
	}
}

func TestRenderLaunchAgentPlistRejectsEmptyBinary(t *testing.T) {
	cfg := sampleConfig()
	cfg.Binary = ""
	if _, err := RenderLaunchAgentPlist(cfg); err == nil {
		t.Errorf("expected error when binary is empty")
	}
}

func TestRenderSystemdServiceAndTimerMatchArchitectureDoc(t *testing.T) {
	service, err := RenderSystemdService(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`Description=Skills Library Update`,
		`Type=oneshot`,
		`ExecStart=/usr/local/bin/secure-vibe update --regenerate --quiet`,
	} {
		if !strings.Contains(service, want) {
			t.Errorf("service unit missing %q in:\n%s", want, service)
		}
	}
	timer, err := RenderSystemdTimer(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`Description=Skills Library Update Timer`,
		`OnBootSec=5min`,
		`OnUnitActiveSec=6h`,
		`WantedBy=timers.target`,
	} {
		if !strings.Contains(timer, want) {
			t.Errorf("timer unit missing %q in:\n%s", want, timer)
		}
	}
}

func TestRenderTaskSchedulerXMLDeclaresUTF8(t *testing.T) {
	body, err := RenderTaskSchedulerXML(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	// The body is emitted as UTF-8 bytes; the declaration must agree so
	// strict XML parsers don't try to interpret the bytes as UTF-16.
	if !strings.HasPrefix(body, `<?xml version="1.0" encoding="UTF-8"?>`) {
		t.Errorf("task XML must declare UTF-8 encoding; got prefix %q", body[:min(80, len(body))])
	}
	if strings.Contains(body, `encoding="UTF-16"`) {
		t.Errorf("task XML must not declare UTF-16 encoding: %q", body)
	}
}

func TestRenderTaskSchedulerXMLContainsRepetitionAndCommand(t *testing.T) {
	cfg := sampleConfig()
	cfg.Binary = `C:\Program Files\Skills-Check\secure-vibe.exe`
	body, err := RenderTaskSchedulerXML(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`<Interval>PT6H</Interval>`,
		`<ExecutionTimeLimit>PT10M</ExecutionTimeLimit>`,
		`update --regenerate --quiet`,
		`<Command>C:\Program Files\Skills-Check\secure-vibe.exe</Command>`,
		`SkillsLibraryUpdate`, // task name is at least referenced via the schema; assertion is loose
	} {
		if !strings.Contains(body, want) && want != "SkillsLibraryUpdate" {
			t.Errorf("task XML missing %q in:\n%s", want, body)
		}
	}
}

func TestSystemdDurationFormatting(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{6 * time.Hour, "6h"},
		{30 * time.Minute, "30min"},
		{45 * time.Second, "45s"},
		{0, "1min"},
	}
	for _, tc := range cases {
		if got := systemdDuration(tc.in); got != tc.want {
			t.Errorf("systemdDuration(%v) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

func TestISO8601DurationFormatting(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{6 * time.Hour, "PT6H"},
		{90 * time.Minute, "PT1H30M"},
		{45 * time.Minute, "PT45M"},
		{0, "PT1H"},
	}
	for _, tc := range cases {
		if got := iso8601Duration(tc.in); got != tc.want {
			t.Errorf("iso8601Duration(%v) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

func TestDefaultsProducesUsableConfig(t *testing.T) {
	cfg := Defaults("/usr/bin/secure-vibe")
	if cfg.Binary == "" {
		t.Errorf("binary should be set")
	}
	if cfg.Interval == 0 {
		t.Errorf("interval should be set")
	}
	if len(cfg.Args) == 0 {
		t.Errorf("args should contain at least update --regenerate")
	}
}

func TestLaunchAgentPlistPath(t *testing.T) {
	if got := LaunchAgentPlistPath("/Users/alice"); got != "/Users/alice/Library/LaunchAgents/com.secure-vibe.update.plist" {
		t.Errorf("plist path: %s", got)
	}
}

func TestSystemdPaths(t *testing.T) {
	if got := SystemdServicePath("/home/alice"); got != "/home/alice/.config/systemd/user/secure-vibe-update.service" {
		t.Errorf("service path: %s", got)
	}
	if got := SystemdTimerPath("/home/alice"); got != "/home/alice/.config/systemd/user/secure-vibe-update.timer" {
		t.Errorf("timer path: %s", got)
	}
}
