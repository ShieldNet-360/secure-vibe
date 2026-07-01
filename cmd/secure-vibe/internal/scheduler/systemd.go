package scheduler

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
	"time"
)

// SystemdServiceName is the systemd unit base name. Two files are produced:
// <name>.service (the oneshot) and <name>.timer (the recurring trigger).
const SystemdServiceName = "secure-vibe-update"

const systemdServiceTemplate = `[Unit]
Description=Skills Library Update

[Service]
Type=oneshot
ExecStart={{ .ExecStart }}
{{- if .LogPath }}
StandardOutput=append:{{ .LogPath }}
StandardError=append:{{ .LogPath }}
{{- end }}
`

const systemdTimerTemplate = `[Unit]
Description=Skills Library Update Timer

[Timer]
OnBootSec=5min
OnUnitActiveSec={{ .OnUnitActiveSec }}
Unit={{ .ServiceUnit }}

[Install]
WantedBy=timers.target
`

// RenderSystemdService returns the .service unit body for the supplied Config.
func RenderSystemdService(cfg Config) (string, error) {
	if cfg.Binary == "" {
		return "", fmt.Errorf("systemd service: Binary must be set")
	}
	args := cfg.Args
	if len(args) == 0 {
		args = []string{"update", "--regenerate", "--quiet"}
	}
	execStart := quoteArg(cfg.Binary)
	for _, a := range args {
		execStart += " " + quoteArg(a)
	}
	data := struct {
		ExecStart string
		LogPath   string
	}{ExecStart: execStart, LogPath: cfg.LogPath}
	tpl := template.Must(template.New("service").Parse(systemdServiceTemplate))
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// RenderSystemdTimer returns the .timer unit body for the supplied Config.
func RenderSystemdTimer(cfg Config) (string, error) {
	if cfg.Interval <= 0 {
		return "", fmt.Errorf("systemd timer: Interval must be positive")
	}
	data := struct {
		OnUnitActiveSec string
		ServiceUnit     string
	}{
		OnUnitActiveSec: systemdDuration(cfg.Interval),
		ServiceUnit:     SystemdServiceName + ".service",
	}
	tpl := template.Must(template.New("timer").Parse(systemdTimerTemplate))
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// SystemdServicePath returns the conventional user-scope path for the
// service unit file.
func SystemdServicePath(homeDir string) string {
	return strings.TrimRight(homeDir, "/\\") + "/.config/systemd/user/" + SystemdServiceName + ".service"
}

// SystemdTimerPath returns the conventional user-scope path for the timer
// unit file.
func SystemdTimerPath(homeDir string) string {
	return strings.TrimRight(homeDir, "/\\") + "/.config/systemd/user/" + SystemdServiceName + ".timer"
}

// systemdDuration renders a Go time.Duration as a systemd OnUnitActiveSec
// string ("6h", "30min", "10s"). Anything below one minute is rounded up.
func systemdDuration(d time.Duration) string {
	switch {
	case d >= time.Hour && d%time.Hour == 0:
		return fmt.Sprintf("%dh", int(d/time.Hour))
	case d >= time.Minute && d%time.Minute == 0:
		return fmt.Sprintf("%dmin", int(d/time.Minute))
	case d >= time.Second:
		return fmt.Sprintf("%ds", int(d/time.Second))
	default:
		return "1min"
	}
}

// quoteArg quotes a single token for the ExecStart line.
func quoteArg(s string) string {
	if !strings.ContainsAny(s, " \t\"\\") {
		return s
	}
	return "\"" + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + "\""
}
