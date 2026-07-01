package scheduler

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
)

// LaunchAgentLabel is the reverse-DNS label launchd uses to identify the
// scheduled update. It is also the basename (with .plist appended) of the
// plist file under ~/Library/LaunchAgents.
const LaunchAgentLabel = "com.secure-vibe.update"

const launchAgentTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{{ .Label }}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{{ .Binary }}</string>{{ range .Args }}
        <string>{{ . }}</string>{{ end }}
    </array>
    <key>StartInterval</key>
    <integer>{{ .IntervalSeconds }}</integer>
    <key>RunAtLoad</key>
    <false/>
    <key>StandardOutPath</key>
    <string>{{ .LogPath }}</string>
    <key>StandardErrorPath</key>
    <string>{{ .LogPath }}</string>
</dict>
</plist>
`

// RenderLaunchAgentPlist returns the plist XML for the supplied Config. It
// is a pure function so tests can assert on the exact output on any OS.
func RenderLaunchAgentPlist(cfg Config) (string, error) {
	if cfg.Binary == "" {
		return "", fmt.Errorf("launchd plist: Binary must be set")
	}
	if cfg.Interval <= 0 {
		return "", fmt.Errorf("launchd plist: Interval must be positive")
	}
	args := cfg.Args
	if len(args) == 0 {
		args = []string{"update", "--regenerate", "--quiet"}
	}
	logPath := cfg.LogPath
	if logPath == "" {
		logPath = "/tmp/secure-vibe-update.log"
	}
	escapedArgs := make([]string, len(args))
	for i, a := range args {
		escapedArgs[i] = escapeXMLAttr(a)
	}
	data := struct {
		Label           string
		Binary          string
		Args            []string
		IntervalSeconds int
		LogPath         string
	}{
		Label:           LaunchAgentLabel,
		Binary:          escapeXMLAttr(cfg.Binary),
		Args:            escapedArgs,
		IntervalSeconds: intSecondsAtLeast(cfg.Interval, 60),
		LogPath:         escapeXMLAttr(logPath),
	}
	tpl := template.Must(template.New("plist").Parse(launchAgentTemplate))
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// LaunchAgentPlistPath is the canonical filesystem location for the plist.
func LaunchAgentPlistPath(homeDir string) string {
	return strings.TrimRight(homeDir, "/\\") + "/Library/LaunchAgents/" + LaunchAgentLabel + ".plist"
}
