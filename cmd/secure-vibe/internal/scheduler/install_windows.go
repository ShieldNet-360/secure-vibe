//go:build windows

package scheduler

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/shieldnet-360/secure-vibe/cmd/secure-vibe/internal/manifest"
)

// On Windows we register the task by writing the XML payload to a temp file
// and asking schtasks.exe to create / delete the task. schtasks ships in
// every supported Windows release and avoids a hard dependency on the COM
// runtime, while still exercising the documented Task Scheduler XML schema.

func installPlatform(cfg Config) error {
	xmlBody, err := RenderTaskSchedulerXML(cfg)
	if err != nil {
		return formatErr("install", "taskscheduler", err)
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = os.TempDir()
	}
	staging := filepath.Join(dir, "secure-vibe")
	xmlPath := filepath.Join(staging, "scheduled-update.xml")
	if err := manifest.WriteFileAtomic(xmlPath, []byte(xmlBody), 0o644); err != nil {
		return formatErr("install", "taskscheduler", err)
	}
	cmd := exec.Command("schtasks", "/Create", "/TN", TaskSchedulerTaskName, "/XML", xmlPath, "/F")
	if out, err := cmd.CombinedOutput(); err != nil {
		return formatErr("install", "taskscheduler", fmt.Errorf("schtasks /Create: %v: %s", err, string(out)))
	}
	return nil
}

func removePlatform() error {
	cmd := exec.Command("schtasks", "/Delete", "/TN", TaskSchedulerTaskName, "/F")
	if out, err := cmd.CombinedOutput(); err != nil {
		// Treat "task does not exist" as success.
		if isTaskNotFound(string(out)) {
			return nil
		}
		return formatErr("remove", "taskscheduler", fmt.Errorf("schtasks /Delete: %v: %s", err, string(out)))
	}
	return nil
}

func statusPlatform() (string, error) {
	cmd := exec.Command("schtasks", "/Query", "/TN", TaskSchedulerTaskName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if isTaskNotFound(string(out)) {
			return "", nil
		}
		return "", err
	}
	return "scheduled task installed: " + TaskSchedulerTaskName, nil
}

func defaultLogPath() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "secure-vibe", "update.log")
	}
	return filepath.Join(os.TempDir(), "secure-vibe-update.log")
}

func isTaskNotFound(output string) bool {
	for _, needle := range []string{"cannot find the file", "does not exist", "Operation cannot be performed"} {
		if containsIgnoreCase(output, needle) {
			return true
		}
	}
	return false
}

func containsIgnoreCase(haystack, needle string) bool {
	if len(haystack) < len(needle) {
		return false
	}
	lh := toLower(haystack)
	ln := toLower(needle)
	for i := 0; i+len(ln) <= len(lh); i++ {
		if lh[i:i+len(ln)] == ln {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}
