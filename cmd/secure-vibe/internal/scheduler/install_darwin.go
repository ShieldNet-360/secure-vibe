//go:build darwin

package scheduler

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/shieldnet-360/secure-vibe/cmd/secure-vibe/internal/manifest"
)

func installPlatform(cfg Config) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return formatErr("install", "launchd", err)
	}
	plist, err := RenderLaunchAgentPlist(cfg)
	if err != nil {
		return formatErr("install", "launchd", err)
	}
	path := LaunchAgentPlistPath(home)
	if err := manifest.WriteFileAtomic(path, []byte(plist), 0o644); err != nil {
		return formatErr("install", "launchd", err)
	}
	// launchctl bootstrap requires the agent's gui domain. Best effort here:
	// unload existing instance, load the new one. Errors are wrapped but not
	// fatal so operators can still inspect the plist on disk.
	_ = exec.Command("launchctl", "unload", path).Run()
	if out, err := exec.Command("launchctl", "load", path).CombinedOutput(); err != nil {
		return formatErr("install", "launchd", fmt.Errorf("launchctl load: %v: %s", err, string(out)))
	}
	return nil
}

func removePlatform() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return formatErr("remove", "launchd", err)
	}
	path := LaunchAgentPlistPath(home)
	_ = exec.Command("launchctl", "unload", path).Run()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return formatErr("remove", "launchd", err)
	}
	return nil
}

func statusPlatform() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	path := LaunchAgentPlistPath(home)
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return "launchd agent installed at " + path, nil
}

func defaultLogPath() string {
	if home, err := os.UserHomeDir(); err == nil {
		return home + "/Library/Logs/secure-vibe-update.log"
	}
	return "/tmp/secure-vibe-update.log"
}
