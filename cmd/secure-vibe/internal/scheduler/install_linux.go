//go:build linux

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
		return formatErr("install", "systemd", err)
	}
	service, err := RenderSystemdService(cfg)
	if err != nil {
		return formatErr("install", "systemd", err)
	}
	timer, err := RenderSystemdTimer(cfg)
	if err != nil {
		return formatErr("install", "systemd", err)
	}
	servicePath := SystemdServicePath(home)
	timerPath := SystemdTimerPath(home)
	if err := manifest.WriteFileAtomic(servicePath, []byte(service), 0o644); err != nil {
		return formatErr("install", "systemd", err)
	}
	if err := manifest.WriteFileAtomic(timerPath, []byte(timer), 0o644); err != nil {
		return formatErr("install", "systemd", err)
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		// systemctl missing — file is on disk, operator can enable manually.
		return nil
	}
	if out, err := exec.Command("systemctl", "--user", "daemon-reload").CombinedOutput(); err != nil {
		return formatErr("install", "systemd", fmt.Errorf("daemon-reload: %v: %s", err, string(out)))
	}
	if out, err := exec.Command("systemctl", "--user", "enable", "--now", SystemdServiceName+".timer").CombinedOutput(); err != nil {
		return formatErr("install", "systemd", fmt.Errorf("enable --now: %v: %s", err, string(out)))
	}
	return nil
}

func removePlatform() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return formatErr("remove", "systemd", err)
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		_ = exec.Command("systemctl", "--user", "disable", "--now", SystemdServiceName+".timer").Run()
	}
	for _, p := range []string{SystemdTimerPath(home), SystemdServicePath(home)} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return formatErr("remove", "systemd", err)
		}
	}
	return nil
}

func statusPlatform() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	timer := SystemdTimerPath(home)
	if _, err := os.Stat(timer); err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return "systemd user timer installed at " + timer, nil
}

func defaultLogPath() string {
	if home, err := os.UserHomeDir(); err == nil {
		return home + "/.cache/secure-vibe/update.log"
	}
	return "/tmp/secure-vibe-update.log"
}
