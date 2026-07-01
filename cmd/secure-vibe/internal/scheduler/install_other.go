//go:build !darwin && !linux && !windows

package scheduler

import (
	"errors"
	"fmt"
	"runtime"
)

var errUnsupportedOS = errors.New("scheduled updates are not supported on this OS")

func installPlatform(cfg Config) error {
	return fmt.Errorf("%w: %s", errUnsupportedOS, runtime.GOOS)
}

func removePlatform() error {
	return fmt.Errorf("%w: %s", errUnsupportedOS, runtime.GOOS)
}

func statusPlatform() (string, error) { return "", nil }

func defaultLogPath() string { return "/tmp/secure-vibe-update.log" }
