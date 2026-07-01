// Package scheduler installs and removes scheduled-update tasks on each
// supported operating system.
//
// Three backends are provided: launchd (macOS), systemd --user (Linux), and
// Task Scheduler (Windows). Backend selection is driven by runtime.GOOS so a
// single CLI binary picks the right implementation transparently.
//
// All artifacts the backends write — plist, .service, .timer, taskscheduler
// XML — are exported as string-returning helpers (RenderLaunchAgentPlist,
// RenderSystemdService, RenderSystemdTimer, RenderTaskSchedulerXML) so they
// can be unit-tested on every operating system, not just the one the test
// runner happens to use.
package scheduler

import (
	"fmt"
	"time"
)

// Config is the cross-platform configuration for one installed scheduled
// update. The same struct drives every backend.
type Config struct {
	// Binary is the absolute path to the secure-vibe binary the scheduler
	// should invoke.
	Binary string
	// Args are extra command-line arguments to pass after "update". A typical
	// invocation is ["update", "--regenerate", "--quiet"].
	Args []string
	// Interval is the gap between successive runs. 6h is the default in
	// ARCHITECTURE.md.
	Interval time.Duration
	// LogPath is where stdout/stderr from the scheduled run should be
	// captured. Backends that do not support log redirection ignore this.
	LogPath string
	// Quiet, when true, suppresses progress chatter to stdout when invoked
	// from a periodic scheduler.
	Quiet bool
}

// Defaults produces a Config populated with the standard 6-hour interval,
// the standard log path, and the conventional update flags.
func Defaults(binary string) Config {
	return Config{
		Binary:   binary,
		Args:     []string{"update", "--regenerate", "--quiet"},
		Interval: 6 * time.Hour,
		LogPath:  defaultLogPath(),
		Quiet:    true,
	}
}

// Install installs the scheduled update appropriate for the host operating
// system. It is implemented per-OS by the platform-tagged files.
func Install(cfg Config) error {
	return installPlatform(cfg)
}

// Remove uninstalls the scheduled update on the host operating system.
func Remove() error { return removePlatform() }

// Status returns a short human description of the currently installed
// scheduled update, or an empty string if nothing is installed.
func Status() (string, error) { return statusPlatform() }

// formatErr is a small helper used by the platform files to wrap external
// command errors in a stable format the tests can match against.
func formatErr(action, target string, err error) error {
	return fmt.Errorf("scheduler %s %s: %w", action, target, err)
}
