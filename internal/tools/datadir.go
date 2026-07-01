package tools

import (
	"os"
	"path/filepath"
	"runtime"
)

// DefaultDataDir is the per-user directory where an installed `secure-vibe`
// looks for its library data (skills/, vulnerabilities/, ...) when neither
// --path nor $SECURE_VIBE_LIBRARY_PATH is given and the current directory is not
// itself a checkout. install.sh extracts the release data tarball here, so a
// `curl | sh` install works without a clone.
//
//	Linux/macOS: $XDG_DATA_HOME/secure-vibe, else ~/.local/share/secure-vibe
//	Windows:     %LocalAppData%\secure-vibe, else %AppData%\secure-vibe
//
// Returns "" if no base directory can be determined.
func DefaultDataDir() string {
	if runtime.GOOS == "windows" {
		for _, env := range []string{"LocalAppData", "AppData"} {
			if v := os.Getenv(env); v != "" {
				return filepath.Join(v, "secure-vibe")
			}
		}
		return ""
	}
	if v := os.Getenv("XDG_DATA_HOME"); v != "" {
		return filepath.Join(v, "secure-vibe")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".local", "share", "secure-vibe")
	}
	return ""
}

// IsLibraryRoot reports whether dir looks like a secure-vibe root — i.e. it
// has a skills/ subdirectory. Used to decide whether a candidate root (cwd, the
// default data dir, ...) actually holds the library data before selecting it.
func IsLibraryRoot(dir string) bool {
	if dir == "" {
		return false
	}
	fi, err := os.Stat(filepath.Join(dir, "skills"))
	return err == nil && fi.IsDir()
}
