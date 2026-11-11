//go:build !windows

package policy

import (
	"os"
	"path/filepath"
)

// RealPath returns the absolute path of p with every symlink resolved.
func RealPath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}

func hideFile(string) {}

// DefaultForbidden returns the always-forbidden folders for this OS, plus
// any extra folders (rdl's own config, state and log folders).
func DefaultForbidden(extra ...string) []string {
	home, _ := os.UserHomeDir()
	out := []string{"/etc", "/bin", "/sbin", "/usr", "/boot", "/lib", "/lib32", "/lib64", "/libx32",
		"/proc", "/sys", "/dev", "/run", "/var/spool", "/var/lib", "/root", "/System", "/Library", "/Applications"}
	if home != "" {
		out = append(out,
			filepath.Join(home, ".config"),
			filepath.Join(home, ".local"),
			filepath.Join(home, ".ssh"),
			filepath.Join(home, ".gnupg"),
			filepath.Join(home, "bin"),
			filepath.Join(home, "Library", "LaunchAgents"),
		)
	}
	return append(out, extra...)
}
