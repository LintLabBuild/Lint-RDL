//go:build !windows

package favorites

import "os"

func list() []Folder {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return linuxBookmarks(home, os.Getenv("XDG_CONFIG_HOME"), os.Getenv("XDG_DATA_HOME"))
}
