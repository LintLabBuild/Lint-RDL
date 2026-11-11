//go:build windows

package winsec

import (
	"io/fs"
	"os"
	"path/filepath"
)

// WriteMOTW writes the Zone.Identifier alternate data stream on path so
// Windows warns before the file is opened. Not all file systems support
// ADS (FAT32, exFAT); the error is returned for the caller to log.
func WriteMOTW(path, originalURL, finalURL string) error {
	return os.WriteFile(path+":Zone.Identifier", []byte(ZoneIdentifier(originalURL, finalURL)), 0o644)
}

func markTree(dir, originalURL string, limit int) (int, error) {
	n := 0
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		if d.Type().IsRegular() && n < limit {
			if WriteMOTW(p, originalURL, originalURL) == nil {
				n++
			}
		}
		return nil
	})
	return n, err
}
