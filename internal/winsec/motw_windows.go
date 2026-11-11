//go:build windows

package winsec

import "os"

// WriteMOTW writes the Zone.Identifier alternate data stream on path so
// Windows warns before the file is opened. Not all file systems support
// ADS (FAT32, exFAT); the error is returned for the caller to log.
func WriteMOTW(path, originalURL, finalURL string) error {
	return os.WriteFile(path+":Zone.Identifier", []byte(ZoneIdentifier(originalURL, finalURL)), 0o644)
}
