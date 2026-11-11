//go:build !windows

package winsec

// WriteMOTW is a no-op outside Windows (no Mark of the Web there).
func WriteMOTW(path, originalURL, finalURL string) error { return nil }
