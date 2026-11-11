//go:build !linux && !darwin && !windows

package policy

import "errors"

// StatDisk is not implemented on this OS.
func StatDisk(dir string) (DiskInfo, error) {
	return DiskInfo{}, errors.New("disk stats not supported on this OS")
}
