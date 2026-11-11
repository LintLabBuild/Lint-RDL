package policy

import (
	"errors"
	"fmt"
)

// FAT32MaxFile is the largest file a FAT32 volume can hold.
const FAT32MaxFile = 1<<32 - 1

// ErrDiskSpace means the drive does not have enough free space.
var ErrDiskSpace = errors.New("not enough free disk space")

// DiskInfo describes the volume holding a folder.
type DiskInfo struct {
	Free   uint64 `json:"free"`
	Total  uint64 `json:"total"`
	FSType string `json:"fs,omitempty"`
}

// DiskGuard checks free space before and during downloads.
type DiskGuard struct {
	// MinFree is the safety margin that must stay free (default 10 GB).
	MinFree uint64
	// Stat is overridable for tests; defaults to StatDisk.
	Stat func(dir string) (DiskInfo, error)
}

func (g *DiskGuard) stat(dir string) (DiskInfo, error) {
	if g.Stat != nil {
		return g.Stat(dir)
	}
	return StatDisk(dir)
}

// Check verifies that dir's drive can take `remaining` more bytes plus the
// safety margin. remaining < 0 means unknown size: only the margin is
// checked. It also refuses files over 4 GB on FAT32.
func (g *DiskGuard) Check(dir string, totalSize, remaining int64) error {
	info, err := g.stat(dir)
	if err != nil {
		return nil // cannot tell; don't block the download on it
	}
	if totalSize > FAT32MaxFile && isFAT(info.FSType) {
		return fmt.Errorf("%s is a FAT32 drive and the file is larger than 4 GB; choose an NTFS or exFAT drive", dir)
	}
	need := g.MinFree
	if remaining > 0 {
		need += uint64(remaining)
	}
	if info.Free < need {
		return fmt.Errorf("%w on %s: %s free, %s needed (incl. %s safety margin)",
			ErrDiskSpace, dir, HumanBytes(int64(info.Free)), HumanBytes(int64(need)), HumanBytes(int64(g.MinFree)))
	}
	return nil
}

func isFAT(fs string) bool {
	switch fs {
	case "FAT", "FAT32", "FAT16", "FAT12", "msdos", "vfat":
		return true
	}
	return false
}

// HumanBytes formats n as a short human-readable size (binary units, shown
// as "GB" like Windows Explorer does).
func HumanBytes(n int64) string {
	if n < 0 {
		return "unknown"
	}
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 4; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(n)/float64(div), "KMGTP"[exp])
}
