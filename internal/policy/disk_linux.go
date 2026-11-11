//go:build linux

package policy

import "syscall"

// StatDisk reports free space and file-system type for dir's volume.
func StatDisk(dir string) (DiskInfo, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return DiskInfo{}, err
	}
	bs := uint64(st.Bsize)
	info := DiskInfo{Free: st.Bavail * bs, Total: st.Blocks * bs}
	switch st.Type {
	case 0x4d44:
		info.FSType = "msdos"
	case 0x2011BAB0:
		info.FSType = "exfat"
	case 0x5346544e:
		info.FSType = "ntfs"
	case 0xEF53:
		info.FSType = "ext4"
	}
	return info, nil
}
