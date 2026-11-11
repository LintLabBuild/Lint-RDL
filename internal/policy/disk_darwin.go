//go:build darwin

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
	b := make([]byte, 0, len(st.Fstypename))
	for _, c := range st.Fstypename {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	info.FSType = string(b)
	return info, nil
}
