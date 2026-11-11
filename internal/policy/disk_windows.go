//go:build windows

package policy

import (
	"path/filepath"
	"syscall"
	"unsafe"
)

var (
	procGetDiskFreeSpaceEx   = modkernel32.NewProc("GetDiskFreeSpaceExW")
	procGetVolumePathName    = modkernel32.NewProc("GetVolumePathNameW")
	procGetVolumeInformation = modkernel32.NewProc("GetVolumeInformationW")
)

// StatDisk reports free space and file-system type for dir's volume.
func StatDisk(dir string) (DiskInfo, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return DiskInfo{}, err
	}
	p, err := syscall.UTF16PtrFromString(abs)
	if err != nil {
		return DiskInfo{}, err
	}
	var free, total, totalFree uint64
	r, _, e := procGetDiskFreeSpaceEx.Call(uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&free)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&totalFree)))
	if r == 0 {
		return DiskInfo{}, e
	}
	info := DiskInfo{Free: free, Total: total}
	vol := make([]uint16, 300)
	if r, _, _ := procGetVolumePathName.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&vol[0])), uintptr(len(vol))); r != 0 {
		fsName := make([]uint16, 64)
		if r, _, _ := procGetVolumeInformation.Call(uintptr(unsafe.Pointer(&vol[0])), 0, 0, 0, 0, 0,
			uintptr(unsafe.Pointer(&fsName[0])), uintptr(len(fsName))); r != 0 {
			info.FSType = syscall.UTF16ToString(fsName)
		}
	}
	return info, nil
}
