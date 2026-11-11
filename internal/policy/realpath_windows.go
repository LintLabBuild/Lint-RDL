//go:build windows

package policy

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var (
	modkernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procGetFinalPathNameByHandle = modkernel32.NewProc("GetFinalPathNameByHandleW")
)

const fileFlagBackupSemantics = 0x02000000

// RealPath returns the final path of p with symlinks, junctions and mount
// points resolved, using GetFinalPathNameByHandleW on an open handle.
func RealPath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	name, err := syscall.UTF16PtrFromString(abs)
	if err != nil {
		return "", err
	}
	h, err := syscall.CreateFile(name, 0,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, fileFlagBackupSemantics, 0)
	if err != nil {
		if err == syscall.ERROR_FILE_NOT_FOUND || err == syscall.ERROR_PATH_NOT_FOUND {
			return "", &os.PathError{Op: "realpath", Path: abs, Err: os.ErrNotExist}
		}
		return "", &os.PathError{Op: "realpath", Path: abs, Err: err}
	}
	defer syscall.CloseHandle(h)
	buf := make([]uint16, 512)
	for {
		n, _, e := procGetFinalPathNameByHandle.Call(uintptr(h), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0)
		if n == 0 {
			return "", &os.PathError{Op: "realpath", Path: abs, Err: e}
		}
		if int(n) < len(buf) {
			s := syscall.UTF16ToString(buf[:n])
			switch {
			case strings.HasPrefix(s, `\\?\UNC\`):
				s = `\\` + s[len(`\\?\UNC\`):]
			case strings.HasPrefix(s, `\\?\`):
				s = s[len(`\\?\`):]
			}
			return filepath.Clean(s), nil
		}
		buf = make([]uint16, n+1)
	}
}

func hideFile(p string) {
	name, err := syscall.UTF16PtrFromString(p)
	if err != nil {
		return
	}
	attrs, err := syscall.GetFileAttributes(name)
	if err != nil {
		return
	}
	_ = syscall.SetFileAttributes(name, attrs|syscall.FILE_ATTRIBUTE_HIDDEN)
}

// DefaultForbidden returns the always-forbidden folders for Windows, plus
// any extra folders (rdl's own config, state and log folders).
func DefaultForbidden(extra ...string) []string {
	env := func(k string) string { return os.Getenv(k) }
	var out []string
	add := func(parts ...string) {
		if parts[0] == "" {
			return
		}
		out = append(out, filepath.Join(parts...))
	}
	add(env("SystemRoot"))
	if env("SystemRoot") == "" {
		add(`C:\Windows`)
	}
	add(env("ProgramFiles"))
	add(env("ProgramFiles(x86)"))
	add(env("ProgramW6432"))
	add(env("ProgramData"), "Microsoft", "Windows", "Start Menu")
	add(env("APPDATA"), "Microsoft", "Windows", "Start Menu")
	return append(out, extra...)
}
