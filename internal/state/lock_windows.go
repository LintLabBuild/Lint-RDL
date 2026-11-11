//go:build windows

package state

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var (
	modkernel32     = syscall.NewLazyDLL("kernel32.dll")
	procCreateMutex = modkernel32.NewProc("CreateMutexW")
)

const errorAlreadyExists syscall.Errno = 183

// Lock is a single-instance lock (a named mutex).
type Lock struct{ h syscall.Handle }

// AcquireLock creates a named mutex derived from dir. It fails if another
// rdl process using the same state folder holds it.
func AcquireLock(dir string) (*Lock, error) {
	abs, _ := filepath.Abs(dir)
	sum := sha256.Sum256([]byte(strings.ToLower(abs)))
	name, err := syscall.UTF16PtrFromString(`Local\rdl-` + hex.EncodeToString(sum[:8]))
	if err != nil {
		return nil, err
	}
	h, _, e := procCreateMutex.Call(0, 1, uintptr(unsafe.Pointer(name)))
	if h == 0 {
		return nil, e
	}
	if e == errorAlreadyExists {
		syscall.CloseHandle(syscall.Handle(h))
		return nil, fmt.Errorf("another rdl process is already running")
	}
	return &Lock{h: syscall.Handle(h)}, nil
}

// Release frees the lock.
func (l *Lock) Release() {
	if l != nil && l.h != 0 {
		syscall.CloseHandle(l.h)
		l.h = 0
	}
}

func syncDir(string) {} // NTFS rename is metadata-journaled; no dir fsync API
