//go:build windows

package power

import (
	"runtime"
	"syscall"
)

var procSetThreadExecutionState = syscall.NewLazyDLL("kernel32.dll").NewProc("SetThreadExecutionState")

const (
	esContinuous     = 0x80000000
	esSystemRequired = 0x00000001
)

// keepAwake calls SetThreadExecutionState(ES_CONTINUOUS|ES_SYSTEM_REQUIRED)
// on a dedicated OS thread (the state is per thread) and returns a func
// that clears it on the same thread.
func keepAwake() func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		procSetThreadExecutionState.Call(uintptr(esContinuous | esSystemRequired))
		<-stop
		procSetThreadExecutionState.Call(uintptr(esContinuous))
		close(done)
	}()
	return func() { close(stop); <-done }
}
