//go:build !windows

package power

// keepAwake is a no-op outside Windows for now. On Linux the daemon can be
// run under `systemd-inhibit`; see docs/INSTALL.md.
func keepAwake() func() { return func() {} }
