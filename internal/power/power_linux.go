//go:build linux

package power

import (
	"os/exec"
)

// keepAwake asks systemd-logind not to sleep or idle-suspend while
// downloads run, by holding an inhibitor lock through systemd-inhibit.
// The child process reads stdin; closing the pipe (or rdl exiting for any
// reason) ends it and releases the lock. Without systemd it's a no-op.
func keepAwake() func() {
	bin, err := exec.LookPath("systemd-inhibit")
	if err != nil {
		return func() {}
	}
	cmd := exec.Command(bin, "--what=sleep:idle", "--who=rdl", "--why=Downloading files", "--mode=block", "cat")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return func() {}
	}
	if err := cmd.Start(); err != nil {
		return func() {}
	}
	return func() {
		stdin.Close()
		go cmd.Wait()
	}
}
