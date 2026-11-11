//go:build darwin

package power

import (
	"os"
	"os/exec"
	"strconv"
)

// keepAwake runs `caffeinate -i -w <rdl pid>`: it prevents idle sleep and
// ends by itself if rdl exits.
func keepAwake() func() {
	cmd := exec.Command("/usr/bin/caffeinate", "-i", "-w", strconv.Itoa(os.Getpid()))
	if err := cmd.Start(); err != nil {
		return func() {}
	}
	return func() {
		cmd.Process.Kill()
		go cmd.Wait()
	}
}
