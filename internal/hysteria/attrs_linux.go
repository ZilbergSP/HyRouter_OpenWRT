package hysteria

import (
	"os/exec"
	"syscall"
)

// childAttrs (HyRouter): a core dies with hyrouterd. procd restarts
// hyrouterd after a crash, and a core left from the old run would hold
// its SOCKS5 port and its server connection.
func childAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
