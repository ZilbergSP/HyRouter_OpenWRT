//go:build !windows && !linux

package hysteria

import "os/exec"

func childAttrs(*exec.Cmd) {}
