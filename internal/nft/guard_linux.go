//go:build linux

package nft

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

// LoadGuard closes the LAN's way beyond the router (GuardTable): hyrouterd
// stops while it should route, and VPN traffic must not go direct until
// it is back.
func LoadGuard(ctx context.Context, lan []string) error {
	script, err := GuardScript(lan)
	if err != nil {
		return err
	}
	return Load(ctx, script)
}

// RemoveGuard opens it again; a guard that is not there is no error.
func RemoveGuard(ctx context.Context) error {
	out, err := exec.CommandContext(ctx, "nft", "delete", "table", "inet", GuardTable).CombinedOutput()
	if err != nil && !bytes.Contains(out, []byte("No such file")) {
		return fmt.Errorf("nft: %v: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

// GuardActive reports whether the guard's table is loaded.
func GuardActive(ctx context.Context) bool {
	return exec.CommandContext(ctx, "nft", "list", "table", "inet", GuardTable).Run() == nil
}
