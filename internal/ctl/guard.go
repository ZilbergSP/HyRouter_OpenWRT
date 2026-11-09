//go:build linux

package ctl

import (
	"context"
	"time"

	"github.com/zilbergsp/hyrouter/internal/nft"
	"github.com/zilbergsp/hyrouter/internal/store"
)

// The kill switch at boot (nft.GuardTable): the hyrouter-guard service
// closes the LAN's way beyond the router while it boots, Start opens it
// once HyRouter's own table is loaded, and Shutdown closes it again when
// hyrouterd stops while it should route.

// syncGuard opens the LAN when routing is off or the kill switch is not
// chosen.
func (c *Controller) syncGuard(s store.Settings) {
	if s.Enabled && s.KillSwitch {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := nft.RemoveGuard(ctx); err != nil {
		c.log.Warn("kill switch: not removed", "err", err)
	}
}

// Shutdown ends routing as hyrouterd exits. With routing on and the kill
// switch chosen, the LAN stays closed until hyrouterd is back (a restart,
// an upgrade); removing the package opens it (prerm).
func (c *Controller) Shutdown() error {
	s := c.State().Settings
	if c.Running() && s.Enabled && s.KillSwitch {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := nft.LoadGuard(ctx, s.LAN); err != nil {
			c.log.Error("kill switch: the LAN could not be closed", "err", err)
		} else {
			c.log.Info("kill switch: the LAN is closed until HyRouter is back")
		}
		cancel()
	}
	return c.Stop()
}

// guardActive reports the guard's table for the status: only while not
// routing, when it may be left from the boot.
func guardActive() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return nft.GuardActive(ctx)
}
