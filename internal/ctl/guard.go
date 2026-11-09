//go:build linux

package ctl

import (
	"context"
	"errors"
	"time"

	"github.com/zilbergsp/hyrouter/internal/store"
)

// The kill switch at boot (nft.GuardTable, ipt.OwnerGuard): on OpenWrt the
// hyrouter-guard service closes the LAN's way beyond the router while it
// boots, on KeeneticOS hyrouterd itself as it starts (Entware starts after
// the firmware); Start opens it once HyRouter's own rules are loaded, and
// Shutdown closes it again when hyrouterd stops while it should route.

// syncGuard opens the LAN when routing is off or the kill switch is not
// chosen.
func (c *Controller) syncGuard(s store.Settings) {
	if s.Enabled && s.KillSwitch {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := fwRemoveGuard(ctx); err != nil {
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
		if err := fwLoadGuard(ctx, s.LAN); err != nil {
			c.log.Error("kill switch: the LAN could not be closed", "err", err)
		} else {
			c.log.Info("kill switch: the LAN is closed until HyRouter is back")
		}
		cancel()
	}
	err := c.Stop()
	if ferr := c.stats.Flush(time.Now()); ferr != nil {
		c.log.Warn("statistics not written", "err", ferr)
	}
	return err
}

// CloseAtStart closes the LAN while hyrouterd starts, when routing is on
// and the kill switch chosen: until Start loads HyRouter's rules, nothing
// goes direct.
func (c *Controller) CloseAtStart() {
	s := c.State().Settings
	if !s.Enabled || !s.KillSwitch {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := fwLoadGuard(ctx, s.LAN); err != nil {
		c.log.Error("kill switch: the LAN could not be closed", "err", err)
	}
}

// Cleanup removes what HyRouter put in the kernel when no hyrouterd runs
// (the package's removal): its rules, the kill switch, the routing rule
// and the nfqws2 a crashed hyrouterd left. The settings stay.
func Cleanup() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	killLeftovers()
	return errors.Join(fwRemove(ctx), fwRemoveGuard(ctx), fwRoute.Remove())
}

// guardActive reports the guard's table for the status: only while not
// routing, when it may be left from the boot.
func guardActive() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return fwGuardActive(ctx)
}
