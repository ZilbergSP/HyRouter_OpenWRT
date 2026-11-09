//go:build linux && lite

package ctl

import (
	"github.com/zilbergsp/hyrouter/internal/hycore"
	"github.com/zilbergsp/hyrouter/internal/hysteria"
	"github.com/zilbergsp/hyrouter/internal/tunnels"
)

// embedded runs a Hysteria 2 server inside hyrouterd: HyRouter Lite has
// no hysteria process (hycore).
func (c *Controller) embedded(p hysteria.Profile, h tunnels.Hooks) tunnels.Runner {
	if p.IsVLESS() {
		return nil
	}
	return &hycore.Runner{Profile: p, Hooks: h, Log: c.log}
}

// needsCore: Lite downloads no core.
func needsCore(hysteria.Profile) bool { return false }
