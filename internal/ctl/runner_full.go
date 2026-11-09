//go:build linux && !lite

package ctl

import (
	"github.com/zilbergsp/hyrouter/internal/hysteria"
	"github.com/zilbergsp/hyrouter/internal/tunnels"
)

// embedded: HyRouter runs every server's own core process.
func (c *Controller) embedded(hysteria.Profile, tunnels.Hooks) tunnels.Runner { return nil }

// needsCore: every server runs its core.
func needsCore(hysteria.Profile) bool { return true }
