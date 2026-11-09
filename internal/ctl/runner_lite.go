//go:build linux && lite

package ctl

import (
	"github.com/apernet/hysteria/core/v2/client"

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
	return &hycore.Runner{Profile: p, Hooks: h, Log: c.log, Tune: smallWindows}
}

// smallWindows bounds what QUIC buffers per server: Hysteria's defaults
// (8 MB a stream, 20 MB a connection) would fill a Lite router's memory
// at full speed. A window the profile sets stays.
func smallWindows(c *client.Config) {
	q := &c.QUICConfig
	for _, w := range []struct {
		v   *uint64
		def uint64
	}{
		{&q.InitialStreamReceiveWindow, 2 << 20},
		{&q.MaxStreamReceiveWindow, 4 << 20},
		{&q.InitialConnectionReceiveWindow, 5 << 20},
		{&q.MaxConnectionReceiveWindow, 10 << 20},
	} {
		if *w.v == 0 {
			*w.v = w.def
		}
	}
}

// needsCore: Lite downloads no core.
func needsCore(hysteria.Profile) bool { return false }
