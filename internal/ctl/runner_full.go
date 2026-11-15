//go:build linux && !lite

package ctl

import "github.com/apernet/hysteria/core/v2/client"

// tuneQUIC: the full edition keeps Hysteria's QUIC windows (the routers
// it is for have the memory).
var tuneQUIC func(*client.Config)
