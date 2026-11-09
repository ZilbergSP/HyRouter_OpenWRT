// Package edition is the HyRouter edition a binary is built as and its
// limits (docs/ARCHITECTURE.md, «Редакции»): HyRouter, or HyRouter Lite
// with the build tag lite.
package edition

import (
	"os"
	"runtime/debug"
)

// Limits are what differs between the editions at run time.
type Limits struct {
	// DNSCache bounds the name and address pairs the DNS cache keeps.
	DNSCache int
	// Relay bounds the connections and UDP flows through the relay at
	// once; a new one past it is refused.
	Relay int
	// Memory is the soft memory limit of hyrouterd in bytes (GOMEMLIMIT);
	// 0 = none.
	Memory int64
	// VLESS: VLESS servers (Xray) are supported.
	VLESS bool
}

// SetMemoryLimit applies Current.Memory unless GOMEMLIMIT is set in the
// environment: the administrator's choice wins.
func SetMemoryLimit() {
	if Current.Memory > 0 && os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(Current.Memory)
	}
}
