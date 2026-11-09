//go:build lite

package edition

// Name is the edition for people, Package its OpenWrt package.
const (
	Name    = "HyRouter Lite"
	Package = "hyrouter-lite"
	Lite    = true
)

// Current are the limits of this edition: routers with 128–256 MB of
// memory and a slow CPU.
var Current = Limits{DNSCache: 10000, Relay: 2048, Memory: 48 << 20, GroupRun: 3}
