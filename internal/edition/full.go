//go:build !lite

package edition

// Name is the edition for people, Package its OpenWrt package.
const (
	Name    = "HyRouter"
	Package = "hyrouter"
	Lite    = false
)

// Current are the limits of this edition.
var Current = Limits{DNSCache: 50000, Relay: 8192, VLESS: true}
