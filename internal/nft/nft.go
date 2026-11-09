// Package nft builds HyRouter's nftables table (inet hyrouter) from the
// rules and fills its sets with the addresses of sites
// (docs/ARCHITECTURE.md, «nftables и policy routing»).
//
// The kernel decides every new connection from the LAN by its device,
// protocol, port and destination address, and keeps the decision in the
// connection mark: a direct connection never reaches hyrouterd, a tunnel
// one goes to the relay through TPROXY, a blocked one is reset. A site is
// matched by the addresses its names resolved to through HyRouter's DNS,
// which adds them to the rule's DNS sets (Sets).
package nft

import (
	"fmt"
	"strings"
)

// Table is the name of HyRouter's table in the inet family.
const Table = "hyrouter"

// Connection marks: the bits CTMask of the connection mark hold the
// route of a connection once its first packet is decided.
const (
	CTMask   = 0x07000000
	CTDirect = 0x01000000
	CTTunnel = 0x02000000
	CTName   = 0x03000000
	CTBlock  = 0x04000000
)

// MarkTProxy is the packet mark of packets for the relay; policy routing
// (RulePriority, RouteTable) delivers them to the local socket.
const (
	MarkTProxy   = 0x08000000
	RouteTable   = 7701
	RulePriority = 7701
)

// Options are the router's side of the table.
type Options struct {
	// LAN are the interfaces whose traffic HyRouter decides (br-lan).
	LAN []string
	// TunnelPort is the relay's TPROXY port for TCP and UDP through a
	// tunnel, NamePort its port for TCP whose route depends on the site
	// name (SNI, Host), DNSPort the port of HyRouter's DNS.
	TunnelPort uint16
	NamePort   uint16
	DNSPort    uint16
	// Extra is put inside the table as it is: the sets and chains of the
	// DPI bypass (zapret.NFT).
	Extra string
}

// DNSSet names the set of rule pos that holds the addresses of its sites.
func DNSSet(pos int, v6 bool) string { return setName(pos, "dns", v6) }

// AmbigSet names the set of addresses shared by sites that the rules
// send different ways: web connections to them are decided by the name
// the relay reads.
func AmbigSet(v6 bool) string {
	if v6 {
		return "ambig6"
	}
	return "ambig4"
}

func setName(pos int, kind string, v6 bool) string {
	fam := 4
	if v6 {
		fam = 6
	}
	return fmt.Sprintf("r%d_%s%d", pos, kind, fam)
}

// validIface accepts a Linux interface name (at most 15 bytes of letters,
// digits and . _ - @): it is written into the script.
func validIface(s string) bool {
	if s == "" || len(s) > 15 {
		return false
	}
	for _, c := range s {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._-@", c)
		if !ok {
			return false
		}
	}
	return true
}
