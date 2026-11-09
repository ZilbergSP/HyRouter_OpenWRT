// Package platform is what differs between the router systems HyRouter
// runs on (docs/ARCHITECTURE.md, «Платформы»): OpenWrt, and KeeneticOS
// with Entware (the build tag keenetic). The paths, the router's DNS,
// its devices, its WAN and its version come from here; the firewall
// (nftables on OpenWrt, iptables on KeeneticOS) is chosen in ctl.
package platform

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"strings"
)

// Host is a device of the LAN the router knows: its MAC, address and
// name (empty when it has none).
type Host struct {
	MAC  string
	IP   string
	Name string
}

// DefaultRoute reads the IPv4 default route: its interface and gateway.
func DefaultRoute() (string, netip.Addr) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", netip.Addr{}
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text()) // Iface Destination Gateway Flags …
		if len(fs) < 3 || fs[1] != "00000000" {
			continue
		}
		b, err := hex.DecodeString(fs[2])
		if err != nil || len(b) != 4 {
			return fs[0], netip.Addr{}
		}
		var a [4]byte
		binary.LittleEndian.PutUint32(a[:], binary.BigEndian.Uint32(b))
		return fs[0], netip.AddrFrom4(a)
	}
	return "", netip.Addr{}
}

// defaultRoute6 is the interface of the IPv6 default route ("" = none).
func defaultRoute6() string {
	f, err := os.Open("/proc/net/ipv6_route")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// dst dst_len src src_len next_hop metric refcnt use flags iface
		fs := strings.Fields(sc.Text())
		if len(fs) < 10 || fs[1] != "00" || strings.Trim(fs[0], "0") != "" || fs[9] == "lo" {
			continue
		}
		return fs[9]
	}
	return ""
}

// lanAddr4 is the first IPv4 address of the first LAN interface that has
// one.
func lanAddr4(lan []string) netip.Addr {
	for _, name := range lan {
		ifc, err := net.InterfaceByName(name)
		if err != nil {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ip, ok := netip.AddrFromSlice(n.IP); ok && ip.Unmap().Is4() {
				return ip.Unmap()
			}
		}
	}
	return netip.Addr{}
}
