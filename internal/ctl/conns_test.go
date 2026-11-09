//go:build linux

package ctl

import (
	"net/netip"
	"testing"

	"github.com/zilbergsp/hyrouter/internal/nft"
	"github.com/zilbergsp/hyrouter/internal/rules"
	"github.com/zilbergsp/hyrouter/internal/store"
)

func TestParseConntrack(t *testing.T) {
	line := "ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.1.20 dst=93.184.216.34 sport=50000 dport=443 packets=10 bytes=1200 " +
		"src=93.184.216.34 dst=10.0.0.2 sport=443 dport=50000 packets=12 bytes=34000 [ASSURED] mark=16777216 zone=0 use=2"
	e, ok := parseConntrack(line)
	if !ok {
		t.Fatal("not parsed")
	}
	if e.proto != 6 || e.src != netip.MustParseAddrPort("192.168.1.20:50000") || e.dst != netip.MustParseAddrPort("93.184.216.34:443") {
		t.Errorf("%+v", e)
	}
	if e.sent != 1200 || e.recv != 34000 || e.mark&nft.CTMask != nft.CTDirect {
		t.Errorf("%+v", e)
	}
	// Without accounting the bytes are unknown.
	e, ok = parseConntrack("ipv6     10 udp      17 30 src=fd00::20 dst=2001:db8::1 sport=5353 dport=53 [UNREPLIED] src=2001:db8::1 dst=fd00::20 sport=53 dport=5353 mark=67108864 zone=0 use=2")
	if !ok || e.proto != 17 || e.sent != -1 || e.recv != -1 || e.mark&nft.CTMask != nft.CTBlock || e.dst.Port() != 53 {
		t.Errorf("%+v %v", e, ok)
	}
	if _, ok := parseConntrack("ipv4     2 icmp     1 29 src=192.168.1.20 dst=1.1.1.1 type=8 code=0 id=1 mark=0 use=1"); ok {
		t.Error("ICMP was taken")
	}
}

// A device is named by the settings, else its address; the key is what
// the statistics count it by.
func TestDeviceNames(t *testing.T) {
	var d devices
	d.set([]store.Device{{ID: "tv", Name: "Телевизор", MACs: []string{"aa:bb:cc:dd:ee:01"}}, {ID: "nas", Addrs: []string{"192.168.1.50"}}})
	mac, _ := rules.ParseMAC("aa:bb:cc:dd:ee:01")
	if n, k := d.name(mac, netip.MustParseAddr("192.168.1.20")); n != "Телевизор" || k != "dev:tv" {
		t.Errorf("%s %s", n, k)
	}
	if n, k := d.name(rules.MAC{}, netip.MustParseAddr("192.168.1.50")); n != "nas" || k != "dev:nas" {
		t.Errorf("%s %s", n, k)
	}
	if n, k := d.name(rules.MAC{}, netip.MustParseAddr("192.168.1.77")); n != "192.168.1.77" || k != "ip:192.168.1.77" {
		t.Errorf("%s %s", n, k)
	}
}
