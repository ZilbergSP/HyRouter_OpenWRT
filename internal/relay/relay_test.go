//go:build linux

package relay

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/zilbergsp/hyrouter/internal/rules"
	"github.com/zilbergsp/hyrouter/internal/socks5"
)

// cmsg builds one control message as the kernel lays it out.
func cmsg(level, typ int, data []byte) []byte {
	b := make([]byte, unix.CmsgSpace(len(data)))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level = int32(level)
	h.Type = int32(typ)
	h.SetLen(unix.CmsgLen(len(data)))
	copy(b[unix.CmsgLen(0):], data)
	return b
}

func TestOrigDst(t *testing.T) {
	sa4 := make([]byte, unix.SizeofSockaddrInet4)
	binary.NativeEndian.PutUint16(sa4[0:2], unix.AF_INET)
	binary.BigEndian.PutUint16(sa4[2:4], 443)
	copy(sa4[4:8], []byte{203, 0, 113, 7})
	if got, ok := origDst(cmsg(unix.SOL_IP, unix.IP_ORIGDSTADDR, sa4)); !ok || got != netip.MustParseAddrPort("203.0.113.7:443") {
		t.Errorf("IPv4: %v %v", got, ok)
	}
	sa6 := make([]byte, unix.SizeofSockaddrInet6)
	binary.NativeEndian.PutUint16(sa6[0:2], unix.AF_INET6)
	binary.BigEndian.PutUint16(sa6[2:4], 53)
	copy(sa6[8:24], netip.MustParseAddr("2001:db8::1").AsSlice())
	if got, ok := origDst(cmsg(unix.SOL_IPV6, unix.IPV6_ORIGDSTADDR, sa6)); !ok || got != netip.MustParseAddrPort("[2001:db8::1]:53") {
		t.Errorf("IPv6: %v %v", got, ok)
	}
	if got, ok := origDst(cmsg(unix.SOL_SOCKET, unix.SCM_RIGHTS, []byte{1, 2, 3, 4})); ok {
		t.Errorf("another message read as a destination: %v", got)
	}
	if _, ok := origDst([]byte{1, 2, 3}); ok {
		t.Error("garbage read as a destination")
	}
}

type fakeTunnel struct{ up, udp bool }

func (f fakeTunnel) Available() bool    { return f.up }
func (f fakeTunnel) UDPAvailable() bool { return f.udp }
func (f fakeTunnel) Dial(context.Context, socks5.Addr) (net.Conn, error) {
	return nil, errors.New("fake")
}
func (f fakeTunnel) UDPAssociate(context.Context) (*socks5.UDPAssoc, error) {
	return nil, errors.New("fake")
}

func TestPickTunnel(t *testing.T) {
	ts := map[string]Tunnel{"down": fakeTunnel{}, "tcp": fakeTunnel{up: true}, "both": fakeTunnel{up: true, udp: true}}
	r := &Relay{cfg: Config{Tunnel: func(id string) Tunnel { return ts[id] }}}
	res := rules.Result{Action: rules.Tunnel, Profile: "down", Fallback: []string{"gone", "tcp", "both"}}
	if _, id := r.pickTunnel(res, false); id != "tcp" {
		t.Errorf("TCP took %q", id)
	}
	if _, id := r.pickTunnel(res, true); id != "both" {
		t.Errorf("UDP took %q", id)
	}
	if tun, id := r.pickTunnel(rules.Result{Action: rules.Tunnel, Profile: "down"}, false); tun != nil || id != "" {
		t.Errorf("a down server was taken: %q", id)
	}
}

// The relay decides as the kernel did: by the sites whose names resolved
// to the destination, for the device the connection comes from.
func TestByDNS(t *testing.T) {
	set, err := rules.Compile(rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{
		{Name: "tv", Devices: []string{"192.168.1.20"}, Domains: []string{".video.example"}, Action: rules.Tunnel},
	}})
	if err != nil {
		t.Fatal(err)
	}
	set.Main = "p1"
	names := map[netip.Addr][]string{netip.MustParseAddr("198.51.100.1"): {"cdn.video.example"}}
	r := &Relay{cfg: Config{Rules: func() *rules.Set { return set }, Names: func(a netip.Addr) []string { return names[a] }}}
	tv := netip.MustParseAddrPort("192.168.1.20:40000")
	other := netip.MustParseAddrPort("192.168.1.21:40000")
	site := netip.MustParseAddrPort("198.51.100.1:443")
	if res := r.byDNS(r.subject(6, tv, site)); res.Action != rules.Tunnel || res.Profile != "p1" {
		t.Errorf("tv to the site: %+v", res)
	}
	if res := r.byDNS(r.subject(6, other, site)); res.Action != rules.Direct {
		t.Errorf("another device to the site: %+v", res)
	}
	if res := r.byDNS(r.subject(6, tv, netip.MustParseAddrPort("198.51.100.2:443"))); res.Action != rules.Direct {
		t.Errorf("tv to an address of no site: %+v", res)
	}
}
