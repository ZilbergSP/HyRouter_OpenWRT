//go:build linux

package kernel

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"

	"github.com/zilbergsp/hyrouter/internal/rules"
)

// Neighbours tells the MAC address of a LAN address from the kernel's
// neighbour table (ARP and NDP). The table is read again on a miss, at
// most once a second.
type Neighbours struct {
	mu   sync.Mutex
	at   time.Time
	macs map[netip.Addr]rules.MAC
}

// Lookup returns the MAC of a, or the zero MAC when it is not known.
func (n *Neighbours) Lookup(a netip.Addr) rules.MAC {
	a = a.Unmap().WithZone("")
	n.mu.Lock()
	defer n.mu.Unlock()
	if m, ok := n.macs[a]; ok {
		return m
	}
	if time.Since(n.at) < time.Second {
		return rules.MAC{}
	}
	n.at = time.Now()
	if t, err := readNeighbours(); err == nil {
		n.macs = t
	}
	return n.macs[a]
}

// readNeighbours dumps the neighbour table of both families.
func readNeighbours() (map[netip.Addr]rules.MAC, error) {
	c, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	// struct ndmsg: family, pad1, pad2 (u16), ifindex (s32), state (u16),
	// flags, type.
	req := make([]byte, 12)
	msgs, err := c.Execute(netlink.Message{
		Header: netlink.Header{Type: unix.RTM_GETNEIGH, Flags: netlink.Request | netlink.Dump},
		Data:   req,
	})
	if err != nil {
		return nil, err
	}
	out := make(map[netip.Addr]rules.MAC, len(msgs))
	for _, m := range msgs {
		if len(m.Data) < 12 {
			continue
		}
		state := binary.NativeEndian.Uint16(m.Data[8:10])
		if state&(unix.NUD_INCOMPLETE|unix.NUD_FAILED|unix.NUD_NOARP) != 0 {
			continue
		}
		ad, err := netlink.NewAttributeDecoder(m.Data[12:])
		if err != nil {
			continue
		}
		var addr netip.Addr
		var mac rules.MAC
		var haveMAC bool
		for ad.Next() {
			switch ad.Type() {
			case unix.NDA_DST:
				if a, ok := netip.AddrFromSlice(ad.Bytes()); ok {
					addr = a.Unmap()
				}
			case unix.NDA_LLADDR:
				if b := ad.Bytes(); len(b) == 6 {
					copy(mac[:], b)
					haveMAC = true
				}
			}
		}
		if addr.IsValid() && haveMAC && !mac.IsZero() {
			out[addr] = mac
		}
	}
	return out, nil
}
