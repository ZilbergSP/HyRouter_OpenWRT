//go:build linux

package ipt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"

	"github.com/zilbergsp/hyrouter/internal/nft"
)

// The ipset netlink protocol (linux/netfilter/ipset/ip_set.h).
const (
	nfnlSubsysIPSet = 6
	ipsetCmdAdd     = 9
	// Protocol 6 is what kernels before 5.x take; newer ones take 6 to 7.
	ipsetProtocol = 6

	ipsetAttrProtocol = 1
	ipsetAttrSetname  = 2
	ipsetAttrData     = 7
	ipsetAttrIP       = 1
	ipsetAttrTimeout  = 6
	ipsetAttrIPv4     = 1
	ipsetAttrIPv6     = 2
)

// Sets adds the addresses HyRouter's DNS learns to the rules' ipsets
// through netlink, as the nftables table's sets (nft.Sets): the same set
// names with SetPrefix. An address already in a set gets its new timeout
// (ipset's -exist), so the refresh needs no delete.
type Sets struct {
	mu   sync.Mutex
	conn *netlink.Conn
	// v6: the IPv6 sets exist (the kernel has IPv6).
	v6 bool
}

// OpenSets opens the netlink connection; Close ends it.
func OpenSets() (*Sets, error) {
	c, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, fmt.Errorf("ipset: %w", err)
	}
	return &Sets{conn: c, v6: HaveIPv6()}, nil
}

// Close closes the netlink connection.
func (s *Sets) Close() error { return s.conn.Close() }

// Apply adds add with their timeouts; del (refreshed addresses, always in
// add too) needs nothing. The first error is returned after every element
// was tried.
func (s *Sets) Apply(del, add []nft.Elem) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var first error
	for _, e := range add {
		a := e.Addr.Unmap()
		if a.Is6() && !s.v6 {
			continue
		}
		if err := s.add(SetName(e.Set), a.AsSlice(), e.Timeout); err != nil && first == nil {
			first = fmt.Errorf("ipset %s: %w", SetName(e.Set), err)
		}
	}
	return first
}

func (s *Sets) add(set string, addr []byte, timeout time.Duration) error {
	secs := uint32(max(timeout/time.Second, 1))
	fam := byte(unix.AF_INET)
	typ := uint16(ipsetAttrIPv4)
	if len(addr) == 16 {
		fam, typ = unix.AF_INET6, ipsetAttrIPv6
	} else if len(addr) != 4 {
		return errors.New("неверный адрес")
	}
	ae := netlink.NewAttributeEncoder()
	ae.Uint8(ipsetAttrProtocol, ipsetProtocol)
	ae.String(ipsetAttrSetname, set)
	ae.Nested(ipsetAttrData, func(d *netlink.AttributeEncoder) error {
		d.Nested(ipsetAttrIP, func(ip *netlink.AttributeEncoder) error {
			ip.Bytes(typ|netlink.NetByteOrder, addr)
			return nil
		})
		var t [4]byte
		binary.BigEndian.PutUint32(t[:], secs)
		d.Bytes(ipsetAttrTimeout|netlink.NetByteOrder, t[:])
		return nil
	})
	attrs, err := ae.Encode()
	if err != nil {
		return err
	}
	// struct nfgenmsg: family, version (NFNETLINK_V0), res_id.
	data := append([]byte{fam, 0, 0, 0}, attrs...)
	_, err = s.conn.Execute(netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(nfnlSubsysIPSet<<8 | ipsetCmdAdd), Flags: netlink.Request | netlink.Acknowledge},
		Data:   data,
	})
	return err
}
