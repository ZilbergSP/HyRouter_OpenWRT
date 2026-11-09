//go:build linux

// Package kernel holds what hyrouterd sets and reads in the Linux kernel
// besides nftables: the policy routing that delivers the relay's packets
// to local sockets, and the neighbour table that tells devices by MAC.
package kernel

import (
	"errors"
	"fmt"
	"net"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// PolicyRouting is the routing for TPROXY: packets whose mark has Mark
// in Mask are looked up in Table, where a local default route of each
// family delivers them to the relay's sockets ("ip rule add fwmark
// Mark/Mask lookup Table" and "ip route add local default dev lo table
// Table").
type PolicyRouting struct {
	Mark     uint32
	Mask     uint32
	Table    uint32
	Priority uint32
}

// Install adds the rules and routes of IPv4 and IPv6, replacing what an
// earlier run left. A kernel without IPv6 gets the IPv4 ones only.
func (p PolicyRouting) Install() error {
	c, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return fmt.Errorf("netlink: %w", err)
	}
	defer c.Close()
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		return err
	}
	for _, fam := range []uint8{unix.AF_INET, unix.AF_INET6} {
		p.removeRules(c, fam)
		if err := p.rule(c, unix.RTM_NEWRULE, fam, netlink.Create|netlink.Excl); err != nil {
			if fam == unix.AF_INET6 && noFamily(err) {
				continue
			}
			return fmt.Errorf("ip rule (%s): %w", famName(fam), err)
		}
		if err := p.route(c, unix.RTM_NEWROUTE, fam, netlink.Create|netlink.Replace, lo.Index); err != nil {
			if fam == unix.AF_INET6 && noFamily(err) {
				continue
			}
			return fmt.Errorf("ip route (%s): %w", famName(fam), err)
		}
	}
	return nil
}

// Remove deletes the rules and routes; missing ones are no error.
func (p PolicyRouting) Remove() error {
	c, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return fmt.Errorf("netlink: %w", err)
	}
	defer c.Close()
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		return err
	}
	var errs []error
	for _, fam := range []uint8{unix.AF_INET, unix.AF_INET6} {
		p.removeRules(c, fam)
		err := p.route(c, unix.RTM_DELROUTE, fam, 0, lo.Index)
		if err != nil && !errors.Is(err, unix.ESRCH) && !errors.Is(err, unix.ENOENT) && !noFamily(err) {
			errs = append(errs, fmt.Errorf("ip route del (%s): %w", famName(fam), err))
		}
	}
	return errors.Join(errs...)
}

// removeRules deletes this rule of a family until none is left: a run
// that crashed may have left one.
func (p PolicyRouting) removeRules(c *netlink.Conn, fam uint8) {
	for range 16 {
		if p.rule(c, unix.RTM_DELRULE, fam, 0) != nil {
			return
		}
	}
}

func (p PolicyRouting) rule(c *netlink.Conn, typ uint16, fam uint8, flags netlink.HeaderFlags) error {
	// struct fib_rule_hdr: family, dst_len, src_len, tos, table, res1,
	// res2, action, flags (u32).
	hdr := []byte{fam, 0, 0, 0, unix.RT_TABLE_UNSPEC, 0, 0, unix.FR_ACT_TO_TBL, 0, 0, 0, 0}
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(unix.FRA_PRIORITY, p.Priority)
	ae.Uint32(unix.FRA_FWMARK, p.Mark)
	ae.Uint32(unix.FRA_FWMASK, p.Mask)
	ae.Uint32(unix.FRA_TABLE, p.Table)
	return execute(c, typ, flags, hdr, ae)
}

func (p PolicyRouting) route(c *netlink.Conn, typ uint16, fam uint8, flags netlink.HeaderFlags, lo int) error {
	// struct rtmsg: family, dst_len, src_len, tos, table, protocol, scope,
	// type, flags (u32). A default route: no RTA_DST.
	hdr := []byte{fam, 0, 0, 0, unix.RT_TABLE_UNSPEC, unix.RTPROT_BOOT, unix.RT_SCOPE_HOST, unix.RTN_LOCAL, 0, 0, 0, 0}
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(unix.RTA_TABLE, p.Table)
	ae.Uint32(unix.RTA_OIF, uint32(lo))
	return execute(c, typ, flags, hdr, ae)
}

func execute(c *netlink.Conn, typ uint16, flags netlink.HeaderFlags, hdr []byte, ae *netlink.AttributeEncoder) error {
	attrs, err := ae.Encode()
	if err != nil {
		return err
	}
	_, err = c.Execute(netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(typ), Flags: netlink.Request | netlink.Acknowledge | flags},
		Data:   append(hdr, attrs...),
	})
	return err
}

// noFamily: the kernel has no such address family (IPv6 turned off).
func noFamily(err error) bool {
	return errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EOPNOTSUPP)
}

func famName(fam uint8) string {
	if fam == unix.AF_INET6 {
		return "IPv6"
	}
	return "IPv4"
}
