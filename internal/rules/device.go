package rules

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
)

// HyRouter: rules by LAN device. Rule.Devices lists the devices a rule
// applies to (empty = any device), joined with the other conditions by
// "and", as Apps are on HyRoute. An item is
//   - a MAC address: "aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF" or
//     "aabbccddeeff";
//   - an address or a network of the device: "192.168.1.20",
//     "192.168.1.16/28", "fd00::20";
//   - "dev:<id>": a device of the table given to SetDevices, with the MAC
//     and addresses it has when the rules are compiled.
//
// The router always knows where a connection comes from, so the
// condition is decided at packet level, like the protocol and ports. A
// rule with device items matches nothing from a source it cannot tell
// (Subject without MAC and address), and a "dev:" item of a device that is
// not in the table matches nothing (a warning, as a missing geosite:
// category): such a rule never widens to every device.

// DevicePrefix starts an item that names a device of the table.
const DevicePrefix = "dev:"

// MAC is a 48-bit hardware address; the zero value means unknown.
type MAC [6]byte

// IsZero reports whether m is the zero (unknown) address.
func (m MAC) IsZero() bool { return m == MAC{} }

// String is the canonical form: lower case, colon separated.
func (m MAC) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

// ParseMAC reads a MAC address written as six pairs of hex digits
// separated by ":" or "-", or as twelve hex digits. The zero address is
// refused.
func ParseMAC(s string) (MAC, error) {
	t := strings.TrimSpace(s)
	bad := fmt.Errorf("неверный MAC-адрес %q", s)
	var hex string
	switch len(t) {
	case 12:
		hex = t
	case 17:
		sep := t[2]
		if sep != ':' && sep != '-' {
			return MAC{}, bad
		}
		var b strings.Builder
		for i := 0; i < len(t); i++ {
			if i%3 == 2 {
				if t[i] != sep {
					return MAC{}, bad
				}
				continue
			}
			b.WriteByte(t[i])
		}
		hex = b.String()
	default:
		return MAC{}, bad
	}
	var m MAC
	for i := range m {
		hi, ok1 := unhexDigit(hex[2*i])
		lo, ok2 := unhexDigit(hex[2*i+1])
		if !ok1 || !ok2 {
			return MAC{}, bad
		}
		m[i] = hi<<4 | lo
	}
	if m.IsZero() {
		return MAC{}, bad
	}
	return m, nil
}

func unhexDigit(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// DeviceAddrs is how a device of the table is recognized: any of its MAC
// addresses, or a source address within any of its prefixes.
type DeviceAddrs struct {
	MACs     []MAC
	Prefixes []netip.Prefix
}

// DeviceTable maps device IDs (the <id> of "dev:<id>") to their addresses.
type DeviceTable map[string]DeviceAddrs

var deviceTable atomic.Pointer[DeviceTable]

// SetDevices replaces the device table used by later compilations; the
// controller recompiles the rules after the table changes.
func SetDevices(t DeviceTable) { deviceTable.Store(&t) }

func currentDevices() DeviceTable {
	if p := deviceTable.Load(); p != nil {
		return *p
	}
	return nil
}

// devPat is one compiled device item.
type devPat struct {
	src  string
	key  string // canonical form for comparisons (devKeys)
	macs []MAC
	pfxs []netip.Prefix
}

// IsDeviceRef reports whether item names a device of the table.
func IsDeviceRef(item string) bool {
	s := strings.TrimSpace(item)
	return len(s) >= len(DevicePrefix) && strings.EqualFold(s[:len(DevicePrefix)], DevicePrefix)
}

// parseDevice compiles one device item against the table t. warn is set
// for a "dev:" item whose device is not in t: it matches nothing.
func parseDevice(item string, t DeviceTable) (d devPat, warn string, err error) {
	s := strings.TrimSpace(item)
	d.src = s
	if s == "" {
		return d, "", errors.New("пустое устройство")
	}
	if IsDeviceRef(s) {
		id := strings.TrimSpace(s[len(DevicePrefix):])
		if id == "" {
			return d, "", fmt.Errorf("неверное устройство %q", s)
		}
		d.key = "r|" + id
		a, ok := t[id]
		if !ok {
			return d, "устройство " + id + " не найдено: для него правило ничего не ловит", nil
		}
		d.macs = slices.Clone(a.MACs)
		for _, p := range a.Prefixes {
			if p.IsValid() {
				d.pfxs = append(d.pfxs, p.Masked())
			}
		}
		return d, "", nil
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		p = p.Masked()
		d.pfxs, d.key = []netip.Prefix{p}, "p|"+p.String()
		return d, "", nil
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap().WithZone("")
		p := netip.PrefixFrom(a, a.BitLen())
		d.pfxs, d.key = []netip.Prefix{p}, "p|"+p.String()
		return d, "", nil
	}
	m, err := ParseMAC(s)
	if err != nil {
		return d, "", fmt.Errorf("неверное устройство %q: нужен MAC-адрес, IP-адрес, подсеть или dev:<id>", s)
	}
	d.macs, d.key = []MAC{m}, "m|"+m.String()
	return d, "", nil
}

// compileDevices adds r's device items to cr.
func (cr *compiled) compileDevices(r Rule) error {
	t := currentDevices()
	for _, it := range r.Devices {
		d, warn, err := parseDevice(it, t)
		if err != nil {
			return fmt.Errorf("%s: %v", cr.name, err)
		}
		if warn != "" {
			cr.warns = append(cr.warns, warn)
		}
		cr.devs = append(cr.devs, d)
	}
	return nil
}

func (d *devPat) match(sub Subject) bool {
	if !sub.MAC.IsZero() && slices.Contains(d.macs, sub.MAC) {
		return true
	}
	if src := sub.Src.Unmap(); src.IsValid() {
		for _, p := range d.pfxs {
			if p.Contains(src) {
				return true
			}
		}
	}
	return false
}

func (r *compiled) hasDev() bool { return len(r.devs) > 0 }

// matchDevice reports whether a device item matches sub's source (true for
// a rule without device items).
func (r *compiled) matchDevice(sub Subject) bool {
	if !r.hasDev() {
		return true
	}
	for i := range r.devs {
		if r.devs[i].match(sub) {
			return true
		}
	}
	return false
}

// deviceKnown reports whether sub tells its device: a MAC or a source
// address.
func (sub Subject) deviceKnown() bool { return !sub.MAC.IsZero() || sub.Src.IsValid() }

func (r *compiled) devKeys() []string {
	out := make([]string, 0, len(r.devs))
	for _, d := range r.devs {
		out = append(out, d.key)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// devsOverlap reports whether some source may match both device items. A
// MAC against an address cannot be told apart without the device table:
// they may be the same device.
func devsOverlap(x, y *devPat) bool {
	if (len(x.macs) > 0 && len(y.pfxs) > 0) || (len(x.pfxs) > 0 && len(y.macs) > 0) {
		return true
	}
	for _, m := range x.macs {
		if slices.Contains(y.macs, m) {
			return true
		}
	}
	for _, p := range x.pfxs {
		for _, q := range y.pfxs {
			if p.Overlaps(q) {
				return true
			}
		}
	}
	return false
}

// coversDevices reports whether every source matching b's device items
// also matches r's (r has device items). Conservative: a MAC is covered
// only by the same MAC, an address only by a prefix containing it.
func (r *compiled) coversDevices(b *compiled) bool {
	if !b.hasDev() {
		return false
	}
	for i := range b.devs {
		if !r.coversDevice(&b.devs[i]) {
			return false
		}
	}
	return true
}

func (r *compiled) coversDevice(d *devPat) bool {
	if len(d.macs) == 0 && len(d.pfxs) == 0 {
		return true // matches nothing
	}
	for _, m := range d.macs {
		if !slices.ContainsFunc(r.devs, func(x devPat) bool { return slices.Contains(x.macs, m) }) {
			return false
		}
	}
	for _, p := range d.pfxs {
		in := func(x devPat) bool {
			return slices.ContainsFunc(x.pfxs, func(q netip.Prefix) bool {
				return q.Bits() <= p.Bits() && q.Contains(p.Addr())
			})
		}
		if !slices.ContainsFunc(r.devs, in) {
			return false
		}
	}
	return true
}

// explainDevice is the device step of Explain: ok when the rule has no
// device items or one matches sub.
func (r *compiled) explainDevice(sub Subject) (ok bool, why string) {
	if !r.hasDev() {
		return true, ""
	}
	list := make([]string, 0, len(r.devs))
	for _, d := range r.devs {
		list = append(list, d.src)
	}
	pats := strings.Join(list, ", ")
	if !sub.deviceKnown() {
		return false, "устройство не указано, а правило только для " + pats
	}
	for i := range r.devs {
		if r.devs[i].match(sub) {
			return true, "устройство " + r.devs[i].src
		}
	}
	return false, "устройство не из правила (" + pats + ")"
}

// DeviceSubject reads the device of an Explain query: a MAC address or
// an IP address ("" = not given).
func DeviceSubject(s string) (Subject, error) {
	var sub Subject
	s = strings.TrimSpace(s)
	if s == "" {
		return sub, nil
	}
	if a, err := netip.ParseAddr(s); err == nil {
		sub.Src = a.Unmap().WithZone("")
		return sub, nil
	}
	m, err := ParseMAC(s)
	if err != nil {
		return sub, fmt.Errorf("неверное устройство %q: нужен MAC-адрес или IP-адрес", s)
	}
	sub.MAC = m
	return sub, nil
}
