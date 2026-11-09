package nft

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/zilbergsp/hyrouter/internal/rules"
)

// skip4 and skip6 are the destinations HyRouter never touches: the local
// and private networks, link-local, multicast and reserved ranges. The
// router's own addresses and broadcasts are left by fib.
var (
	skip4 = []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3"}
	skip6 = []string{"::/127", "::ffff:0:0/96", "fc00::/7", "fe80::/10", "ff00::/8"}
)

// webPorts are the TCP ports whose site name the relay can read.
const webPorts = "{ 80, 443, 8080, 8443 }"

// Compile returns the nftables script that replaces HyRouter's table in
// one transaction (nft -f): the rules of plan in order, then the default
// route def.
func Compile(plan []rules.PlanRule, def rules.Result, o Options) (string, error) {
	if len(o.LAN) == 0 {
		return "", errors.New("nft: no LAN interface")
	}
	for _, n := range o.LAN {
		if !validIface(n) {
			return "", fmt.Errorf("nft: bad interface name %q", n)
		}
	}
	if o.TunnelPort == 0 || o.NamePort == 0 || o.DNSPort == 0 {
		return "", errors.New("nft: a relay or DNS port is not set")
	}
	var sets, lines strings.Builder
	set := func(name, typ string, elems []string, interval bool) {
		fmt.Fprintf(&sets, "\tset %s {\n\t\ttype %s\n", name, typ)
		if interval {
			sets.WriteString("\t\tflags interval\n\t\tauto-merge\n")
		}
		if len(elems) > 0 {
			fmt.Fprintf(&sets, "\t\telements = { %s }\n", strings.Join(elems, ", "))
		}
		sets.WriteString("\t}\n")
	}
	timeoutSet := func(name, typ string) {
		fmt.Fprintf(&sets, "\tset %s {\n\t\ttype %s\n\t\tflags timeout\n\t}\n", name, typ)
	}
	set("skip4", "ipv4_addr", skip4, true)
	set("skip6", "ipv6_addr", skip6, true)
	timeoutSet(AmbigSet(false), "ipv4_addr")
	timeoutSet(AmbigSet(true), "ipv6_addr")

	ambig := false
	for _, r := range plan {
		if r.Never {
			continue
		}
		var devs []alt
		if r.Devices {
			if len(r.MACs) > 0 {
				name := fmt.Sprintf("r%d_mac", r.Pos)
				set(name, "ether_addr", macs(r.MACs), false)
				devs = append(devs, alt{"ether saddr @" + name, 0})
			}
			v4, v6 := prefixes(r.Sources)
			if len(v4) > 0 {
				set(setName(r.Pos, "src", false), "ipv4_addr", v4, true)
				devs = append(devs, alt{"ip saddr @" + setName(r.Pos, "src", false), 4})
			}
			if len(v6) > 0 {
				set(setName(r.Pos, "src", true), "ipv6_addr", v6, true)
				devs = append(devs, alt{"ip6 saddr @" + setName(r.Pos, "src", true), 6})
			}
		} else {
			devs = []alt{{}}
		}
		dests := []alt{{}}
		if r.Dest {
			dests = nil
			v4, v6 := prefixes(r.Nets)
			if len(v4) > 0 {
				set(setName(r.Pos, "net", false), "ipv4_addr", v4, true)
				dests = append(dests, alt{"ip daddr @" + setName(r.Pos, "net", false), 4})
			}
			if len(v6) > 0 {
				set(setName(r.Pos, "net", true), "ipv6_addr", v6, true)
				dests = append(dests, alt{"ip6 daddr @" + setName(r.Pos, "net", true), 6})
			}
			if r.Sites {
				timeoutSet(DNSSet(r.Pos, false), "ipv4_addr")
				timeoutSet(DNSSet(r.Pos, true), "ipv6_addr")
				dests = append(dests, alt{"ip daddr @" + DNSSet(r.Pos, false), 4}, alt{"ip6 daddr @" + DNSSet(r.Pos, true), 6})
			}
		}
		if len(devs) == 0 || len(dests) == 0 {
			continue // matches nothing
		}
		if r.Sites && !ambig {
			// Above here no rule depends on a site: what the kernel decided
			// the relay would decide too.
			ambig = true
			fmt.Fprintf(&lines, "\t\tmeta l4proto tcp th dport %s ip daddr @%s goto v_name\n", webPorts, AmbigSet(false))
			fmt.Fprintf(&lines, "\t\tmeta l4proto tcp th dport %s ip6 daddr @%s goto v_name\n", webPorts, AmbigSet(true))
		}
		pp := protoPorts(r.Proto, r.Ports)
		verdict := verdictOf(r.Route)
		fmt.Fprintf(&lines, "\t\t# %s\n", comment(r.Name))
		for _, d := range devs {
			for _, x := range dests {
				// A source of one family never goes to an address of the
				// other (and nft refuses such a rule).
				if d.fam != 0 && x.fam != 0 && d.fam != x.fam {
					continue
				}
				lines.WriteString("\t\t" + join(d.expr, pp, x.expr, verdict) + "\n")
			}
		}
	}
	fmt.Fprintf(&lines, "\t\t# Всё остальное\n\t\t%s\n", verdictOf(def))

	lan := quoteJoin(o.LAN)
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	w("table inet %s", Table)
	w("delete table inet %s", Table)
	w("table inet %s {", Table)
	b.WriteString(sets.String())
	w("\tchain prerouting_lan {")
	w("\t\ttype filter hook prerouting priority -151; policy accept;")
	w("\t\tiifname != { %s } return", lan)
	w("\t\tct mark & 0x%08x == 0x%08x return", CTMask, CTDirect)
	w("\t\tct mark & 0x%08x == 0x%08x goto to_tunnel", CTMask, CTTunnel)
	w("\t\tct mark & 0x%08x == 0x%08x goto to_name", CTMask, CTName)
	w("\t\tct mark & 0x%08x == 0x%08x return", CTMask, CTBlock)
	w("\t\tct state != new return")
	w("\t\tfib daddr type { local, broadcast, multicast, anycast } return")
	w("\t\tip daddr @skip4 return")
	w("\t\tip6 daddr @skip6 return")
	b.WriteString(lines.String())
	w("\t}")
	for _, v := range []struct {
		name string
		mark int
		then string
	}{{"v_direct", CTDirect, ""}, {"v_tunnel", CTTunnel, "goto to_tunnel"}, {"v_name", CTName, "goto to_name"}, {"v_block", CTBlock, ""}} {
		w("\tchain %s {", v.name)
		w("\t\tct mark set ct mark & 0x%08x | 0x%08x", ^uint32(CTMask), v.mark)
		if v.then != "" {
			w("\t\t%s", v.then)
		}
		w("\t}")
	}
	tproxy := func(proto string, port uint16) {
		w("\t\tmeta l4proto %s tproxy to :%d meta mark set meta mark | 0x%08x accept", proto, port, MarkTProxy)
	}
	w("\tchain to_tunnel {")
	tproxy("tcp", o.TunnelPort)
	tproxy("udp", o.TunnelPort)
	w("\t\tdrop")
	w("\t}")
	w("\tchain to_name {")
	tproxy("tcp", o.NamePort)
	w("\t\tdrop")
	w("\t}")
	// Blocked connections are reset where they are forwarded: reject is
	// not allowed in prerouting.
	w("\tchain forward_block {")
	w("\t\ttype filter hook forward priority -1; policy accept;")
	w("\t\tct mark & 0x%08x == 0x%08x meta l4proto tcp reject with tcp reset", CTMask, CTBlock)
	w("\t\tct mark & 0x%08x == 0x%08x drop", CTMask, CTBlock)
	w("\t}")
	// DNS queries of the LAN to the router go to HyRouter's DNS.
	w("\tchain dns_redirect {")
	w("\t\ttype nat hook prerouting priority -105; policy accept;")
	w("\t\tiifname != { %s } return", lan)
	w("\t\tfib daddr type local meta l4proto { tcp, udp } th dport 53 redirect to :%d", o.DNSPort)
	w("\t}")
	if o.Extra != "" {
		b.WriteString(strings.TrimRight(o.Extra, "\n") + "\n")
	}
	w("}")
	return b.String(), nil
}

// alt is one alternative of a rule's condition: a match on the source or
// the destination, of the address family fam (0 = either).
type alt struct {
	expr string
	fam  int
}

// verdictOf is the jump for a route. A tunnel without a server is
// refused, as in HyRoute: it never goes direct.
func verdictOf(r rules.Result) string {
	switch {
	case r.Action == rules.Direct:
		return "goto v_direct"
	case r.Action == rules.Tunnel && r.Profile != "":
		return "goto v_tunnel"
	}
	return "goto v_block"
}

func protoPorts(proto uint8, ports []rules.PortRange) string {
	var l4 string
	switch proto {
	case 6:
		l4 = "meta l4proto tcp"
	case 17:
		l4 = "meta l4proto udp"
	default:
		if len(ports) == 0 {
			return ""
		}
		l4 = "meta l4proto { tcp, udp }"
	}
	if len(ports) == 0 {
		return l4
	}
	items := make([]string, 0, len(ports))
	for _, p := range ports {
		if p.Lo == p.Hi {
			items = append(items, strconv.Itoa(int(p.Lo)))
		} else {
			items = append(items, fmt.Sprintf("%d-%d", p.Lo, p.Hi))
		}
	}
	if len(items) == 1 {
		return l4 + " th dport " + items[0]
	}
	return l4 + " th dport { " + strings.Join(items, ", ") + " }"
}

func macs(ms []rules.MAC) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		if s := m.String(); !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// prefixes splits prefixes by family in nft's notation.
func prefixes(ps []netip.Prefix) (v4, v6 []string) {
	for _, p := range ps {
		if !p.IsValid() {
			continue
		}
		a := p.Addr()
		if a.Is4In6() {
			bits := p.Bits() - 96
			if bits < 0 {
				continue
			}
			p = netip.PrefixFrom(a.Unmap(), bits)
		}
		p = p.Masked()
		s := p.String()
		if p.IsSingleIP() {
			s = p.Addr().String()
		}
		if p.Addr().Is4() {
			v4 = append(v4, s)
		} else {
			v6 = append(v6, s)
		}
	}
	return v4, v6
}

func join(parts ...string) string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, " ")
}

func quoteJoin(names []string) string {
	q := make([]string, 0, len(names))
	for _, n := range names {
		q = append(q, strconv.Quote(n))
	}
	return strings.Join(q, ", ")
}

// comment makes a rule name safe for a comment line of the script.
func comment(s string) string {
	return strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}
