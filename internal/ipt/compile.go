package ipt

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/zilbergsp/hyrouter/internal/nft"
	"github.com/zilbergsp/hyrouter/internal/rules"
)

// skip4 and skip6 are the destinations HyRouter never touches: the local
// and private networks, link-local, multicast and reserved ranges (as in
// the nftables table). The router's own addresses and broadcasts are left
// by addrtype.
var (
	skip4 = []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3"}
	skip6 = []string{"::/127", "::ffff:0:0/96", "fc00::/7", "fe80::/10", "ff00::/8"}
)

// webPorts are the TCP ports whose site name the relay can read.
const webPorts = "80,443,8080,8443"

// Chains of the routing.
const (
	chPre    = "HYR_PRE"
	chLAN    = "HYR_LAN"
	chDirect = "HYR_V_DIRECT"
	chTunnel = "HYR_V_TUNNEL"
	chName   = "HYR_V_NAME"
	chBlock  = "HYR_V_BLOCK"
	chToTun  = "HYR_TUNNEL"
	chToName = "HYR_NAME"
	chDNS    = "HYR_DNS"
	chFwd    = "HYR_FWD"
	chIn     = "HYR_IN"
)

// SetName is the ipset of a DNS set of the nftables table (nft.DNSSet,
// nft.AmbigSet): the names HyRouter's DNS writes stay the same.
func SetName(nftSet string) string { return SetPrefix + nftSet }

// Compile returns the rules of plan in order, then the default route
// def, for IPv4 and IPv6 (v6 false: IPv4 only).
func Compile(plan []rules.PlanRule, def rules.Result, o Options, v6 bool) (*Part, error) {
	if err := checkIfaces(o.LAN, "LAN"); err != nil {
		return nil, err
	}
	if o.TunnelPort == 0 || o.NamePort == 0 || o.DNSPort == 0 {
		return nil, errors.New("ipt: не задан порт relay или DNS")
	}
	fams := []int{4}
	if v6 {
		fams = append(fams, 6)
	}
	p := &Part{}
	set := func(name string, fam int, net, timeout bool, elems []string) {
		p.Sets = append(p.Sets, Set{Name: name, Family: fam, Net: net, Timeout: timeout, Elems: elems})
	}
	set("skip4", 4, true, false, skip4)
	if v6 {
		set("skip6", 6, true, false, skip6)
	}
	set(nft.AmbigSet(false), 4, false, true, nil)
	if v6 {
		set(nft.AmbigSet(true), 6, false, true, nil)
	}
	for _, fam := range fams {
		for _, c := range []string{chPre, chLAN, chDirect, chTunnel, chName, chBlock, chToTun, chToName} {
			p.chain(fam, "mangle", c)
		}
		p.hook(fam, "mangle", "PREROUTING", chPre)
		for _, n := range o.LAN {
			p.rule(fam, "mangle", "-A %s -i %s -g %s", chPre, n, chLAN)
		}
		skip := "skip4"
		if fam == 6 {
			skip = "skip6"
		}
		p.rule(fam, "mangle", "-A %s %s -j RETURN", chLAN, markMatch(CTDirect))
		p.rule(fam, "mangle", "-A %s %s -g %s", chLAN, markMatch(CTTunnel), chToTun)
		p.rule(fam, "mangle", "-A %s %s -g %s", chLAN, markMatch(CTName), chToName)
		p.rule(fam, "mangle", "-A %s %s -j RETURN", chLAN, markMatch(CTBlock))
		p.rule(fam, "mangle", "-A %s -m conntrack ! --ctstate NEW -j RETURN", chLAN)
		// IPv6 has no broadcast, and addrtype refuses to match it there.
		types := "LOCAL,BROADCAST,MULTICAST,ANYCAST"
		if fam == 6 {
			types = "LOCAL,MULTICAST,ANYCAST"
		}
		p.rule(fam, "mangle", "-A %s -m addrtype --dst-type %s -j RETURN", chLAN, types)
		p.rule(fam, "mangle", "-A %s -m set --match-set %s dst -j RETURN", chLAN, SetPrefix+skip)
	}

	ambig := false
	for _, r := range plan {
		if r.Never {
			continue
		}
		var devs []alt
		if r.Devices {
			for _, m := range macs(r.MACs) {
				devs = append(devs, alt{"-m mac --mac-source " + m, 0})
			}
			s4, s6 := prefixes(r.Sources)
			if len(s4) > 0 {
				name := ruleSet(r.Pos, "src", false)
				set(name, 4, true, false, s4)
				devs = append(devs, alt{"-m set --match-set " + SetPrefix + name + " src", 4})
			}
			if len(s6) > 0 && v6 {
				name := ruleSet(r.Pos, "src", true)
				set(name, 6, true, false, s6)
				devs = append(devs, alt{"-m set --match-set " + SetPrefix + name + " src", 6})
			}
		} else {
			devs = []alt{{}}
		}
		dests := []alt{{}}
		if r.Dest {
			dests = nil
			n4, n6 := prefixes(r.Nets)
			if len(n4) > 0 {
				name := ruleSet(r.Pos, "net", false)
				set(name, 4, true, false, n4)
				dests = append(dests, alt{"-m set --match-set " + SetPrefix + name + " dst", 4})
			}
			if len(n6) > 0 && v6 {
				name := ruleSet(r.Pos, "net", true)
				set(name, 6, true, false, n6)
				dests = append(dests, alt{"-m set --match-set " + SetPrefix + name + " dst", 6})
			}
			if r.Sites {
				set(nft.DNSSet(r.Pos, false), 4, false, true, nil)
				dests = append(dests, alt{"-m set --match-set " + SetName(nft.DNSSet(r.Pos, false)) + " dst", 4})
				if v6 {
					set(nft.DNSSet(r.Pos, true), 6, false, true, nil)
					dests = append(dests, alt{"-m set --match-set " + SetName(nft.DNSSet(r.Pos, true)) + " dst", 6})
				}
			}
		}
		if len(devs) == 0 || len(dests) == 0 {
			continue // matches nothing
		}
		if r.Sites && !ambig {
			// Above here no rule depends on a site: what the kernel decided
			// the relay would decide too.
			ambig = true
			for _, fam := range fams {
				p.rule(fam, "mangle", "-A %s -p tcp -m multiport --dports %s -m set --match-set %s dst -g %s",
					chLAN, webPorts, SetName(nft.AmbigSet(fam == 6)), chName)
			}
		}
		pps, err := protoPorts(r.Proto, r.Ports)
		if err != nil {
			return nil, fmt.Errorf("«%s»: %w", r.Name, err)
		}
		verdict := verdictOf(r.Route)
		for _, fam := range fams {
			var lines []string
			for _, d := range devs {
				for _, x := range dests {
					if d.fam != 0 && d.fam != fam || x.fam != 0 && x.fam != fam {
						continue
					}
					for _, pp := range pps {
						lines = append(lines, "-A "+join(chLAN, d.expr, x.expr, pp, verdict))
					}
				}
			}
			if len(lines) > 0 {
				p.rule(fam, "mangle", "# %s", comment(r.Name))
				t := p.table(fam, "mangle")
				t.Rules = append(t.Rules, lines...)
			}
		}
	}
	for _, fam := range fams {
		p.rule(fam, "mangle", "# Всё остальное")
		p.rule(fam, "mangle", "-A %s %s", chLAN, verdictOf(def))

		for _, v := range []struct {
			chain string
			mark  uint32
			then  string
		}{{chDirect, CTDirect, ""}, {chTunnel, CTTunnel, chToTun}, {chName, CTName, chToName}, {chBlock, CTBlock, ""}} {
			p.rule(fam, "mangle", "-A %s -j CONNMARK --set-xmark %s/%s", v.chain, hexMark(v.mark), hexMark(CTMask))
			if v.then != "" {
				p.rule(fam, "mangle", "-A %s -g %s", v.chain, v.then)
			}
		}
		tproxy := func(chain, proto string, port uint16) {
			p.rule(fam, "mangle", "-A %s -p %s -j TPROXY --on-port %d --tproxy-mark %s/%s", chain, proto, port, hexMark(MarkTProxy), hexMark(MarkTProxy))
		}
		tproxy(chToTun, "tcp", o.TunnelPort)
		tproxy(chToTun, "udp", o.TunnelPort)
		p.rule(fam, "mangle", "-A %s -j DROP", chToTun)
		tproxy(chToName, "tcp", o.NamePort)
		p.rule(fam, "mangle", "-A %s -j DROP", chToName)

		// DNS queries of the LAN to the router go to HyRouter's DNS.
		p.chain(fam, "nat", chDNS)
		p.hook(fam, "nat", "PREROUTING", chDNS)
		for _, n := range o.LAN {
			for _, proto := range []string{"udp", "tcp"} {
				p.rule(fam, "nat", "-A %s -i %s -m addrtype --dst-type LOCAL -p %s --dport 53 -j REDIRECT --to-ports %d", chDNS, n, proto, o.DNSPort)
			}
		}

		// Blocked connections are reset where they are forwarded; a
		// connection of the relay is never forwarded (were the policy
		// routing gone, it would go direct).
		p.chain(fam, "filter", chFwd)
		p.hook(fam, "filter", "FORWARD", chFwd)
		p.rule(fam, "filter", "-A %s %s -p tcp -j REJECT --reject-with tcp-reset", chFwd, markMatch(CTBlock))
		for _, m := range []uint32{CTBlock, CTTunnel, CTName} {
			p.rule(fam, "filter", "-A %s %s -j DROP", chFwd, markMatch(m))
		}
		// The firmware's input rules may refuse what a guest segment sends
		// the router: the relay's packets and the DNS redirected to
		// HyRouter come in.
		p.chain(fam, "filter", chIn)
		p.hook(fam, "filter", "INPUT", chIn)
		p.rule(fam, "filter", "-A %s -m mark --mark %s/%s -j ACCEPT", chIn, hexMark(MarkTProxy), hexMark(MarkTProxy))
		for _, n := range o.LAN {
			for _, proto := range []string{"udp", "tcp"} {
				p.rule(fam, "filter", "-A %s -i %s -p %s --dport %d -j ACCEPT", chIn, n, proto, o.DNSPort)
			}
		}
	}
	return p, nil
}

// DNS6Fallback are the rules for IPv6 when the router has no IPv6 NAT
// (ip6table_nat): the LAN's IPv6 DNS queries to the router are refused,
// so devices ask over IPv4, where HyRouter's DNS answers.
func DNS6Fallback(lan []string) []string {
	var out []string
	for _, n := range lan {
		out = append(out,
			fmt.Sprintf("-A %s -i %s -m addrtype --dst-type LOCAL -p udp --dport 53 -j REJECT", chIn, n),
			fmt.Sprintf("-A %s -i %s -m addrtype --dst-type LOCAL -p tcp --dport 53 -j REJECT --reject-with tcp-reset", chIn, n))
	}
	return out
}

// Closed6 are the rules for IPv6 when its routing could not be loaded
// (no ip6table_mangle): the LAN's IPv6 connections beyond the router are
// refused, so devices use IPv4, which HyRouter routes. VPN traffic never
// goes direct.
func Closed6(lan []string) []string {
	var out []string
	for _, n := range lan {
		out = append(out, fmt.Sprintf("-A %s -i %s -j REJECT", chFwd, n))
	}
	return out
}

// alt is one alternative of a rule's condition: a match on the source or
// the destination, of the address family fam (0 = either).
type alt struct {
	expr string
	fam  int
}

func ruleSet(pos int, kind string, v6 bool) string {
	fam := 4
	if v6 {
		fam = 6
	}
	return fmt.Sprintf("r%d_%s%d", pos, kind, fam)
}

// verdictOf is the jump for a route. A tunnel without a server is
// refused, as in HyRoute: it never goes direct.
func verdictOf(r rules.Result) string {
	switch {
	case r.Action == rules.Direct:
		return "-g " + chDirect
	case r.Action == rules.Tunnel && r.Profile != "":
		return "-g " + chTunnel
	}
	return "-g " + chBlock
}

// protoPorts are the protocol and port matches of a rule: one or more
// alternatives ("" = any).
func protoPorts(proto uint8, ports []rules.PortRange) ([]string, error) {
	var protos []string
	switch proto {
	case 6:
		protos = []string{"tcp"}
	case 17:
		protos = []string{"udp"}
	default:
		if len(ports) == 0 {
			return []string{""}, nil
		}
		protos = []string{"tcp", "udp"}
	}
	if len(ports) == 0 {
		out := make([]string, 0, len(protos))
		for _, pr := range protos {
			out = append(out, "-p "+pr)
		}
		return out, nil
	}
	items := make([]string, 0, len(ports))
	for _, pr := range ports {
		if pr.Lo == pr.Hi {
			items = append(items, strconv.Itoa(int(pr.Lo)))
		} else {
			items = append(items, fmt.Sprintf("%d-%d", pr.Lo, pr.Hi))
		}
	}
	lists, err := Ports(items)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, pr := range protos {
		for _, l := range lists {
			out = append(out, dport(pr, l, false))
		}
	}
	return out, nil
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

// prefixes splits prefixes by family as ipset writes them.
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
		if p.Bits() == 0 {
			// hash:net takes no /0: the two halves.
			half := "0.0.0.0/1"
			other := "128.0.0.0/1"
			if !p.Addr().Is4() {
				half, other = "::/1", "8000::/1"
			}
			if p.Addr().Is4() {
				v4 = append(v4, half, other)
			} else {
				v6 = append(v6, half, other)
			}
			continue
		}
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

// comment makes a rule name safe for a comment line.
func comment(s string) string {
	return strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// Guard is the kill switch while the router boots (OwnerGuard): the LAN
// reaches nothing beyond the router until HyRouter's rules are loaded.
// The router itself (its interfaces, DNS, DHCP) stays reachable.
func Guard(lan []string, v6 bool) (*Part, error) {
	if err := checkIfaces(lan, "LAN"); err != nil {
		return nil, err
	}
	p := &Part{}
	fams := []int{4}
	if v6 {
		fams = append(fams, 6)
	}
	for _, fam := range fams {
		ch := OwnerGuard + "FWD"
		p.chain(fam, "filter", ch)
		p.hook(fam, "filter", "FORWARD", ch)
		with := "icmp-admin-prohibited"
		if fam == 6 {
			with = "icmp6-adm-prohibited"
		}
		for _, n := range lan {
			p.rule(fam, "filter", "-A %s -i %s -j REJECT --reject-with %s", ch, n, with)
		}
	}
	return p, nil
}
