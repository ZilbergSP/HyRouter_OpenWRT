// Package ipt builds HyRouter's rules for iptables and ipset, the
// firewall of KeeneticOS (docs/ARCHITECTURE.md, «Кинетик»). It makes the
// decisions of the nftables table (internal/nft) with iptables: the
// kernel decides each new connection from the LAN by its device,
// protocol, port and destination and keeps the decision in the
// connection mark; a site is matched by the addresses its names resolved
// to, which HyRouter's DNS adds to ipsets with a timeout (Sets).
//
// The rules live in HyRouter's own chains (HYR_…), entered by one jump
// from each built-in chain they need, kept first. KeeneticOS rebuilds its
// tables when a connection changes and drops other rules with them: the
// chains are also written to files the firmware's netfilter.d hook loads
// again (build/keenetic), and Heal puts back what is missing.
package ipt

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Connection marks. KeeneticOS's own policies mark packets in the low 28
// bits, so HyRouter takes the high ones (as nfqws-keenetic does): bits
// 28-30 of the connection mark hold the route, bit 31 of the packet mark
// sends a packet to the relay. zapret's marks (0x20000000, 0x40000000) are
// packet marks of nfqws2's own packets.
const (
	CTMask   = 0x70000000
	CTDirect = 0x10000000
	CTTunnel = 0x20000000
	CTName   = 0x30000000
	CTBlock  = 0x40000000
	// MarkTProxy marks the packets for the relay; policy routing
	// (RouteTable at RulePriority, before the firmware's rules) delivers
	// them to the local socket.
	MarkTProxy   = 0x80000000
	RouteTable   = 7701
	RulePriority = 50
)

// Prefixes of what HyRouter owns: the routing chains, the boot guard's
// chains, and the ipsets.
const (
	OwnerRoute = "HYR_"
	OwnerGuard = "HYRG_"
	SetPrefix  = "hyr_"
)

// Options are the router's side of the rules.
type Options struct {
	// LAN are the interfaces whose traffic HyRouter decides (br0).
	LAN []string
	// TunnelPort and NamePort are the relay's TPROXY ports, DNSPort the
	// port of HyRouter's DNS.
	TunnelPort uint16
	NamePort   uint16
	DNSPort    uint16
}

// Part is a piece of the rules: ipsets, and per family and table the
// chains (created, or emptied when they are there), their rules and the
// jumps from the built-in chains.
type Part struct {
	Sets   []Set   `json:"sets,omitempty"`
	Tables []Table `json:"tables,omitempty"`
}

// Table is a family's table in a Part.
type Table struct {
	// Family is 4 (iptables) or 6 (ip6tables).
	Family int `json:"family"`
	// Name is mangle, nat or filter.
	Name   string   `json:"name"`
	Chains []string `json:"chains,omitempty"`
	// Rules are iptables-restore lines: "-A CHAIN …", or "# …".
	Rules []string `json:"rules,omitempty"`
	Hooks []Hook   `json:"hooks,omitempty"`
}

// Hook is the jump from a built-in chain (PREROUTING) to HyRouter's.
type Hook struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// Set is an ipset. Name is without SetPrefix.
type Set struct {
	Name string `json:"name"`
	// Net: hash:net (prefixes), else hash:ip.
	Net bool `json:"net,omitempty"`
	// Family is 4 or 6.
	Family int `json:"family"`
	// Timeout: the addresses of sites from DNS, each with its own time;
	// such a set is emptied when the rules are loaded again.
	Timeout bool     `json:"timeout,omitempty"`
	Elems   []string `json:"elems,omitempty"`
}

// FullName is the set's name in the kernel.
func (s Set) FullName() string { return SetPrefix + s.Name }

// table returns the part's table of a family, added when it is not there.
func (p *Part) table(fam int, name string) *Table {
	for i := range p.Tables {
		if p.Tables[i].Family == fam && p.Tables[i].Name == name {
			return &p.Tables[i]
		}
	}
	p.Tables = append(p.Tables, Table{Family: fam, Name: name})
	return &p.Tables[len(p.Tables)-1]
}

// chain declares a chain of a family's table.
func (p *Part) chain(fam int, table, name string) {
	t := p.table(fam, table)
	if !slices.Contains(t.Chains, name) {
		t.Chains = append(t.Chains, name)
	}
}

// rule adds a rule; the chain must be declared.
func (p *Part) rule(fam int, table, format string, a ...any) {
	t := p.table(fam, table)
	t.Rules = append(t.Rules, fmt.Sprintf(format, a...))
}

// hook adds a jump from a built-in chain.
func (p *Part) hook(fam int, table, from, to string) {
	t := p.table(fam, table)
	h := Hook{From: from, To: to}
	if !slices.Contains(t.Hooks, h) {
		t.Hooks = append(t.Hooks, h)
	}
}

// Merge adds another part (the DPI bypass's) to p.
func (p *Part) Merge(o Part) {
	p.Sets = append(p.Sets, o.Sets...)
	for _, t := range o.Tables {
		pt := p.table(t.Family, t.Name)
		for _, c := range t.Chains {
			if !slices.Contains(pt.Chains, c) {
				pt.Chains = append(pt.Chains, c)
			}
		}
		pt.Rules = append(pt.Rules, t.Rules...)
		for _, h := range t.Hooks {
			if !slices.Contains(pt.Hooks, h) {
				pt.Hooks = append(pt.Hooks, h)
			}
		}
	}
}

// Families reports the families a part has tables of.
func (p *Part) Families() []int {
	var out []int
	for _, t := range p.Tables {
		if !slices.Contains(out, t.Family) {
			out = append(out, t.Family)
		}
	}
	slices.Sort(out)
	return out
}

// Check rejects a part whose chains, rules or sets are not HyRouter's or
// could reach iptables as anything but one line.
func (p *Part) Check(owner string) error {
	for _, s := range p.Sets {
		if !validName(s.Name) || len(s.FullName()) > 31 || s.Family != 4 && s.Family != 6 {
			return fmt.Errorf("ipt: неверный набор %q", s.Name)
		}
		for _, e := range s.Elems {
			if !validElem(e) {
				return fmt.Errorf("ipt: неверный элемент набора %s: %q", s.Name, e)
			}
		}
	}
	for _, t := range p.Tables {
		if t.Family != 4 && t.Family != 6 || !slices.Contains([]string{"mangle", "nat", "filter"}, t.Name) {
			return fmt.Errorf("ipt: неверная таблица %d/%s", t.Family, t.Name)
		}
		for _, c := range t.Chains {
			if !strings.HasPrefix(c, owner) || !validName(c) || len(c) > 28 {
				return fmt.Errorf("ipt: неверная цепочка %q", c)
			}
		}
		for _, r := range t.Rules {
			if strings.ContainsAny(r, "\n\r\x00") {
				return fmt.Errorf("ipt: правило в несколько строк: %q", r)
			}
			if !strings.HasPrefix(r, "# ") && !strings.HasPrefix(r, "-A "+owner) {
				return fmt.Errorf("ipt: правило не в своей цепочке: %q", r)
			}
		}
		for _, h := range t.Hooks {
			if !builtin(t.Name, h.From) || !slices.Contains(t.Chains, h.To) {
				return fmt.Errorf("ipt: неверный переход %s → %s", h.From, h.To)
			}
		}
	}
	return nil
}

// builtin: a built-in chain of the table.
func builtin(table, chain string) bool {
	switch table {
	case "mangle":
		return slices.Contains([]string{"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"}, chain)
	case "nat":
		return slices.Contains([]string{"PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"}, chain)
	case "filter":
		return slices.Contains([]string{"INPUT", "FORWARD", "OUTPUT"}, chain)
	}
	return false
}

// validName: letters, digits and _ (chain and set names).
func validName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_'
		if !ok {
			return false
		}
	}
	return true
}

// validElem: an address or prefix as ipset writes it.
func validElem(s string) bool {
	if s == "" || len(s) > 50 {
		return false
	}
	for _, r := range s {
		ok := r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r == '.' || r == ':' || r == '/'
		if !ok {
			return false
		}
	}
	return true
}

// ValidIface accepts a Linux interface name (at most 15 bytes of letters,
// digits and . _ - @): it is written into the rules.
func ValidIface(s string) bool {
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

// checkIfaces validates interface names.
func checkIfaces(names []string, what string) error {
	if len(names) == 0 {
		return errors.New("ipt: нет интерфейсов " + what)
	}
	for _, n := range names {
		if !ValidIface(n) {
			return fmt.Errorf("ipt: неверное имя интерфейса %q", n)
		}
	}
	return nil
}

// Ports turns port items ("443", "19294-19344") into multiport lists of
// at most 15 ports each (a range counts as two), as iptables takes them.
func Ports(items []string) ([]string, error) {
	var out []string
	var cur []string
	n := 0
	for _, it := range items {
		lo, hi, rng := strings.Cut(it, "-")
		a, err1 := strconv.ParseUint(lo, 10, 16)
		w := 1
		s := lo
		if rng {
			b, err2 := strconv.ParseUint(hi, 10, 16)
			if err2 != nil || b < a {
				return nil, fmt.Errorf("ipt: неверный порт %q", it)
			}
			w, s = 2, lo+":"+hi
		}
		if err1 != nil || a == 0 {
			return nil, fmt.Errorf("ipt: неверный порт %q", it)
		}
		if n+w > 15 {
			out = append(out, strings.Join(cur, ","))
			cur, n = nil, 0
		}
		cur = append(cur, s)
		n += w
	}
	if len(cur) > 0 {
		out = append(out, strings.Join(cur, ","))
	}
	return out, nil
}

// dport is the match of destination ports for a protocol ("tcp"):
// multiport for a list, --dport for one.
func dport(proto, list string, src bool) string {
	dir := "d"
	if src {
		dir = "s"
	}
	if !strings.ContainsAny(list, ",") {
		return fmt.Sprintf("-p %s --%sport %s", proto, dir, list)
	}
	return fmt.Sprintf("-p %s -m multiport --%sports %s", proto, dir, list)
}

func hexMark(v uint32) string { return fmt.Sprintf("0x%08x", v) }

// markMatch matches a connection mark under CTMask.
func markMatch(v uint32) string {
	return "-m connmark --mark " + hexMark(v) + "/" + hexMark(CTMask)
}
