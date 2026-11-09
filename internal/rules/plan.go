package rules

import (
	"net/netip"
	"slices"
)

// HyRouter: the view of a compiled set the nftables compiler works from.
// The kernel decides a new connection by its device, protocol, port and
// destination address; a site is matched by the addresses its names
// resolved to through HyRouter's DNS (each rule's DNS sets, NameRules).

// PlanRule is one enabled rule as the kernel sees it.
type PlanRule struct {
	// Pos is the rule's position among the enabled rules; the names of
	// its nftables sets are made of it.
	Pos  int
	Name string
	ID   string
	// Never: the rule matches nothing on a router: it names programs, or
	// its device items resolve to no address.
	Never bool
	// Route is where a match goes (Action, Profile, Fallback).
	Route Result
	// Proto is 0 (any), 6 or 17; Ports empty = any port.
	Proto uint8
	Ports []PortRange
	// Devices: the rule is limited to sources with one of MACs or within
	// one of Sources; false = any device.
	Devices bool
	MACs    []MAC
	Sources []netip.Prefix
	// Dest: the rule names destinations; a connection matches when its
	// address is in Nets, or in the rule's DNS sets when Sites. GeoIP
	// items are not in Nets: the kernel does not see them yet, and they
	// match nothing without the rule database.
	Dest  bool
	Nets  []netip.Prefix
	Sites bool
}

// Plan returns the enabled rules in their order and the default route.
func (s *Set) Plan() ([]PlanRule, Result) {
	out := make([]PlanRule, 0, len(s.rules))
	for i := range s.rules {
		r := &s.rules[i]
		p := PlanRule{
			Pos:   i,
			Name:  r.name,
			ID:    r.src.ID,
			Never: r.hasApp(),
			Route: s.result(r),
			Proto: r.proto,
			Ports: slices.Clone(r.ports),
			Dest:  r.hasDest(),
			Sites: r.hasDom(),
		}
		if r.hasDev() {
			p.Devices = true
			for _, d := range r.devs {
				p.MACs = append(p.MACs, d.macs...)
				p.Sources = append(p.Sources, d.pfxs...)
			}
			if len(p.MACs) == 0 && len(p.Sources) == 0 {
				p.Never = true
			}
		}
		for _, ip := range r.ips {
			if ip.pfx.IsValid() {
				p.Nets = append(p.Nets, ip.pfx)
			}
		}
		out = append(out, p)
	}
	return out, s.result(nil)
}

// NameRules returns the positions of the enabled rules whose sites match
// name: the rules whose DNS sets take the addresses of an answer for it.
// Devices, protocol and ports are left to the kernel.
func (s *Set) NameRules(name string) []int {
	name = NormalizeDomain(name)
	if name == "" {
		return nil
	}
	var out []int
	for i := range s.rules {
		r := &s.rules[i]
		if r.hasDom() && !r.hasApp() && r.matchDomain(name) {
			out = append(out, i)
		}
	}
	return out
}
