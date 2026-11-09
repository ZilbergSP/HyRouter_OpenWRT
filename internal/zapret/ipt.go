package zapret

import (
	"errors"
	"fmt"
	"slices"

	"github.com/zilbergsp/hyrouter/internal/ipt"
)

// The iptables side of the bypass, for KeeneticOS (docs/ARCHITECTURE.md,
// «Кинетик»). It follows zapret2's own rules for iptables (common/ipt.sh
// of v1.0.7): iptables has no chain after NAT on the way out and none
// before it on the way in, so the queries are queued in mangle
// POSTROUTING with the LAN's address and the answers in mangle INPUT and
// FORWARD with it again; nfqws2's own packets carry that address too and
// are NATed with their connection. Only the first packets of a connection
// go to nfqws2 (connbytes), as with nftables.
//
// KeeneticOS does not NAT the UDP nfqws2 sends itself (zapret's
// 10-keenetic-udp-fix, nfqws-keenetic): a masquerade of the packets with
// DesyncMark leaving by the WAN does.

// The bypass's chains in HyRouter's iptables rules.
const (
	chZPost    = "HYR_ZPOST"
	chZOut     = "HYR_ZOUT"
	chZProbe   = "HYR_ZPROBE"
	chZIn      = "HYR_ZIN"
	chZFwd     = "HYR_ZFWD"
	chZReply   = "HYR_ZREPLY"
	chZProbeIn = "HYR_ZPROBE_IN"
	chZNAT     = "HYR_ZNAT"
)

// IPT returns the bypass's sets and chains for HyRouter's iptables rules
// (v6: with IPv6).
func IPT(c NFTConfig, v6 bool) (ipt.Part, error) {
	var p ipt.Part
	if len(c.WAN) == 0 {
		return p, errors.New("zapret: не известен интерфейс WAN")
	}
	for _, w := range c.WAN {
		if !validIfname(w) {
			return p, fmt.Errorf("zapret: неверное имя интерфейса %q", w)
		}
	}
	tcp, err := ipt.Ports(c.Queue.TCP)
	if err != nil {
		return p, err
	}
	udp, err := ipt.Ports(c.Queue.UDP)
	if err != nil {
		return p, err
	}
	qn, err := c.qnum()
	if err != nil {
		return p, err
	}
	lo, _ := ProbeSlot(0)
	_, hi := ProbeSlot(ProbeSlots - 1)
	probes := fmt.Sprintf("%d:%d", lo, hi)
	desync := fmt.Sprintf("0x%08x/0x%08x", DesyncMark, DesyncMark)
	queue := func(qnum int) string { return fmt.Sprintf("-j NFQUEUE --queue-num %d --queue-bypass", qnum) }
	first := func(dir string, n int) string {
		return fmt.Sprintf("-m connbytes --connbytes 1:%d --connbytes-mode packets --connbytes-dir %s", n, dir)
	}

	fams := []int{4}
	if v6 {
		fams = append(fams, 6)
	}
	var mangle []ipt.Table
	for _, fam := range fams {
		skip := "zskip4"
		if fam == 6 {
			skip = "zskip6"
		}
		var elems []string
		for _, a := range c.Skip {
			a = a.Unmap()
			if a.IsValid() && a.Is6() == (fam == 6) {
				elems = append(elems, a.String())
			}
		}
		slices.Sort(elems)
		p.Sets = append(p.Sets, ipt.Set{Name: skip, Net: true, Family: fam, Elems: slices.Compact(elems)})
		skipSet := ipt.SetPrefix + skip

		t := ipt.Table{Family: fam, Name: "mangle"}
		add := func(format string, a ...any) { t.Rules = append(t.Rules, fmt.Sprintf(format, a...)) }
		// Out.
		t.Chains = append(t.Chains, chZPost, chZOut)
		t.Hooks = append(t.Hooks, ipt.Hook{From: "POSTROUTING", To: chZPost})
		for _, w := range c.WAN {
			add("-A %s -o %s -g %s", chZPost, w, chZOut)
		}
		add("-A %s -m mark --mark %s -j RETURN", chZOut, desync)
		add("-A %s -m set --match-set %s dst -j RETURN", chZOut, skipSet)
		if c.Probes {
			add("-A %s -p tcp --sport %s -g %s", chZOut, probes, chZProbe)
		} else {
			add("-A %s -p tcp --sport %s -j RETURN", chZOut, probes)
		}
		for _, l := range tcp {
			add("-A %s %s %s %s", chZOut, portMatch("tcp", l, false), first("original", tcpPktOut), queue(qn))
		}
		for _, l := range udp {
			add("-A %s %s %s %s", chZOut, portMatch("udp", l, false), first("original", udpPktOut), queue(qn))
		}
		if c.Probes {
			// Slot 0 checks without a bypass: no rule, the goto ends in accept.
			t.Chains = append(t.Chains, chZProbe)
			for i := 1; i < ProbeSlots; i++ {
				slo, shi := ProbeSlot(i)
				add("-A %s -p tcp --sport %d:%d %s %s", chZProbe, slo, shi, first("original", tcpPktOut), queue(qn+i))
			}
		}
		// In: the answers, after NAT. The first one always (the SYN-ACK,
		// for autottl); with circular the first tcpPktIn. An answer to a
		// probe slot goes to that slot's tester.
		if len(tcp) > 0 || c.Probes {
			in := 1
			if c.Queue.In {
				in = tcpPktIn
			}
			t.Chains = append(t.Chains, chZIn, chZFwd, chZReply)
			t.Hooks = append(t.Hooks, ipt.Hook{From: "INPUT", To: chZIn}, ipt.Hook{From: "FORWARD", To: chZFwd})
			for _, w := range c.WAN {
				add("-A %s -i %s -g %s", chZIn, w, chZReply)
				add("-A %s -i %s -g %s", chZFwd, w, chZReply)
			}
			add("-A %s -m set --match-set %s src -j RETURN", chZReply, skipSet)
			if c.Probes {
				add("-A %s -p tcp --dport %s -g %s", chZReply, probes, chZProbeIn)
			} else {
				add("-A %s -p tcp --dport %s -j RETURN", chZReply, probes)
			}
			for _, l := range tcp {
				add("-A %s %s %s %s", chZReply, portMatch("tcp", l, true), first("reply", in), queue(qn))
			}
			if c.Probes {
				t.Chains = append(t.Chains, chZProbeIn)
				for i := 1; i < ProbeSlots; i++ {
					slo, shi := ProbeSlot(i)
					add("-A %s -p tcp --dport %d:%d %s %s", chZProbeIn, slo, shi, first("reply", 1), queue(qn+i))
				}
			}
		}
		mangle = append(mangle, t)
	}
	p.Tables = append(p.Tables, mangle...)
	if len(tcp)+len(udp) > 0 || c.Probes {
		t := ipt.Table{Family: 4, Name: "nat", Chains: []string{chZNAT}, Hooks: []ipt.Hook{{From: "POSTROUTING", To: chZNAT}}}
		for _, w := range c.WAN {
			t.Rules = append(t.Rules, fmt.Sprintf("-A %s -o %s -p udp -m mark --mark %s -j MASQUERADE", chZNAT, w, desync))
		}
		p.Tables = append(p.Tables, t)
	}
	return p, p.Check(ipt.OwnerRoute)
}

// portMatch matches a protocol's destination ports (source ports of the
// answers) from a list of ipt.Ports.
func portMatch(proto, list string, src bool) string {
	dir := "d"
	if src {
		dir = "s"
	}
	for _, r := range list {
		if r == ',' {
			return fmt.Sprintf("-p %s -m multiport --%sports %s", proto, dir, list)
		}
	}
	return fmt.Sprintf("-p %s --%sport %s", proto, dir, list)
}
