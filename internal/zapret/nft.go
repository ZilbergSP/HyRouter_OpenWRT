package zapret

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// The nftables side of the bypass. HyRouter's table holds these sets and
// chains next to its routing ones. They follow zapret2's own rules
// (common/nft.sh of v1.0.7) in the "postnat" mode it uses on OpenWrt:
// outgoing packets are queued after NAT, so nfqws2 sees the address the
// internet sees, and the packets nfqws2 makes itself are not tracked by
// conntrack (a NATed fake would be rewritten or dropped as invalid).
//
// Only the first packets of a connection go to nfqws2 (connbytes, as
// zapret2's defaults): the DPI looks at the start of a connection, and the
// rest stays in the kernel, flow offloading included.

// Marks and queues.
const (
	// DesyncMark is on every packet nfqws2 sends (--fwmark): the rules
	// never queue them again.
	DesyncMark = 0x40000000
	// PostNATMark is set on the packets queued after NAT: what nfqws2
	// makes of them is not tracked.
	PostNATMark = 0x20000000
	// QNumBypass is the queue of the bypass of the LAN (the tester of
	// probe slot i takes QNumBypass+i) unless another program holds one of
	// them: then PickQueue moves the range by 100.
	QNumBypass = 200
)

// Packets queued per connection (zapret2's NFQWS2_*_PKT_* defaults).
const (
	tcpPktOut = 20
	tcpPktIn  = 10
	udpPktOut = 5
)

// Sets HyRouter fills with its servers' addresses: the bypass never
// touches the tunnels.
const (
	SetSkip4 = "zapret_skip4"
	SetSkip6 = "zapret_skip6"
)

// NFTConfig is what the rules are built from.
type NFTConfig struct {
	// WAN: the interfaces traffic leaves the router by (the devices of
	// OpenWrt's wan and wan6: "eth1", "pppoe-wan"). Required.
	WAN []string
	// Queue: what goes to the bypass of the LAN (QueueFor of its plans;
	// the zero Queue when the bypass is off).
	Queue Queue
	// Probes: the rules of an auto-pick's probe slots (the router's own
	// connections from ProbeSlot ports go to their testers' queues).
	Probes bool
	// Skip: HyRouter's server addresses, never queued (the sets
	// SetSkip4/6 start with them).
	Skip []netip.Addr
	// QNum: the queue of the bypass of the LAN; the tester of probe slot
	// i takes QNum+i (0: QNumBypass; PickQueue chooses it).
	QNum int
}

// qnum is the queue of the bypass of the LAN.
func (c NFTConfig) qnum() (int, error) {
	switch {
	case c.QNum == 0:
		return QNumBypass, nil
	case c.QNum < 0 || c.QNum+ProbeSlots > 65536:
		return 0, fmt.Errorf("zapret: неверный номер очереди %d", c.QNum)
	}
	return c.QNum, nil
}

// skipElems is the elements of a skip set.
func skipElems(addrs []netip.Addr, v6 bool) string {
	var out []string
	for _, a := range addrs {
		a = a.Unmap()
		if a.IsValid() && a.Is6() == v6 {
			out = append(out, a.String())
		}
	}
	slices.Sort(out)
	return strings.Join(slices.Compact(out), ", ")
}

// NFT returns the sets and chains of the bypass, to be placed inside
// "table inet <HyRouter's table> { … }".
func NFT(c NFTConfig) (string, error) {
	if len(c.WAN) == 0 {
		return "", errors.New("zapret: не известен интерфейс WAN")
	}
	for _, w := range c.WAN {
		if !validIfname(w) {
			return "", fmt.Errorf("zapret: неверное имя интерфейса %q", w)
		}
	}
	for _, p := range append(append([]string{}, c.Queue.TCP...), c.Queue.UDP...) {
		if !validPortItem(p) {
			return "", fmt.Errorf("zapret: неверный порт %q", p)
		}
	}
	qn, err := c.qnum()
	if err != nil {
		return "", err
	}
	wan := "{ " + quoteJoin(c.WAN) + " }"
	lo, _ := ProbeSlot(0)
	_, hi := ProbeSlot(ProbeSlots - 1)
	probes := fmt.Sprintf("%d-%d", lo, hi)
	queue := func(qnum int) string {
		return fmt.Sprintf("meta mark set meta mark | 0x%08x queue num %d bypass", PostNATMark, qnum)
	}

	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	w("\tset %s {", SetSkip4)
	w("\t\ttype ipv4_addr")
	w("\t\tflags interval")
	if e := skipElems(c.Skip, false); e != "" {
		w("\t\telements = { %s }", e)
	}
	w("\t}")
	w("\tset %s {", SetSkip6)
	w("\t\ttype ipv6_addr")
	w("\t\tflags interval")
	if e := skipElems(c.Skip, true); e != "" {
		w("\t\telements = { %s }", e)
	}
	w("\t}")

	// Out: after NAT (srcnat is priority 100).
	w("\tchain zapret_post {")
	w("\t\ttype filter hook postrouting priority 101; policy accept;")
	w("\t\tmeta mark & 0x%08x != 0 return", DesyncMark)
	w("\t\toifname != %s return", wan)
	w("\t\tip daddr @%s return", SetSkip4)
	w("\t\tip6 daddr @%s return", SetSkip6)
	if c.Probes {
		w("\t\ttcp sport %s goto zapret_probe", probes)
	} else {
		w("\t\ttcp sport %s return", probes)
	}
	if len(c.Queue.TCP) > 0 {
		w("\t\ttcp dport { %s } ct original packets 1-%d %s", strings.Join(c.Queue.TCP, ", "), tcpPktOut, queue(qn))
	}
	if len(c.Queue.UDP) > 0 {
		w("\t\tudp dport { %s } ct original packets 1-%d %s", strings.Join(c.Queue.UDP, ", "), udpPktOut, queue(qn))
	}
	w("\t}")
	if c.Probes {
		// Slot 0 checks without a bypass: no rule, the goto ends in accept.
		w("\tchain zapret_probe {")
		for i := 1; i < ProbeSlots; i++ {
			slo, shi := ProbeSlot(i)
			w("\t\ttcp sport %d-%d ct original packets 1-%d %s", slo, shi, tcpPktOut, queue(qn+i))
		}
		w("\t}")
	}

	// In: the server's answers. The first one always: the SYN-ACK, whose
	// TTL autottl reads (ip_autottl: without it the fake keeps its TTL and
	// reaches the server, which breaks the handshake); with circular the
	// first tcpPktIn, for its failure detector. An answer to a probe slot
	// goes to that slot's tester. Priority -101 is before dstnat (-100)
	// undoes the masquerade: the answer still has the WAN address nfqws2
	// saw its query leave from (zapret2's prenat).
	if len(c.Queue.TCP) > 0 || c.Probes {
		in := "1"
		if c.Queue.In {
			in = fmt.Sprintf("1-%d", tcpPktIn)
		}
		w("\tchain zapret_pre {")
		w("\t\ttype filter hook prerouting priority -101; policy accept;")
		w("\t\tiifname != %s return", wan)
		w("\t\tip saddr @%s return", SetSkip4)
		w("\t\tip6 saddr @%s return", SetSkip6)
		if c.Probes {
			w("\t\ttcp dport %s goto zapret_probe_in", probes)
		} else {
			w("\t\ttcp dport %s return", probes)
		}
		if len(c.Queue.TCP) > 0 {
			w("\t\ttcp sport { %s } ct reply packets %s queue num %d bypass", strings.Join(c.Queue.TCP, ", "), in, qn)
		}
		w("\t}")
	}
	if c.Probes {
		// A tester runs one method: its SYN-ACK is enough.
		w("\tchain zapret_probe_in {")
		for i := 1; i < ProbeSlots; i++ {
			slo, shi := ProbeSlot(i)
			w("\t\ttcp dport %d-%d ct reply packets 1 queue num %d bypass", slo, shi, qn+i)
		}
		w("\t}")
	}

	// nfqws2's own packets: untracked (zapret2's predefrag chain).
	w("\tchain zapret_predefrag {")
	w("\t\ttype filter hook output priority -401; policy accept;")
	w("\t\tmeta mark & 0x%08x != 0 jump zapret_predefrag_nfqws", DesyncMark)
	w("\t}")
	w("\tchain zapret_predefrag_nfqws {")
	w("\t\tmeta mark & 0x%08x != 0 notrack", PostNATMark)
	w("\t\tip frag-off & 0x1fff != 0 notrack")
	w("\t\texthdr frag exists notrack")
	w("\t\ttcp flags ! syn,rst,ack notrack")
	w("\t}")
	return b.String(), nil
}

// validIfname: a Linux interface name (at most 15 bytes) of the
// characters OpenWrt uses.
func validIfname(s string) bool {
	if s == "" || len(s) > 15 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.', r == '@':
		default:
			return false
		}
	}
	return true
}

// validPortItem: "443" or "19294-19344" within 1-65535.
func validPortItem(s string) bool {
	lo, hi, rng := strings.Cut(s, "-")
	a, ok1 := portNum(lo)
	if !rng {
		return ok1
	}
	z, ok2 := portNum(hi)
	return ok1 && ok2 && a <= z
}

func portNum(s string) (int, bool) {
	if s == "" || len(s) > 5 {
		return 0, false
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, n >= 1 && n <= 65535
}

func quoteJoin(list []string) string {
	q := make([]string, len(list))
	for i, s := range list {
		q[i] = `"` + s + `"`
	}
	return strings.Join(q, ", ")
}
