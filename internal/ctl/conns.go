//go:build linux

package ctl

import (
	"bufio"
	"context"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zilbergsp/hyrouter/internal/edition"
	"github.com/zilbergsp/hyrouter/internal/flows"
	"github.com/zilbergsp/hyrouter/internal/platform"
	"github.com/zilbergsp/hyrouter/internal/rules"
	"github.com/zilbergsp/hyrouter/internal/store"
)

// «Соединения» (docs/ARCHITECTURE.md): every connection of the LAN that
// HyRouter decided. The relay records the ones it carries (through a
// server, or decided by the site's name); the ones the kernel sends
// directly or blocks never reach it, so they are read from the kernel's
// connection table (/proc/net/nf_conntrack) every few seconds, by the
// connection mark HyRouter's table gave them.

var (
	conntrackFile  = "/proc/net/nf_conntrack"
	conntrackAcct  = "/proc/sys/net/netfilter/nf_conntrack_acct"
	conntrackEvery = 5 * time.Second
)

// devices names the devices of the LAN.
type devices struct {
	mu     sync.Mutex
	macs   map[rules.MAC]store.Device
	pfxs   []devicePrefix
	leases map[rules.MAC]string
	readAt time.Time
	// reading: the names are being read (platform.Hosts may ask the
	// firmware, which takes a while): the old ones serve meanwhile.
	reading bool
}

type devicePrefix struct {
	p netip.Prefix
	d store.Device
}

// set takes the devices of the settings.
func (d *devices) set(list []store.Device) {
	macs := map[rules.MAC]store.Device{}
	var pfxs []devicePrefix
	for _, dev := range list {
		for _, m := range dev.MACs {
			if mac, err := rules.ParseMAC(m); err == nil {
				macs[mac] = dev
			}
		}
		for _, a := range dev.Addrs {
			if p, err := netip.ParsePrefix(a); err == nil {
				pfxs = append(pfxs, devicePrefix{p.Masked(), dev})
			} else if ip, err := netip.ParseAddr(a); err == nil {
				pfxs = append(pfxs, devicePrefix{netip.PrefixFrom(ip, ip.BitLen()), dev})
			}
		}
	}
	d.mu.Lock()
	d.macs, d.pfxs = macs, pfxs
	d.mu.Unlock()
}

// name names the device of a connection: a device of the settings, else
// the name the router knows it by (DHCP), else its address. key is what
// the statistics count it by.
func (d *devices) name(mac rules.MAC, ip netip.Addr) (name, key string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !mac.IsZero() {
		if dev, ok := d.macs[mac]; ok {
			return deviceName(dev), "dev:" + dev.ID
		}
	}
	for _, p := range d.pfxs {
		if p.p.Contains(ip) {
			return deviceName(p.d), "dev:" + p.d.ID
		}
	}
	if !mac.IsZero() {
		if time.Since(d.readAt) > 30*time.Second && !d.reading {
			d.reading = true
			go d.readNames()
		}
		if h := d.leases[mac]; h != "" {
			return h, "mac:" + mac.String()
		}
		return ip.String(), "mac:" + mac.String()
	}
	return ip.String(), "ip:" + ip.String()
}

func deviceName(d store.Device) string {
	if d.Name != "" {
		return d.Name
	}
	return d.ID
}

// readNames reads the names the router knows its devices by.
func (d *devices) readNames() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out := map[rules.MAC]string{}
	for _, h := range platform.Hosts(ctx) {
		if mac, err := rules.ParseMAC(h.MAC); err == nil && h.Name != "" {
			out[mac] = h.Name
		}
	}
	d.mu.Lock()
	d.leases, d.readAt, d.reading = out, time.Now(), false
	d.mu.Unlock()
}

// ctEntry is one connection of the kernel's table.
type ctEntry struct {
	proto      uint8
	src, dst   netip.AddrPort
	sent, recv int64 // -1 without accounting
	mark       uint32
}

// parseConntrack reads a line of /proc/net/nf_conntrack:
// "ipv4 2 tcp 6 431999 ESTABLISHED src=… dst=… sport=… dport=…
// [packets=… bytes=…] src=… dst=… sport=… dport=… [packets=… bytes=…]
// [ASSURED] mark=… zone=0 use=2".
func parseConntrack(line string) (ctEntry, bool) {
	fs := strings.Fields(line)
	if len(fs) < 6 {
		return ctEntry{}, false
	}
	e := ctEntry{sent: -1, recv: -1}
	switch fs[2] {
	case "tcp":
		e.proto = 6
	case "udp":
		e.proto = 17
	default:
		return ctEntry{}, false
	}
	var src, dst netip.Addr
	var sport, dport uint16
	var nSrc, nBytes int
	for _, f := range fs[3:] {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			continue
		}
		switch k {
		case "src":
			nSrc++
			if nSrc == 1 {
				src, _ = netip.ParseAddr(v)
			}
		case "dst":
			if nSrc == 1 && !dst.IsValid() {
				dst, _ = netip.ParseAddr(v)
			}
		case "sport":
			if nSrc == 1 && sport == 0 {
				n, _ := strconv.ParseUint(v, 10, 16)
				sport = uint16(n)
			}
		case "dport":
			if nSrc == 1 && dport == 0 {
				n, _ := strconv.ParseUint(v, 10, 16)
				dport = uint16(n)
			}
		case "bytes":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				continue
			}
			nBytes++
			if nBytes == 1 {
				e.sent = n
			} else if nBytes == 2 {
				e.recv = n
			}
		case "mark":
			n, _ := strconv.ParseUint(v, 10, 32)
			e.mark = uint32(n)
		}
	}
	if !src.IsValid() || !dst.IsValid() {
		return ctEntry{}, false
	}
	e.src, e.dst = netip.AddrPortFrom(src.Unmap(), sport), netip.AddrPortFrom(dst.Unmap(), dport)
	return e, true
}

// runConntrack records the direct and blocked connections until ctx ends.
func (c *Controller) runConntrack(ctx context.Context) {
	os.WriteFile(conntrackAcct, []byte("1\n"), 0o644) // byte counts of new connections
	live := map[string]*flows.Record{}
	defer func() {
		now := time.Now()
		for _, rec := range live {
			c.flows.Close(rec, now)
		}
	}()
	t := time.NewTicker(conntrackEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		c.conntrackRound(live)
	}
}

func (c *Controller) conntrackRound(live map[string]*flows.Record) {
	f, err := os.Open(conntrackFile)
	if err != nil {
		return
	}
	defer f.Close()
	seen := make(map[string]bool, len(live))
	set := c.rules.Load()
	limit := edition.Current.Relay
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	for sc.Scan() {
		e, ok := parseConntrack(sc.Text())
		if !ok {
			continue
		}
		route := ""
		switch e.mark & fwCTMask {
		case fwCTDirect:
			route = "direct"
		case fwCTBlock:
			route = "block"
		default:
			continue // not decided by HyRouter, or carried by the relay
		}
		key := strconv.Itoa(int(e.proto)) + " " + e.src.String() + " " + e.dst.String()
		seen[key] = true
		rec := live[key]
		if rec == nil {
			if len(live) >= limit {
				continue
			}
			rec = &flows.Record{Proto: e.proto, Src: e.src, Dst: e.dst}
			mac := c.neigh.Lookup(e.src.Addr())
			rec.Process, rec.Path = c.devs.name(mac, e.src.Addr())
			rec = c.flows.Open(rec)
			sub := rules.Subject{Proto: e.proto, Dst: e.dst, Src: e.src.Addr(), MAC: mac}
			res := rules.Result{Rule: "—"}
			if set != nil {
				res = set.EvaluateSites(sub, [][]string{c.cache.Names(e.dst.Addr())})
			}
			rec.Set(func(f *flows.Fields) {
				f.Route, f.Rule, f.Stage, f.Outcome = route, res.Rule, "kernel", "passed"
				if route == "block" {
					f.Outcome = "rst: заблокировано правилом"
				}
			})
			live[key] = rec
		}
		if e.sent >= 0 {
			rec.Sent.Store(e.sent)
		}
		if e.recv >= 0 {
			rec.Recv.Store(e.recv)
		}
	}
	now := time.Now()
	for key, rec := range live {
		if !seen[key] {
			c.flows.Close(rec, now)
			delete(live, key)
		}
	}
}

// Connections is the «Соединения» page: the live connections and the
// last ones closed, newest first.
type Connections struct {
	Active []flows.View `json:"active"`
	Closed []flows.View `json:"closed"`
}

// Connections reports the connections.
func (c *Controller) Connections() Connections {
	now := time.Now()
	out := Connections{Active: c.flows.Active(now), Closed: c.flows.Closed()}
	if out.Active == nil {
		out.Active = []flows.View{}
	}
	if out.Closed == nil {
		out.Closed = []flows.View{}
	}
	// Newest first.
	for i, j := 0, len(out.Closed)-1; i < j; i, j = i+1, j-1 {
		out.Closed[i], out.Closed[j] = out.Closed[j], out.Closed[i]
	}
	return out
}
