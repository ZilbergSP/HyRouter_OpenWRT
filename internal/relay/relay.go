//go:build linux

// Package relay carries the LAN connections the kernel hands over through
// TPROXY (docs/ARCHITECTURE.md, «Как идёт трафик»). On the tunnel port a
// connection goes through the server its rule names; on the name port the
// relay first reads the site name (SNI, Host) and then sends it directly,
// through a server or nowhere. A connection the rules do not send through
// a tunnel never leaves from the tunnel port: it is reset. VPN traffic
// never goes direct.
package relay

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/zilbergsp/hyrouter/internal/flows"
	"github.com/zilbergsp/hyrouter/internal/groups"
	"github.com/zilbergsp/hyrouter/internal/rules"
	"github.com/zilbergsp/hyrouter/internal/sniff"
	"github.com/zilbergsp/hyrouter/internal/socks5"
)

const (
	sniffTimeout  = 3 * time.Second
	dialTimeout   = 30 * time.Second
	directTimeout = 10 * time.Second
)

// Tunnel is a running server's way out (tunnels.Endpoint).
type Tunnel interface {
	Available() bool
	UDPAvailable() bool
	Dial(ctx context.Context, dst socks5.Addr) (net.Conn, error)
	UDPAssociate(ctx context.Context) (*socks5.UDPAssoc, error)
}

// Config connects the relay to the rest of hyrouterd.
type Config struct {
	// TunnelPort and NamePort are the TPROXY ports (nft.Options).
	TunnelPort uint16
	NamePort   uint16
	// Rules returns the rules in force.
	Rules func() *rules.Set
	// Names returns the names the DNS cache holds for an address.
	Names func(netip.Addr) []string
	// MAC tells a LAN address's MAC (zero when unknown).
	MAC func(netip.Addr) rules.MAC
	// Pick chooses the server of a Tunnel decision: its server or group,
	// then its fallbacks. It returns the decision moved to that server
	// and its way out; nil when none can carry the connection, which is
	// then refused.
	Pick func(res rules.Result, udp bool, h groups.Hint) (rules.Result, Tunnel)
	// Limit bounds the TCP connections and UDP flows at once (0 = none).
	Limit int
	// Flows records the connections and flows (nil = none); Device names
	// the device of a LAN address in them, and keys it.
	Flows  *flows.Registry
	Device func(mac rules.MAC, ip netip.Addr) (name, key string)
	Log   *slog.Logger
}

// Relay is the running relay.
type Relay struct {
	cfg    Config
	ctx    context.Context
	cancel context.CancelFunc
	lns    []net.Listener
	udps   []*net.UDPConn
	wg     sync.WaitGroup
	active atomic.Int64

	mu    sync.Mutex
	flows map[flowKey]*flow
}

// Start opens the listeners: TCP on both ports and UDP on the tunnel
// port, for IPv4 and IPv6 (IPv6 is skipped when the router has none).
func Start(cfg Config) (*Relay, error) {
	ctx, cancel := context.WithCancel(context.Background())
	r := &Relay{cfg: cfg, ctx: ctx, cancel: cancel, flows: map[flowKey]*flow{}}
	lc := net.ListenConfig{Control: transparent}
	for _, fam := range []string{"4", "6"} {
		host := "0.0.0.0"
		if fam == "6" {
			host = "::"
		}
		for _, l := range []struct {
			port   uint16
			handle func(*net.TCPConn)
		}{{cfg.TunnelPort, r.handleTunnel}, {cfg.NamePort, r.handleName}} {
			ln, err := lc.Listen(ctx, "tcp"+fam, net.JoinHostPort(host, strconv.Itoa(int(l.port))))
			if err != nil {
				if fam == "6" {
					r.log().Warn("relay: no IPv6", "err", err)
					break
				}
				r.Close()
				return nil, err
			}
			r.lns = append(r.lns, ln)
			r.wg.Add(1)
			go r.acceptLoop(ln, l.handle)
		}
		pc, err := lc.ListenPacket(ctx, "udp"+fam, net.JoinHostPort(host, strconv.Itoa(int(cfg.TunnelPort))))
		if err != nil {
			if fam == "6" {
				continue
			}
			r.Close()
			return nil, err
		}
		u := pc.(*net.UDPConn)
		r.udps = append(r.udps, u)
		r.wg.Add(1)
		go r.udpLoop(u)
	}
	r.wg.Add(1)
	go r.sweepLoop()
	return r, nil
}

// Close stops listening and ends every connection and flow.
func (r *Relay) Close() {
	r.cancel()
	for _, ln := range r.lns {
		ln.Close()
	}
	for _, u := range r.udps {
		u.Close()
	}
	r.mu.Lock()
	for _, f := range r.flows {
		f.close()
	}
	r.mu.Unlock()
	r.wg.Wait()
	r.mu.Lock()
	for _, f := range r.flows {
		r.end(f.rec)
	}
	r.mu.Unlock()
}

// Active is the number of TCP connections and UDP flows under way.
func (r *Relay) Active() int64 { return r.active.Load() }

func (r *Relay) log() *slog.Logger {
	if r.cfg.Log == nil {
		return slog.Default()
	}
	return r.cfg.Log
}

// transparent lets a socket take connections and send packets for
// addresses that are not the router's (TPROXY), and tells a UDP
// listener each datagram's original destination.
func transparent(network, _ string, rc syscall.RawConn) error {
	v6 := strings.HasSuffix(network, "6")
	var serr error
	err := rc.Control(func(fd uintptr) {
		s := int(fd)
		if v6 {
			serr = unix.SetsockoptInt(s, unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
		} else {
			serr = unix.SetsockoptInt(s, unix.SOL_IP, unix.IP_TRANSPARENT, 1)
		}
		if serr == nil {
			serr = unix.SetsockoptInt(s, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		}
		if serr == nil && strings.HasPrefix(network, "udp") {
			if v6 {
				serr = unix.SetsockoptInt(s, unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
			} else {
				serr = unix.SetsockoptInt(s, unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
			}
		}
	})
	if err != nil {
		return err
	}
	return serr
}

// acquire counts a new connection or flow; false past the limit.
func (r *Relay) acquire() bool {
	n := r.active.Add(1)
	if r.cfg.Limit > 0 && n > int64(r.cfg.Limit) {
		r.active.Add(-1)
		return false
	}
	return true
}

func (r *Relay) release() { r.active.Add(-1) }

func (r *Relay) acceptLoop(ln net.Listener, handle func(*net.TCPConn)) {
	defer r.wg.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || r.ctx.Err() != nil {
				return
			}
			r.log().Warn("relay: accept", "err", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		tc, ok := c.(*net.TCPConn)
		if !ok || !r.acquire() {
			socks5.Abort(c)
			continue
		}
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			defer r.release()
			handle(tc)
		}()
	}
}

func addrPort(a net.Addr) netip.AddrPort {
	switch a := a.(type) {
	case *net.TCPAddr:
		ap := a.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	case *net.UDPAddr:
		ap := a.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return netip.AddrPort{}
}

func (r *Relay) subject(proto uint8, src, dst netip.AddrPort) rules.Subject {
	s := src.Addr().Unmap()
	sub := rules.Subject{Proto: proto, Dst: netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port()), Src: s}
	if r.cfg.MAC != nil {
		sub.MAC = r.cfg.MAC(s)
	}
	return sub
}

func (r *Relay) names(a netip.Addr) []string {
	if r.cfg.Names == nil {
		return nil
	}
	return r.cfg.Names(a)
}

// byDNS decides a connection the way the kernel did: the destination is
// every site whose name resolved to it.
func (r *Relay) byDNS(sub rules.Subject) rules.Result {
	return r.cfg.Rules().EvaluateSites(sub, [][]string{r.names(sub.Dst.Addr())})
}

func (r *Relay) handleTunnel(c *net.TCPConn) {
	src := addrPort(c.RemoteAddr())
	sub := r.subject(6, src, addrPort(c.LocalAddr()))
	rec := r.open(sub, src)
	defer r.end(rec)
	res := r.byDNS(sub)
	if res.Action != rules.Tunnel {
		r.log().Debug("relay: a tunnel connection the rules no longer send through a tunnel: reset", "rule", res.Rule)
		decided(rec, res, "", rules.SrcNone, "rst: правила больше не ведут его через VPN")
		socks5.Abort(c)
		return
	}
	r.viaTunnel(c, rec, res, sub, "", rules.SrcNone, socks5.AddrFromAddrPort(sub.Dst), nil)
}

func (r *Relay) handleName(c *net.TCPConn) {
	from := addrPort(c.RemoteAddr())
	sub := r.subject(6, from, addrPort(c.LocalAddr()))
	rec := r.open(sub, from)
	defer r.end(rec)
	prefix, sn := readName(c)
	names := r.names(sub.Dst.Addr())
	host := sn.Host
	// The outer name of an encrypted ClientHello is the site itself under
	// GREASE ECH, a provider's public name under real ECH: trusted only
	// when DNS gave this address to it.
	if sn.ECH && !slices.Contains(names, host) {
		host = ""
	}
	var res rules.Result
	src := rules.SrcNone
	if host != "" {
		src = rules.SrcSNI
		if sn.Kind == sniff.HTTP {
			src = rules.SrcHost
		}
		res = r.cfg.Rules().EvaluateDomain(sub, host, src)
	} else {
		res = r.cfg.Rules().EvaluateSites(sub, [][]string{names})
	}
	switch res.Action {
	case rules.Direct:
		d := net.Dialer{Timeout: directTimeout}
		up, err := d.DialContext(r.ctx, "tcp", sub.Dst.String())
		if err != nil {
			r.log().Debug("relay: direct connection failed", "rule", res.Rule, "err", err)
			decided(rec, res, host, src, "rst: "+err.Error())
			socks5.Abort(c)
			return
		}
		decided(rec, res, host, src, "passed")
		r.pipe(c, up, prefix, rec)
	case rules.Tunnel:
		dst := socks5.AddrFromAddrPort(sub.Dst)
		if host != "" {
			dst = socks5.Addr{Host: host, Port: sub.Dst.Port()}
		}
		r.viaTunnel(c, rec, res, sub, host, src, dst, prefix)
	default:
		decided(rec, res, host, src, "rst: заблокировано правилом")
		socks5.Abort(c)
	}
}

// readName reads what the client sends first until the site name is
// known, the bytes say there is none, or sniffTimeout passes. The bytes
// read are passed on unchanged.
func readName(c *net.TCPConn) ([]byte, sniff.Result) {
	buf := make([]byte, 0, 2048)
	tmp := make([]byte, 4096)
	c.SetReadDeadline(time.Now().Add(sniffTimeout))
	defer c.SetReadDeadline(time.Time{})
	var res sniff.Result
	for len(buf) < sniff.MaxTLS {
		n, err := c.Read(tmp)
		buf = append(buf, tmp[:n]...)
		res = sniff.Parse(buf)
		if res.Done || err != nil {
			break
		}
	}
	return buf, res
}

// pickTunnel chooses the server of a connection (Config.Pick). host is
// the name seen in the connection itself ("" = none): a group keeps one
// site on one server by it, or by the names DNS gave the address.
func (r *Relay) pickTunnel(res rules.Result, udp bool, sub rules.Subject, host string) (Tunnel, rules.Result) {
	if r.cfg.Pick == nil {
		return nil, res
	}
	h := groups.Hint{App: deviceKey(sub), IP: sub.Dst.Addr()}
	if hasGroup(res) {
		h.Site = groups.SiteOf(host, r.names(sub.Dst.Addr()))
	}
	picked, t := r.cfg.Pick(res, udp, h)
	return t, picked
}

// hasGroup reports a group anywhere in a Tunnel result's chain.
func hasGroup(res rules.Result) bool {
	return groups.IsGroupID(res.Profile) || slices.ContainsFunc(res.Fallback, groups.IsGroupID)
}

// deviceKey names the device of a connection for a group that keeps a
// device's site on one server: its MAC, else its address.
func deviceKey(sub rules.Subject) string {
	if !sub.MAC.IsZero() {
		return "dev:" + sub.MAC.String()
	}
	if sub.Src.IsValid() {
		return "dev:" + sub.Src.String()
	}
	return ""
}

func (r *Relay) viaTunnel(c *net.TCPConn, rec *flows.Record, res rules.Result, sub rules.Subject, host string, hsrc rules.DomainSource, dst socks5.Addr, prefix []byte) {
	t, picked := r.pickTunnel(res, false, sub, host)
	if t == nil {
		r.log().Info("relay: no server can carry the connection, it is refused", "rule", res.Rule, "server", res.Profile)
		decided(rec, picked, host, hsrc, "rst: ни один сервер не может его пропустить")
		socks5.Abort(c)
		return
	}
	ctx, cancel := context.WithTimeout(r.ctx, dialTimeout)
	up, err := t.Dial(ctx, dst)
	cancel()
	if err != nil {
		r.log().Debug("relay: connection through the server failed", "rule", res.Rule, "server", picked.Profile, "err", err)
		decided(rec, picked, host, hsrc, "rst: "+err.Error())
		socks5.Abort(c)
		return
	}
	decided(rec, picked, host, hsrc, "passed")
	r.pipe(c, up, prefix, rec)
}

// pipe passes prefix and then both directions until both are done; the
// relay's Close ends it early.
func (r *Relay) pipe(c *net.TCPConn, up net.Conn, prefix []byte, rec *flows.Record) {
	stop := context.AfterFunc(r.ctx, func() {
		socks5.Abort(c)
		socks5.Abort(up)
	})
	defer stop()
	defer c.Close()
	defer up.Close()
	if len(prefix) > 0 {
		if _, err := up.Write(prefix); err != nil {
			socks5.Abort(c)
			return
		}
		if rec != nil {
			rec.Sent.Add(int64(len(prefix)))
		}
	}
	pipeCounted(c, up, rec)
}
