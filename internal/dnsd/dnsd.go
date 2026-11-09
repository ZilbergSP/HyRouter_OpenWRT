//go:build linux

// Package dnsd is HyRouter's DNS in front of dnsmasq (docs/ARCHITECTURE.md,
// «DNS»). The LAN's queries to the router come here (nft redirects them):
// a name the rules send through a server is resolved through that server,
// a blocked one gets NXDOMAIN, every other query goes to dnsmasq as
// before. The addresses of every answer go into the nftables sets of the
// rules whose sites the name matches before the answer reaches the
// device, so its first connection is already decided by them.
package dnsd

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/zilbergsp/hyrouter/internal/dnscache"
	"github.com/zilbergsp/hyrouter/internal/dnspolicy"
	"github.com/zilbergsp/hyrouter/internal/dnsproxy"
	"github.com/zilbergsp/hyrouter/internal/nft"
	"github.com/zilbergsp/hyrouter/internal/rules"
)

const (
	// minTimeout and maxTimeout bound how long an address stays in a set
	// after its answer: a short TTL must not empty the set under a
	// connection the device opens a little later.
	minTimeout = 10 * time.Minute
	maxTimeout = 6 * time.Hour
	// upstreamTimeout bounds a query to dnsmasq.
	upstreamTimeout = 5 * time.Second
	// tcpIdle ends a DNS-over-TCP connection with no query.
	tcpIdle = 10 * time.Second
	// maxBusy bounds the UDP queries answered at once.
	maxBusy = 256
)

// SetWriter changes the elements of the table's sets (nft.Sets).
type SetWriter interface {
	Apply(del, add []nft.Elem) error
}

// Config connects the server to the rest of hyrouterd.
type Config struct {
	// Port is where the server listens on every address (nft redirects
	// the LAN's port 53 to it).
	Port uint16
	// Upstream is dnsmasq: "127.0.0.1:53".
	Upstream string
	// Policy, Rules and HasSets return what is in force: the DNS policy
	// (nil = pass everything), the rules, and whether the rule at a
	// position has DNS sets in the table.
	Policy  func() *dnspolicy.Policy
	Rules   func() *rules.Set
	HasSets func(pos int) bool
	// MAC tells a LAN address's MAC (zero when unknown).
	MAC      func(netip.Addr) rules.MAC
	Resolver *dnsproxy.Resolver
	Cache    *dnscache.Cache
	Sets     SetWriter
	Log      *slog.Logger
}

type elemKey struct {
	set  string
	addr netip.Addr
}

// elemTime is until when an element is in its set, and for how long it
// was put there.
type elemTime struct {
	until   time.Time
	timeout time.Duration
}

// Server is the running DNS.
type Server struct {
	cfg    Config
	ctx    context.Context
	cancel context.CancelFunc
	udps   []*net.UDPConn
	lns    []net.Listener
	wg     sync.WaitGroup

	mu    sync.Mutex
	elems map[elemKey]elemTime     // what is in the sets
	known map[netip.Addr]time.Time // addresses learned, until when
	// busy bounds the UDP queries answered at once.
	busy chan struct{}
}

// New makes a server that is not listening (tests use Learn).
func New(cfg Config) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{cfg: cfg, ctx: ctx, cancel: cancel, elems: map[elemKey]elemTime{}, known: map[netip.Addr]time.Time{}, busy: make(chan struct{}, maxBusy)}
}

// Start makes a server and opens its UDP and TCP listeners, IPv4 and
// IPv6 (IPv6 is skipped when the router has none).
func Start(cfg Config) (*Server, error) {
	s := New(cfg)
	for _, fam := range []string{"4", "6"} {
		host := "0.0.0.0"
		if fam == "6" {
			host = "::"
		}
		addr := net.JoinHostPort(host, strconv.Itoa(int(cfg.Port)))
		u, err := net.ListenUDP("udp"+fam, mustUDP(addr))
		if err != nil {
			if fam == "6" {
				continue
			}
			s.Close()
			return nil, err
		}
		s.udps = append(s.udps, u)
		ln, err := net.Listen("tcp"+fam, addr)
		if err != nil {
			s.Close()
			return nil, err
		}
		s.lns = append(s.lns, ln)
		s.wg.Add(2)
		go s.udpLoop(u)
		go s.tcpLoop(ln)
	}
	s.wg.Add(1)
	go s.sweepLoop()
	return s, nil
}

func mustUDP(addr string) *net.UDPAddr {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		panic(err)
	}
	return a
}

// Close stops the server.
func (s *Server) Close() {
	s.cancel()
	for _, u := range s.udps {
		u.Close()
	}
	for _, ln := range s.lns {
		ln.Close()
	}
	s.wg.Wait()
}

func (s *Server) log() *slog.Logger {
	if s.cfg.Log == nil {
		return slog.Default()
	}
	return s.cfg.Log
}

func (s *Server) udpLoop(u *net.UDPConn) {
	defer s.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, client, err := u.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || s.ctx.Err() != nil {
				return
			}
			continue
		}
		msg := append([]byte(nil), buf[:n]...)
		select {
		case s.busy <- struct{}{}:
		default:
			continue // too many at once: the client asks again
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.busy }()
			if out := s.Handle(s.ctx, client, msg, false); out != nil {
				u.WriteToUDPAddrPort(out, client)
			}
		}()
	}
}

func (s *Server) tcpLoop(ln net.Listener) {
	defer s.wg.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || s.ctx.Err() != nil {
				return
			}
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serveTCP(c)
		}()
	}
}

func (s *Server) serveTCP(c net.Conn) {
	defer c.Close()
	stop := context.AfterFunc(s.ctx, func() { c.Close() })
	defer stop()
	client := netip.AddrPort{}
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		client = a.AddrPort()
	}
	for {
		c.SetReadDeadline(time.Now().Add(tcpIdle))
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		msg := make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(c, msg); err != nil {
			return
		}
		out := s.Handle(s.ctx, client, msg, true)
		if out == nil {
			return
		}
		if _, err := c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(out))), out...)); err != nil {
			return
		}
	}
}

// Handle answers one query of client (nil = no answer) and learns the
// addresses of the answer.
func (s *Server) Handle(ctx context.Context, client netip.AddrPort, msg []byte, tcp bool) []byte {
	src := client.Addr().Unmap()
	q, ok := dnsproxy.ParseQuery(msg)
	var pol *dnspolicy.Policy
	if s.cfg.Policy != nil {
		pol = s.cfg.Policy()
	}
	if !ok || pol == nil {
		out := s.forward(ctx, msg, tcp)
		if ok && out != nil {
			s.Learn(msg, out)
		}
		return out
	}
	req := dnspolicy.Requester{Src: src}
	if s.cfg.MAC != nil {
		req.MAC = s.cfg.MAC(src)
	}
	d := pol.Classify(dnspolicy.Question{Name: q.Name, Type: q.Type}, req, dnspolicy.Env{Rules: s.cfg.Rules()})
	var out []byte
	switch d.Kind {
	case dnspolicy.Answer:
		out = dnsproxy.Synth(q, d.Rcode)
	case dnspolicy.Resolve:
		if s.cfg.Resolver == nil {
			out = dnsproxy.Synth(q, dnsmessage.RCodeServerFailure)
			break
		}
		up, age, err := s.cfg.Resolver.Exchange(ctx, d.Via, d.Route.Profile, q)
		if err == nil {
			limit := q.MaxUDP()
			if tcp {
				limit = 65535
			}
			out, _, err = dnsproxy.Reply(q, up, dnsproxy.ReplyOpts{Max: limit, Age: age, Tunnel: d.Via == dnspolicy.ViaTunnel})
		}
		if err != nil {
			s.log().Debug("dns: resolving failed", "rule", d.Rule, "err", err)
			out = dnsproxy.Synth(q, dnsmessage.RCodeServerFailure)
		}
	default:
		out = s.forward(ctx, msg, tcp)
	}
	if out != nil {
		s.Learn(msg, out)
	}
	return out
}

// forward passes a query to dnsmasq as it is and returns its answer.
func (s *Server) forward(ctx context.Context, msg []byte, tcp bool) []byte {
	ctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
	defer cancel()
	network := "udp"
	if tcp {
		network = "tcp"
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, network, s.cfg.Upstream)
	if err != nil {
		return nil
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	if !tcp {
		if _, err := c.Write(msg); err != nil {
			return nil
		}
		buf := make([]byte, 65535)
		n, err := c.Read(buf)
		if err != nil {
			return nil
		}
		return buf[:n]
	}
	if _, err := c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(msg))), msg...)); err != nil {
		return nil
	}
	var l [2]byte
	if _, err := io.ReadFull(c, l[:]); err != nil {
		return nil
	}
	out := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(c, out); err != nil {
		return nil
	}
	return out
}

// addrTTL is an address of an answer and its record's TTL.
type addrTTL struct {
	addr netip.Addr
	ttl  time.Duration
}

// answerAddrs returns the A and AAAA records of an answer.
func answerAddrs(msg []byte) (out []addrTTL) {
	defer func() {
		if recover() != nil {
			out = nil
		}
	}()
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return nil
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil
	}
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			return out
		}
		ttl := time.Duration(h.TTL) * time.Second
		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return out
			}
			out = append(out, addrTTL{netip.AddrFrom4(r.A), ttl})
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return out
			}
			out = append(out, addrTTL{netip.AddrFrom16(r.AAAA).Unmap(), ttl})
		default:
			if err := p.SkipAnswer(); err != nil {
				return out
			}
		}
	}
}

// Learn records the answer to query in the DNS cache and puts its
// addresses into the sets of the rules their names match.
func (s *Server) Learn(query, answer []byte) {
	if s.cfg.Cache == nil {
		return
	}
	if _, err := s.cfg.Cache.AddAnswerFor(query, answer); err != nil {
		return
	}
	addrs := answerAddrs(answer)
	if len(addrs) == 0 {
		return
	}
	now := time.Now()
	s.mu.Lock()
	for _, a := range addrs {
		until := now.Add(clampTimeout(a.ttl))
		if until.After(s.known[a.addr]) {
			s.known[a.addr] = until
		}
	}
	s.mu.Unlock()
	s.place(addrs, now)
}

func clampTimeout(ttl time.Duration) time.Duration {
	return min(max(ttl, minTimeout), maxTimeout)
}

// place puts addresses into the sets their sites' rules name. An address
// shared by sites the rules match differently also goes into the
// ambiguous set: web connections to it are decided by the name the relay
// reads. An address already in a set is refreshed (deleted and added in
// one transaction) once half its time is gone.
func (s *Server) place(addrs []addrTTL, now time.Time) {
	set := s.cfg.Rules()
	var del, add []nft.Elem
	s.mu.Lock()
	for _, a := range addrs {
		timeout := clampTimeout(a.ttl)
		v6 := a.addr.Is6()
		want := map[string]bool{}
		sigs := map[string]bool{}
		for _, site := range s.cfg.Cache.Sites(a.addr) {
			var pos []int
			for _, n := range site {
				for _, p := range set.NameRules(n) {
					if s.cfg.HasSets == nil || s.cfg.HasSets(p) {
						pos = append(pos, p)
					}
				}
			}
			slices.Sort(pos)
			pos = slices.Compact(pos)
			sigs[fmt.Sprint(pos)] = true
			for _, p := range pos {
				want[nft.DNSSet(p, v6)] = true
			}
		}
		if len(sigs) > 1 {
			want[nft.AmbigSet(v6)] = true
		}
		for name := range want {
			k := elemKey{name, a.addr}
			e := nft.Elem{Set: name, Addr: a.addr, Timeout: timeout}
			if old, ok := s.elems[k]; ok && old.until.After(now) {
				if old.until.Sub(now) > old.timeout/2 {
					continue
				}
				del = append(del, e)
			}
			add = append(add, e)
			s.elems[k] = elemTime{now.Add(timeout), timeout}
		}
	}
	s.mu.Unlock()
	if len(add) == 0 || s.cfg.Sets == nil {
		return
	}
	err := s.cfg.Sets.Apply(del, add)
	if err != nil && len(del) > 0 {
		// An element left its set just before: add without deleting.
		err = s.cfg.Sets.Apply(nil, add)
	}
	if err != nil {
		s.log().Warn("dns: the addresses of an answer did not reach the rules' sets", "err", err)
	}
}

// Refill puts every address learned and not yet expired into the sets
// again: the table was loaded anew (the rules changed) with empty sets.
func (s *Server) Refill() {
	now := time.Now()
	s.mu.Lock()
	clear(s.elems)
	addrs := make([]addrTTL, 0, len(s.known))
	for a, until := range s.known {
		if until.After(now) {
			addrs = append(addrs, addrTTL{a, until.Sub(now)})
		}
	}
	s.mu.Unlock()
	for chunk := range slices.Chunk(addrs, 256) {
		s.place(chunk, now)
	}
}

// sweepLoop forgets expired addresses.
func (s *Server) sweepLoop() {
	defer s.wg.Done()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
		}
		now := time.Now()
		s.mu.Lock()
		for k, e := range s.elems {
			if !e.until.After(now) {
				delete(s.elems, k)
			}
		}
		for a, until := range s.known {
			if !until.After(now) {
				delete(s.known, a)
			}
		}
		s.mu.Unlock()
		s.cfg.Cache.Sweep()
	}
}
