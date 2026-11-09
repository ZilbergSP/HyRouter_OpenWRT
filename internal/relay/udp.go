//go:build linux

package relay

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/zilbergsp/hyrouter/internal/rules"
	"github.com/zilbergsp/hyrouter/internal/socks5"
)

const (
	// udpIdle ends a flow with no datagram either way for this long; DNS
	// flows end sooner.
	udpIdle    = 2 * time.Minute
	udpIdleDNS = 20 * time.Second
	// udpQueue bounds the datagrams kept while a flow is being set up.
	udpQueue = 16
	// udpRefused keeps a flow the rules do not send through a tunnel, so
	// its datagrams are dropped without deciding again each time.
	udpRefused = 10 * time.Second
	// clientBuf and serverBuf are a flow's buffers: Hysteria carries no
	// datagram over socks5.MaxUDPPayload (about 4 KB) from the client, and
	// thousands of flows must fit a small router's memory (Lite).
	clientBuf = 8 << 10
	serverBuf = 16 << 10
)

type flowKey struct{ src, dst netip.AddrPort }

// flow is one client's UDP traffic to one destination. Its first
// datagrams come through the listener; then conn, a transparent socket
// bound to the destination and connected to the client, takes the later
// ones (the kernel's TPROXY finds it first) and sends the replies.
type flow struct {
	key  flowKey
	last atomic.Int64 // unix nanoseconds of the last datagram

	mu      sync.Mutex
	ready   bool
	refused time.Time // the flow is dropped until then
	queue   [][]byte
	assoc   *socks5.UDPAssoc
	conn    *net.UDPConn
	closed  bool
	counted bool
}

func (f *flow) touch() { f.last.Store(time.Now().UnixNano()) }

func (f *flow) close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return
	}
	f.closed = true
	if f.assoc != nil {
		f.assoc.Close()
	}
	if f.conn != nil {
		f.conn.Close()
	}
}

func (r *Relay) udpLoop(l *net.UDPConn) {
	defer r.wg.Done()
	buf := make([]byte, 65535)
	oob := make([]byte, 256)
	for {
		n, oobn, _, src, err := l.ReadMsgUDPAddrPort(buf, oob)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || r.ctx.Err() != nil {
				return
			}
			continue
		}
		dst, ok := origDst(oob[:oobn])
		if !ok {
			continue
		}
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		r.udpDatagram(src, dst, append([]byte(nil), buf[:n]...))
	}
}

// origDst reads a datagram's original destination from its control
// messages (IP_ORIGDSTADDR, IPV6_ORIGDSTADDR).
func origDst(oob []byte) (netip.AddrPort, bool) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.AddrPort{}, false
	}
	for _, m := range msgs {
		switch {
		case m.Header.Level == unix.SOL_IP && m.Header.Type == unix.IP_ORIGDSTADDR && len(m.Data) >= unix.SizeofSockaddrInet4:
			// struct sockaddr_in: family, port (big endian), address.
			a := netip.AddrFrom4([4]byte(m.Data[4:8]))
			return netip.AddrPortFrom(a, binary.BigEndian.Uint16(m.Data[2:4])), true
		case m.Header.Level == unix.SOL_IPV6 && m.Header.Type == unix.IPV6_ORIGDSTADDR && len(m.Data) >= unix.SizeofSockaddrInet6:
			// struct sockaddr_in6: family, port, flow info, address, scope.
			a := netip.AddrFrom16([16]byte(m.Data[8:24])).Unmap()
			return netip.AddrPortFrom(a, binary.BigEndian.Uint16(m.Data[2:4])), true
		}
	}
	return netip.AddrPort{}, false
}

// udpDatagram passes a datagram that came through the listener to its
// flow, setting the flow up first when it is new.
func (r *Relay) udpDatagram(src, dst netip.AddrPort, p []byte) {
	key := flowKey{src, dst}
	r.mu.Lock()
	f := r.flows[key]
	if f == nil {
		if !r.acquire() {
			r.mu.Unlock()
			return
		}
		f = &flow{key: key, counted: true}
		f.touch()
		r.flows[key] = f
		r.mu.Unlock()
		f.queue = append(f.queue, p)
		r.wg.Add(1)
		go r.setUp(f)
		return
	}
	r.mu.Unlock()
	f.touch()
	f.mu.Lock()
	switch {
	case f.closed || time.Now().Before(f.refused):
	case !f.ready:
		if len(f.queue) < udpQueue {
			f.queue = append(f.queue, p)
		}
	default:
		a := f.assoc
		f.mu.Unlock()
		a.WriteTo(p, socks5.AddrFromAddrPort(dst))
		return
	}
	f.mu.Unlock()
}

// setUp decides a new flow, opens its association through the server
// and its socket, and sends the datagrams that came meanwhile.
func (r *Relay) setUp(f *flow) {
	defer r.wg.Done()
	src, dst := f.key.src, f.key.dst
	refuse := func(msg string, args ...any) {
		r.log().Debug(msg, args...)
		f.mu.Lock()
		f.refused = time.Now().Add(udpRefused)
		f.queue = nil
		f.mu.Unlock()
	}
	sub := r.subject(17, src, dst)
	res := r.byDNS(sub)
	if res.Action != rules.Tunnel {
		refuse("relay: a UDP flow the rules do not send through a tunnel: dropped", "rule", res.Rule)
		return
	}
	t, id := r.pickTunnel(res, true, sub, "")
	if t == nil {
		refuse("relay: no server carries UDP for the flow: dropped", "rule", res.Rule, "server", res.Profile)
		return
	}
	ctx, cancel := context.WithTimeout(r.ctx, dialTimeout)
	assoc, err := t.UDPAssociate(ctx)
	cancel()
	if err != nil {
		refuse("relay: UDP through the server failed", "rule", res.Rule, "server", id, "err", err)
		return
	}
	network := "udp4"
	if dst.Addr().Is6() {
		network = "udp6"
	}
	d := net.Dialer{LocalAddr: net.UDPAddrFromAddrPort(dst), Control: transparent}
	c, err := d.DialContext(r.ctx, network, src.String())
	if err != nil {
		assoc.Close()
		refuse("relay: the flow's socket failed", "err", err)
		return
	}
	conn := c.(*net.UDPConn)
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		assoc.Close()
		conn.Close()
		return
	}
	f.assoc, f.conn, f.ready = assoc, conn, true
	queued := f.queue
	f.queue = nil
	f.mu.Unlock()
	to := socks5.AddrFromAddrPort(dst)
	limit := socks5.MaxUDPPayload(to)
	for _, p := range queued {
		if len(p) <= limit {
			assoc.WriteTo(p, to)
		}
	}
	r.wg.Add(2)
	go func() { // client → server
		defer r.wg.Done()
		buf := make([]byte, clientBuf)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				f.close()
				return
			}
			f.touch()
			if n <= limit {
				assoc.WriteTo(buf[:n], to)
			}
		}
	}()
	go func() { // server → client
		defer r.wg.Done()
		buf := make([]byte, serverBuf)
		for {
			n, _, err := assoc.ReadFrom(buf)
			if err != nil {
				f.close()
				return
			}
			f.touch()
			conn.Write(buf[:n])
		}
	}()
}

// sweepLoop ends idle and refused flows.
func (r *Relay) sweepLoop() {
	defer r.wg.Done()
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-t.C:
		}
		now := time.Now()
		r.mu.Lock()
		for k, f := range r.flows {
			idle := udpIdle
			if k.dst.Port() == 53 {
				idle = udpIdleDNS
			}
			f.mu.Lock()
			done := f.closed || now.Sub(time.Unix(0, f.last.Load())) > idle || !f.refused.IsZero() && now.After(f.refused)
			f.mu.Unlock()
			if done {
				f.close()
				delete(r.flows, k)
				if f.counted {
					r.release()
				}
			}
		}
		r.mu.Unlock()
	}
}
