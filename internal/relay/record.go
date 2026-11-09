//go:build linux

package relay

import (
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zilbergsp/hyrouter/internal/flows"
	"github.com/zilbergsp/hyrouter/internal/rules"
	"github.com/zilbergsp/hyrouter/internal/socks5"
)

// Every connection and UDP flow the relay carries is a flows.Record (the
// «Соединения» page and the statistics): the device it comes from, where
// it goes, the rule, the server and group, and its bytes as they move.

// open starts the record of a connection or flow from src (nil without a
// registry).
func (r *Relay) open(sub rules.Subject, src netip.AddrPort) *flows.Record {
	if r.cfg.Flows == nil {
		return nil
	}
	rec := &flows.Record{Proto: sub.Proto, Src: src, Dst: sub.Dst}
	if r.cfg.Device != nil {
		rec.Process, rec.Path = r.cfg.Device(sub.MAC, sub.Src)
	}
	return r.cfg.Flows.Open(rec)
}

// end finishes a record.
func (r *Relay) end(rec *flows.Record) {
	if rec != nil {
		r.cfg.Flows.Close(rec, time.Now())
	}
}

// decided puts a decision into a record.
func decided(rec *flows.Record, res rules.Result, host string, src rules.DomainSource, outcome string) {
	if rec == nil {
		return
	}
	rec.Set(func(f *flows.Fields) {
		f.Rule, f.Route, f.Outcome, f.Stage = res.Rule, res.Action.String(), outcome, "kernel"
		if host != "" {
			f.Domain, f.DomainSrc, f.Stage = host, src.String(), "sniff"
		}
		if res.Action == rules.Tunnel {
			f.Profile, f.Group, f.Failover = res.Profile, res.Group, res.Failover
		}
	})
}

// countReader counts the bytes read through it.
type countReader struct {
	r io.Reader
	n *atomic.Int64
}

func (c countReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	if n > 0 {
		c.n.Add(int64(n))
	}
	return n, err
}

// pipeCounted is socks5.Pipe that counts into rec as the bytes move: sent
// is what the device sends, received what comes back.
func pipeCounted(c, up net.Conn, rec *flows.Record) {
	if rec == nil {
		socks5.Pipe(c, up)
		return
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := io.Copy(c, countReader{up, &rec.Recv})
		finish(c, up, err)
	}()
	_, err := io.Copy(up, countReader{c, &rec.Sent})
	finish(up, c, err)
	wg.Wait()
}

// finish ends one direction: a clean end half-closes the other side, an
// error resets both (a truncated download must not look complete).
func finish(dst, src net.Conn, err error) {
	if err != nil {
		socks5.Abort(dst)
		socks5.Abort(src)
		return
	}
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
		return
	}
	dst.Close()
}
