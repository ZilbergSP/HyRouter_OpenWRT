package hycore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	coreErrs "github.com/apernet/hysteria/core/v2/errors"

	"github.com/zilbergsp/hyrouter/internal/hysteria"
	"github.com/zilbergsp/hyrouter/internal/socks5"
	"github.com/zilbergsp/hyrouter/internal/tunnels"
)

// Backoff of the connection attempts: 2, 4, 8… seconds, at most a minute.
var (
	backoffMin = 2 * time.Second
	backoffMax = time.Minute
	// steady: a connection this long resets the backoff.
	steady = time.Minute
)

// Runner is one server's client (tunnels.Runner).
type Runner struct {
	Profile hysteria.Profile
	Hooks   tunnels.Hooks
	Log     *slog.Logger
	// Resolve finds the server's addresses (nil: the system's resolver).
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)

	mu        sync.Mutex
	st        hysteria.Status
	cl        client.Client
	srv       *socks5.Server
	socks     socks5.Client
	cancel    context.CancelFunc
	done      chan struct{}
	available atomic.Bool
}

func (r *Runner) log() *slog.Logger {
	if r.Log == nil {
		return slog.Default()
	}
	return r.Log
}

func (r *Runner) setStatus(f func(*hysteria.Status)) {
	r.mu.Lock()
	f(&r.st)
	st := r.st
	r.mu.Unlock()
	r.available.Store(st.State == hysteria.Connected)
	if r.Hooks.OnStatus != nil {
		r.Hooks.OnStatus(st)
	}
}

// Start begins connecting; it returns at once.
func (r *Runner) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	srv := &socks5.Server{
		Dial: func(network, addr string) (net.Conn, error) { return r.tcp(addr) },
		UDP:  func() (socks5.UDPSession, error) { return r.udp() },
	}
	if err := srv.Listen("127.0.0.1:0"); err != nil {
		cancel()
		return err
	}
	r.mu.Lock()
	r.cancel, r.done, r.srv = cancel, make(chan struct{}), srv
	r.socks = socks5.Client{Server: srv.Addr()}
	r.st = hysteria.Status{State: hysteria.Connecting, SOCKS: srv.Addr()}
	done := r.done
	r.mu.Unlock()
	go r.run(ctx, done)
	return nil
}

// Stop ends the client and its SOCKS5 server.
func (r *Runner) Stop() {
	r.mu.Lock()
	cancel, done, srv, cl := r.cancel, r.done, r.srv, r.cl
	r.cancel, r.srv, r.cl = nil, nil, nil
	r.socks = socks5.Client{}
	r.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	if cl != nil {
		cl.Close()
	}
	srv.Close()
	<-done
	r.setStatus(func(s *hysteria.Status) { *s = hysteria.Status{State: hysteria.Stopped} })
}

// run connects, and again after a failure, until ctx ends.
func (r *Runner) run(ctx context.Context, done chan struct{}) {
	defer close(done)
	wait := backoffMin
	for ctx.Err() == nil {
		start := time.Now()
		cl, info, err := r.connect(ctx)
		if err != nil {
			r.log().Warn("hysteria: not connected", "server", r.Profile.Name, "err", err)
			r.setStatus(func(s *hysteria.Status) {
				s.State, s.Message, s.RetryIn = hysteria.Failed, err.Error(), wait
				s.Restarts++
			})
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			wait = min(wait*2, backoffMax)
			continue
		}
		r.mu.Lock()
		if r.cancel == nil {
			r.mu.Unlock()
			cl.Close()
			return
		}
		r.cl = cl
		r.mu.Unlock()
		r.log().Info("hysteria: connected", "server", r.Profile.Name, "udp", info.UDPEnabled)
		r.setStatus(func(s *hysteria.Status) {
			s.State, s.Message, s.UDPEnabled, s.RetryIn = hysteria.Connected, "", info.UDPEnabled, 0
		})
		// The connection lives until a stream finds it closed (tcp, udp)
		// or the runner stops.
		r.wait(ctx, cl)
		if time.Since(start) >= steady {
			wait = backoffMin
		}
		if ctx.Err() == nil {
			r.setStatus(func(s *hysteria.Status) {
				s.State, s.Message = hysteria.Connecting, "соединение с сервером потеряно"
			})
		}
	}
}

// wait returns when the client's connection is gone: a use found it
// closed (lost), or the runner stopped. A quiet connection is checked
// every few seconds by opening a UDP session, which costs no stream.
func (r *Runner) wait(ctx context.Context, cl client.Client) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		r.mu.Lock()
		cur := r.cl
		r.mu.Unlock()
		if cur != cl {
			return // lost: tcp or udp dropped it
		}
	}
}

// connect resolves the server, tells the hooks its addresses and makes
// the client.
func (r *Runner) connect(ctx context.Context) (client.Client, *client.HandshakeInfo, error) {
	p := r.Profile
	var ips []netip.Addr
	if a, err := netip.ParseAddr(p.Host); err == nil {
		ips = []netip.Addr{a.Unmap()}
	} else {
		resolve := r.Resolve
		if resolve == nil {
			resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
				return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			}
		}
		rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		found, err := resolve(rctx, p.Host)
		cancel()
		if err != nil || len(found) == 0 {
			return nil, nil, fmt.Errorf("адрес сервера не найден: %v", err)
		}
		for _, a := range found {
			ips = append(ips, a.Unmap())
		}
	}
	// The exclusions must hold before the first packet.
	if r.Hooks.SetServerIPs != nil {
		if err := r.Hooks.SetServerIPs(ips); err != nil {
			return nil, nil, err
		}
	}
	r.setStatus(func(s *hysteria.Status) { s.ServerIPs, s.State = ips, hysteria.Connecting })
	// The address excluded is the one connected to.
	cfg, err := Config(p, ips[0].String())
	if err != nil {
		return nil, nil, err
	}
	type result struct {
		cl   client.Client
		info *client.HandshakeInfo
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		cl, info, err := client.NewClient(cfg)
		ch <- result{cl, info, err}
	}()
	select {
	case res := <-ch:
		return res.cl, res.info, explain(res.err)
	case <-ctx.Done():
		go func() {
			if res := <-ch; res.cl != nil {
				res.cl.Close()
			}
		}()
		return nil, nil, ctx.Err()
	}
}

// explain words the core's errors for the user.
func explain(err error) error {
	var auth coreErrs.AuthError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &auth):
		return fmt.Errorf("сервер не принял пароль (код %d)", auth.StatusCode)
	}
	return err
}

// lost drops a client a use found closed: run connects again.
func (r *Runner) lost(cl client.Client, err error) {
	var closed coreErrs.ClosedError
	if !errors.As(err, &closed) {
		return
	}
	r.mu.Lock()
	if r.cl == cl {
		r.cl = nil
	}
	r.mu.Unlock()
	cl.Close()
	r.available.Store(false)
}

func (r *Runner) current() (client.Client, error) {
	r.mu.Lock()
	cl := r.cl
	r.mu.Unlock()
	if cl == nil {
		return nil, errors.New("hysteria: нет соединения с сервером")
	}
	return cl, nil
}

func (r *Runner) tcp(addr string) (net.Conn, error) {
	cl, err := r.current()
	if err != nil {
		return nil, err
	}
	c, err := cl.TCP(addr)
	if err != nil {
		r.lost(cl, err)
		return nil, err
	}
	return c, nil
}

func (r *Runner) udp() (socks5.UDPSession, error) {
	cl, err := r.current()
	if err != nil {
		return nil, err
	}
	u, err := cl.UDP()
	if err != nil {
		r.lost(cl, err)
		return nil, err
	}
	return u, nil
}

// Status is the runner's state.
func (r *Runner) Status() hysteria.Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.st
	st.ServerIPs = append([]netip.Addr(nil), r.st.ServerIPs...)
	return st
}

// Available: connected.
func (r *Runner) Available() bool { return r.available.Load() }

// UDPAvailable: connected, and the server carries UDP.
func (r *Runner) UDPAvailable() bool {
	if !r.available.Load() {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.st.UDPEnabled
}

// SOCKS is the SOCKS5 server of the client.
func (r *Runner) SOCKS() socks5.Client {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.socks
}

// Dial opens a TCP connection through the server.
func (r *Runner) Dial(ctx context.Context, dst socks5.Addr) (net.Conn, error) {
	c := r.SOCKS()
	if c.Server == "" {
		return nil, errors.New("hysteria: не запущен")
	}
	return c.Connect(ctx, dst)
}

// UDPAssociate opens a UDP association through the server.
func (r *Runner) UDPAssociate(ctx context.Context) (*socks5.UDPAssoc, error) {
	c := r.SOCKS()
	if c.Server == "" {
		return nil, errors.New("hysteria: не запущен")
	}
	return c.UDPAssociate(ctx)
}
