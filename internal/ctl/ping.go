//go:build linux

package ctl

// «Проверить показанные» on the servers page (HyRoute 1.3.32-1.3.34,
// internal/app/ping.go): the delay of the servers named, so that the
// fastest working one is seen at once. It is measured as a group's check
// measures its members: a request for the probe address through the
// server, the time to the first byte of the answer (the better of two). A
// server that routes now is measured in place, the others through a
// temporary Hysteria or Xray each. The cores start and connect a few at a
// time (where a dead server takes its seconds); the requests go one server
// at a time, so that no measurement shares the line and the processor with
// another. The results live in memory until hyrouterd exits; they take no
// part in what groups pick.

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/zilbergsp/hyrouter/internal/edition"
	"github.com/zilbergsp/hyrouter/internal/groups"
	"github.com/zilbergsp/hyrouter/internal/hysteria"
	"github.com/zilbergsp/hyrouter/internal/socks5"
)

const (
	// pingTries: the first request through a server just started also
	// resolves the name and warms the connection up.
	pingTries = 2
)

// Bounds (variables for tests): how long a server may take to connect,
// and a whole run.
var (
	pingConnectWait      = 8 * time.Second
	pingConnectWaitVLESS = 20 * time.Second
	pingBudget           = 10 * time.Minute
)

// pingWorkers is how many servers are started and connected at a time:
// each one that does not route starts a core of its own (Lite: as many
// as a group runs).
func pingWorkers() int { return min(6, edition.Current.GroupRun) }

// pingResult is the last measurement of a server.
type pingResult struct {
	ms  int64 // 0: no answer, err says why
	err string
	at  time.Time
	p   hysteria.Profile // what was measured: a server changed since has no result
}

// pingRun is a run under way.
type pingRun struct {
	cancel context.CancelFunc
	left   map[string]bool // not measured yet
	total  int
}

// pingCtl is the controller's part.
type pingCtl struct {
	mu      sync.Mutex
	results map[string]pingResult
	run     *pingRun
}

// PingResult is a server's measurement for the page.
type PingResult struct {
	Ms    int64  `json:"ms,omitempty"`
	Error string `json:"error,omitempty"`
	At    int64  `json:"at"` // Unix seconds
}

// PingView is the run under way and the results.
type PingView struct {
	Running bool                  `json:"running"`
	Done    int                   `json:"done"`
	Total   int                   `json:"total"`
	Pending []string              `json:"pending"` // not measured yet
	Results map[string]PingResult `json:"results"`
}

// Pings reports the run and the results of the servers as they are now.
func (c *Controller) Pings() PingView {
	byID := map[string]hysteria.Profile{}
	for _, p := range c.State().Servers {
		byID[p.ID] = p
	}
	c.ping.mu.Lock()
	defer c.ping.mu.Unlock()
	v := PingView{Pending: []string{}, Results: map[string]PingResult{}}
	if r := c.ping.run; r != nil {
		v.Running, v.Done, v.Total = true, r.total-len(r.left), r.total
		for id := range r.left {
			v.Pending = append(v.Pending, id)
		}
	}
	for id, res := range c.ping.results {
		if p, ok := byID[id]; ok && hysteria.SameConnection(p, res.p) {
			v.Results[id] = PingResult{Ms: res.ms, Error: res.err, At: res.at.Unix()}
		}
	}
	return v
}

// PingServers starts measuring the servers named, all of them when ids is
// empty, and returns at once; the page follows by Pings. While a run is
// under way it only reports that run.
func (c *Controller) PingServers(ids []string) PingView {
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var list []hysteria.Profile
	known := map[string]bool{}
	for _, p := range c.State().Servers {
		known[p.ID] = true
		if len(want) == 0 || want[p.ID] {
			list = append(list, p)
		}
	}
	c.ping.mu.Lock()
	if c.ping.run != nil || len(list) == 0 {
		c.ping.mu.Unlock()
		return c.Pings()
	}
	if c.ping.results == nil {
		c.ping.results = map[string]pingResult{}
	}
	for id := range c.ping.results { // servers deleted since
		if !known[id] {
			delete(c.ping.results, id)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), pingBudget)
	run := &pingRun{cancel: cancel, left: map[string]bool{}, total: len(list)}
	for _, p := range list {
		run.left[p.ID] = true
	}
	c.ping.run = run
	c.ping.mu.Unlock()
	var probe groups.Probe
	if g := c.gview.Load(); g != nil {
		probe = g.probe
	}
	rawURL, _ := probe.Effective()
	go c.runPing(ctx, run, list, rawURL)
	return c.Pings()
}

// PingStop ends the run under way: the servers not measured yet keep what
// they had.
func (c *Controller) PingStop() {
	c.ping.mu.Lock()
	run := c.ping.run
	c.ping.mu.Unlock()
	if run != nil {
		run.cancel()
	}
}

func (c *Controller) runPing(ctx context.Context, run *pingRun, list []hysteria.Profile, rawURL string) {
	defer run.cancel()
	turn := make(chan struct{}, 1) // one measurement at a time
	jobs := make(chan hysteria.Profile)
	var wg sync.WaitGroup
	answered := 0
	for i := 0; i < min(pingWorkers(), len(list)); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				rtt, err := c.pingOne(ctx, p, rawURL, turn)
				c.ping.mu.Lock()
				delete(run.left, p.ID)
				switch {
				case ctx.Err() != nil || errors.Is(err, groups.ErrCanceled):
					// Stopped: no result, the last one stays.
				case err != nil:
					c.ping.results[p.ID] = pingResult{err: err.Error(), at: time.Now(), p: p}
				default:
					c.ping.results[p.ID] = pingResult{ms: max(1, rtt.Milliseconds()), at: time.Now(), p: p}
					answered++
				}
				c.ping.mu.Unlock()
			}
		}()
	}
feed:
	for _, p := range list {
		select {
		case jobs <- p:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	c.ping.mu.Lock()
	c.ping.run = nil
	c.ping.mu.Unlock()
	c.log.Info("servers measured", "servers", run.total, "answered", answered)
}

// pingOne measures one server: in place when it routes now, else through
// a temporary endpoint.
func (c *Controller) pingOne(ctx context.Context, p hysteria.Profile, rawURL string, turn chan struct{}) (time.Duration, error) {
	if ep := c.tunnels.Get(p.ID); ep != nil && ep.Available() {
		// A routing endpoint, measured past its Dial: a probe that fails
		// is not a connection of a device that failed.
		return pingMeasure(ctx, rawURL, turn, func(ctx context.Context, dst socks5.Addr) (net.Conn, error) {
			return c.probeDial(ctx, p.ID, dst)
		})
	}
	ep, release := c.tunnels.Acquire(p)
	defer release()
	if ep == nil {
		return 0, errors.New("сервер не запустился")
	}
	wait := pingConnectWait
	if p.IsVLESS() {
		wait = pingConnectWaitVLESS
	}
	if !waitConnected(ctx, ep.Status, wait) {
		if ctx.Err() != nil {
			return 0, groups.ErrCanceled
		}
		if m := ep.Status().Message; m != "" {
			return 0, errors.New(m)
		}
		return 0, errors.New("не подключился")
	}
	return pingMeasure(ctx, rawURL, turn, func(ctx context.Context, dst socks5.Addr) (net.Conn, error) {
		cl := ep.SOCKS()
		return cl.Connect(ctx, dst)
	})
}

// pingMeasure is the better of pingTries probes in the server's turn; an
// error only when none passed.
func pingMeasure(ctx context.Context, rawURL string, turn chan struct{}, dial func(context.Context, socks5.Addr) (net.Conn, error)) (time.Duration, error) {
	select {
	case turn <- struct{}{}:
	case <-ctx.Done():
		return 0, groups.ErrCanceled
	}
	defer func() { <-turn }()
	var best time.Duration
	var last error
	for i := 0; i < pingTries; i++ {
		pctx, cancel := context.WithTimeout(ctx, groups.ProbeTimeout+time.Second)
		rtt, err := groups.ProbeOnce(pctx, dial, rawURL, nil)
		cancel()
		switch {
		case errors.Is(err, groups.ErrCanceled):
			if ctx.Err() != nil {
				return 0, err
			}
			last = err
		case err != nil:
			last = err
		case best == 0 || rtt < best:
			best = rtt
		}
	}
	if best > 0 {
		return best, nil
	}
	return 0, last
}
