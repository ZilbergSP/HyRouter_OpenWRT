//go:build linux

package ctl

import (
	"context"
	"net"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/zilbergsp/hyrouter/internal/edition"
	"github.com/zilbergsp/hyrouter/internal/groups"
	"github.com/zilbergsp/hyrouter/internal/hysteria"
	"github.com/zilbergsp/hyrouter/internal/relay"
	"github.com/zilbergsp/hyrouter/internal/rules"
	"github.com/zilbergsp/hyrouter/internal/socks5"
	"github.com/zilbergsp/hyrouter/internal/store"
)

// Server groups and fallbacks (docs/ARCHITECTURE.md, «Группы и запасные
// серверы»). A Tunnel decision's target, or one of its fallbacks, may be a
// group, which resolves to one of its members when a new connection is
// decided (pick). A group with no usable member refuses like a server that
// is down: VPN traffic never goes direct.
//
// A group runs at most edition.Current.GroupRun members at once (a
// process each). A larger one (a subscription's servers) runs its best
// members; the scanner measures the others a few at a time through
// temporary endpoints and swaps in a better one.

var (
	groupScanEvery   = 20 * time.Second // a scanner round
	groupScanStale   = 30 * time.Minute // a measurement older than this is taken again
	groupScanBadWait = time.Hour        // a member that failed is measured again after this
	connectWait      = 20 * time.Second // a temporary Hysteria to connect
	connectWaitVLESS = 45 * time.Second // Xray takes up to three starts
)

// groupScanBatch is the temporary endpoints at once, all groups together.
func groupScanBatch() int { return max(1, edition.Current.GroupRun/3) }

// scanState is the scanner's memory (Controller.gmu).
type scanState struct {
	// run: the chosen members of each large group.
	run map[string][]string
	// scanned: when a member was last measured and whether it answered.
	scanned map[string]scanResult
}

type scanResult struct {
	at time.Time
	ok bool
}

// expandGroups returns the groups with their members expanded: the
// servers listed, then every server of their subscriptions that the
// subscription still lists, each once. IDs that are no server are left
// out.
func expandGroups(st store.State) []groups.Group {
	exists := make(map[string]bool, len(st.Servers))
	for _, p := range st.Servers {
		exists[p.ID] = true
	}
	out := make([]groups.Group, 0, len(st.Groups.Groups))
	for _, g := range st.Groups.Groups {
		var members []string
		for _, m := range g.Members {
			if exists[m] && !slices.Contains(members, m) {
				members = append(members, m)
			}
		}
		for _, sub := range g.Subs {
			for _, p := range st.Servers {
				if p.Source == "sub:"+sub && !p.Missing && !slices.Contains(members, p.ID) {
					members = append(members, p.ID)
				}
			}
		}
		g.Members = members
		out = append(out, g)
	}
	return out
}

// firstMembers runs a group's first members: Check, and a controller that
// has measured nothing yet.
func firstMembers(g groups.Group) []string {
	return g.Members[:min(len(g.Members), edition.Current.GroupRun)]
}

// runMembers: the members of g that run while it is used: every one of a
// small group, else the chosen ones.
func (c *Controller) runMembers(g groups.Group) []string {
	if len(g.Members) <= edition.Current.GroupRun {
		return g.Members
	}
	c.gmu.Lock()
	defer c.gmu.Unlock()
	return c.chosenLocked(g.ID, g.Members)
}

// chosenLocked keeps the chosen members that are still members and fills
// up to the limit in list order, passing over members whose last
// measurement failed.
func (c *Controller) chosenLocked(gid string, all []string) []string {
	limit := edition.Current.GroupRun
	in := make(map[string]bool, len(all))
	for _, m := range all {
		in[m] = true
	}
	var out []string
	for _, m := range c.scan.run[gid] {
		if in[m] && len(out) < limit {
			out = append(out, m)
		}
	}
	now := time.Now()
	for _, pass := range []bool{false, true} {
		for _, m := range all {
			if len(out) >= limit {
				return out
			}
			r, seen := c.scan.scanned[m]
			bad := seen && !r.ok && now.Sub(r.at) < groupScanBadWait
			if bad == pass && !slices.Contains(out, m) {
				out = append(out, m)
			}
		}
	}
	return out
}

// usable reports whether a server runs and can carry a connection now.
func (c *Controller) usable(udp bool) func(string) bool {
	return func(id string) bool {
		ep := c.tunnels.Get(id)
		if ep == nil {
			return false
		}
		if udp {
			return ep.UDPAvailable()
		}
		return ep.Available()
	}
}

// hasGroup reports a group anywhere in a Tunnel result's chain.
func hasGroup(res rules.Result) bool {
	return groups.IsGroupID(res.Profile) || slices.ContainsFunc(res.Fallback, groups.IsGroupID)
}

// pick is the relay's choice of a server (relay.Config.Pick): it moves a
// Tunnel decision to the first target of its chain (the target, then the
// fallbacks) that can carry the connection, a group resolved to its
// member, and returns that server's way out. Nil when nothing can carry
// it: the connection is refused.
func (c *Controller) pick(res rules.Result, udp bool, h groups.Hint) (rules.Result, relay.Tunnel) {
	res = c.resolve(res, udp, h, true)
	if res.Action != rules.Tunnel || res.Profile == "" {
		return res, nil
	}
	if groups.IsGroupID(res.Profile) {
		// Nothing of the chain was usable and its first target is a group.
		c.groups.NoteRejected(res.Profile)
		return res, nil
	}
	ep := c.tunnels.Get(res.Profile)
	if ep == nil {
		return res, nil
	}
	if !c.usable(udp)(res.Profile) {
		ep.NoteRejected()
		return res, nil
	}
	return res, ep
}

// resolve works in two phases (HyRoute's engine): it peeks every entry of
// the chain (the first healthy one wins, else the first degraded one),
// then commits a choice on that one entry only, so a degraded group
// earlier in the chain never moves its state when a later target gets the
// connection. With nothing usable it stays on the primary target.
func (c *Controller) resolve(res rules.Result, udp bool, h groups.Hint, commit bool) rules.Result {
	if res.NeedsDomain || res.Action != rules.Tunnel {
		return res
	}
	if !hasGroup(res) {
		// The first healthy server (connected, its probe and recent
		// connections fine), else the first connected one, else the
		// primary one (refused).
		if len(res.Fallback) == 0 {
			return res
		}
		chain := append([]string{res.Profile}, res.Fallback...)
		usable := c.usable(udp)
		healthy := func(id string) bool { return usable(id) && c.groups.ServerHealthy(id) }
		for _, pass := range []func(string) bool{healthy, usable} {
			for i, id := range chain {
				if pass(id) {
					if i > 0 {
						res.Profile = id
						res.Rule += " (запасной)"
						res.Failover = true
					}
					return res
				}
			}
		}
		return res
	}
	chain := append([]string{res.Profile}, res.Fallback...)
	skip := map[int]bool{} // entries whose commit found nothing usable any more
	for {
		idx, deg := -1, -1
		var pk, dpk groups.Pick
		for i, t := range chain {
			if skip[i] {
				continue
			}
			p, ok := c.target(t, udp, h, false)
			if !ok {
				continue
			}
			if p.Healthy {
				idx, pk = i, p
				break
			}
			if deg < 0 {
				deg, dpk = i, p
			}
		}
		if idx < 0 {
			idx, pk = deg, dpk
		}
		if idx < 0 {
			return res
		}
		if !commit || !groups.IsGroupID(chain[idx]) {
			return with(res, pk, idx)
		}
		// Choose decides again under the runtime's lock: it may return
		// another member than the peek did; that is still the right entry.
		if p, ok := c.target(chain[idx], udp, h, true); ok {
			return with(res, p, idx)
		}
		skip[idx] = true
	}
}

// with puts the pick of chain entry idx into res.
func with(res rules.Result, p groups.Pick, idx int) rules.Result {
	res.Profile, res.Group = p.Member, p.Group
	res.Failover = p.Failover || idx > 0
	if idx > 0 {
		res.Rule += " (запасной)"
	}
	return res
}

// target decides one chain entry: a server is itself (usable or not), a
// group asks the runtime.
func (c *Controller) target(t string, udp bool, h groups.Hint, commit bool) (groups.Pick, bool) {
	usable := c.usable(udp)
	if !groups.IsGroupID(t) {
		return groups.Pick{Member: t, Healthy: c.groups.ServerHealthy(t)}, usable(t)
	}
	switch {
	case !commit && udp:
		return c.groups.PeekUDP(t, h, usable)
	case !commit:
		return c.groups.Peek(t, h, usable)
	case udp:
		return c.groups.ChooseUDP(t, h, usable)
	}
	return c.groups.Choose(t, h, usable)
}

// memberFor is the server a lookup through target goes through (the DNS
// of «через VPN» names): a server is itself, a group gives its member
// without moving its state.
func (c *Controller) memberFor(target string) string {
	if !groups.IsGroupID(target) {
		return target
	}
	p, ok := c.groups.Choose(target, groups.Hint{App: "hyrouter:dns", Stable: true}, c.usable(false))
	if !ok {
		return ""
	}
	return p.Member
}

// startProber runs the latency prober and the scanner of large groups
// until stopProber.
func (c *Controller) startProber() {
	ctx, cancel := context.WithCancel(context.Background())
	c.probeStop = cancel
	p := &groups.Prober{RT: c.groups, Dial: c.probeDial, Targets: c.probeTargets, Workers: 4, Log: c.log}
	go p.Run(ctx)
	go c.scanGroups(ctx)
}

func (c *Controller) stopProber() {
	if c.probeStop != nil {
		c.probeStop()
		c.probeStop = nil
	}
}

// probeTargets are the running members of the used groups and the
// servers of routes with fallbacks, and the probe settings.
func (c *Controller) probeTargets() ([]string, groups.Probe) {
	g := c.gview.Load()
	if g == nil {
		return nil, groups.Probe{}
	}
	usable := c.usable(false)
	seen := map[string]bool{}
	var out []string
	add := func(m string) {
		if !seen[m] && usable(m) {
			seen[m] = true
			out = append(out, m)
		}
	}
	for _, m := range g.fallback {
		add(m)
	}
	for _, gid := range g.used {
		for _, m := range g.byID[gid].Members {
			add(m)
		}
	}
	return out, g.probe
}

// probeDial goes through a routing endpoint's SOCKS5 directly: not its
// Dial, whose errors count against the member. A member not connected now
// is groups.ErrNotRunning: no result.
func (c *Controller) probeDial(ctx context.Context, member string, dst socks5.Addr) (net.Conn, error) {
	ep := c.tunnels.Get(member)
	if ep == nil || !ep.Available() {
		return nil, groups.ErrNotRunning
	}
	cl := ep.SOCKS()
	return cl.Connect(ctx, dst)
}

// groupView is what the prober, the scanner and the status read of the
// groups in force.
type groupView struct {
	list     []groups.Group // expanded members
	byID     map[string]groups.Group
	used     []string // groups the routes use
	fallback []string // servers of routes with fallbacks
	probe    groups.Probe
}

func newGroupView(list []groups.Group, used, fallback []string, probe *groups.Probe) *groupView {
	v := &groupView{list: list, byID: make(map[string]groups.Group, len(list)), used: used, fallback: fallback}
	for _, g := range list {
		v.byID[g.ID] = g
	}
	if probe != nil {
		v.probe = *probe
	}
	return v
}

// scanGroups is the scanner (startProber): it ends with ctx.
func (c *Controller) scanGroups(ctx context.Context) {
	t := time.NewTicker(groupScanEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		c.scanRound(ctx)
	}
}

// scanRound measures a few members of the used large groups that do not
// run and were not measured lately, then chooses each group's running
// members again.
func (c *Controller) scanRound(ctx context.Context) {
	v := c.gview.Load()
	if v == nil {
		return
	}
	servers := c.State().Servers
	find := func(id string) *hysteria.Profile {
		for i := range servers {
			if servers[i].ID == id {
				return &servers[i]
			}
		}
		return nil
	}
	large := map[string]groups.Group{}
	var todo []hysteria.Profile
	now := time.Now()
	c.gmu.Lock()
	for _, gid := range v.used {
		g := v.byID[gid]
		if len(g.Members) <= edition.Current.GroupRun {
			continue
		}
		large[gid] = g
		running := c.chosenLocked(gid, g.Members)
		for _, m := range g.Members {
			if len(todo) >= groupScanBatch() {
				break
			}
			if slices.Contains(running, m) || slices.ContainsFunc(todo, func(p hysteria.Profile) bool { return p.ID == m }) {
				continue
			}
			wait := groupScanStale
			r, ok := c.scan.scanned[m]
			if ok && !r.ok {
				wait = groupScanBadWait
			}
			if ok && now.Sub(r.at) < wait {
				continue
			}
			if p := find(m); p != nil && (!p.IsVLESS() || edition.Current.VLESS) {
				todo = append(todo, *p)
			}
		}
	}
	c.gmu.Unlock()
	if len(large) == 0 {
		return
	}
	rawURL, _ := v.probe.Effective()
	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make(map[string]bool, len(todo))
	for _, p := range todo {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok := c.scanOne(ctx, p, rawURL)
			mu.Lock()
			results[p.ID] = ok
			mu.Unlock()
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}
	c.gmu.Lock()
	if c.scan.scanned == nil {
		c.scan.scanned = map[string]scanResult{}
	}
	for id, ok := range results {
		c.scan.scanned[id] = scanResult{at: time.Now(), ok: ok}
	}
	changed := false
	for gid, g := range large {
		next := c.rechooseLocked(g)
		if !sameSet(next, c.chosenLocked(gid, g.Members)) {
			if c.scan.run == nil {
				c.scan.run = map[string][]string{}
			}
			c.scan.run[gid] = next
			changed = true
			c.log.Info("server group: running members chosen again", "group", g.Name, "running", len(next), "members", len(g.Members))
		}
	}
	c.gmu.Unlock()
	if changed {
		c.resync()
	}
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}

// scanOne measures one member through a temporary endpoint.
func (c *Controller) scanOne(ctx context.Context, p hysteria.Profile, rawURL string) bool {
	ep, release := c.tunnels.Acquire(p)
	defer release()
	if ep == nil {
		return false
	}
	wait := connectWait
	if p.IsVLESS() {
		wait = connectWaitVLESS
	}
	if !waitConnected(ctx, ep.Status, wait) {
		return false
	}
	pctx, cancel := context.WithTimeout(ctx, groups.ProbeTimeout+time.Second)
	defer cancel()
	rtt, err := groups.ProbeOnce(pctx, func(ctx context.Context, dst socks5.Addr) (net.Conn, error) {
		cl := ep.SOCKS()
		return cl.Connect(ctx, dst)
	}, rawURL, nil)
	if ctx.Err() != nil {
		return false
	}
	c.groups.NoteProbe(p.ID, rtt, err)
	return err == nil
}

// waitConnected waits until a Hysteria connects (true), fails or the time
// is up.
func waitConnected(ctx context.Context, status func() hysteria.Status, wait time.Duration) bool {
	deadline := time.Now().Add(wait)
	t := time.NewTicker(200 * time.Millisecond)
	defer t.Stop()
	for {
		switch status().State {
		case hysteria.Connected:
			return true
		case hysteria.Failed:
			return false
		}
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
		}
	}
}

// rechooseLocked picks a large group's running members (HyRoute's
// scanner). Failover keeps the list order (its first working members).
// The other strategies keep the running ones that work, fill the empty
// places with the fastest measured, and swap at most one running member a
// round for a faster one (by the group's tolerance): a swap stops a
// member, and its connections with it. Members whose last measurement
// failed come last.
func (c *Controller) rechooseLocked(g groups.Group) []string {
	limit := edition.Current.GroupRun
	h := c.groups.Snapshot(g.ID, c.usable(false))
	health := make(map[string]groups.MemberHealth, len(h.Members))
	for _, m := range h.Members {
		health[m.ID] = m
	}
	now := time.Now()
	bad := func(m string) bool {
		if mh, ok := health[m]; ok && (mh.ProbeError != "" || mh.Skipped) {
			return true
		}
		r, ok := c.scan.scanned[m]
		return ok && !r.ok && now.Sub(r.at) < groupScanBadWait
	}
	lat := func(m string) time.Duration {
		if l := health[m].Latency; l > 0 {
			return l
		}
		return time.Hour // unknown: after the measured ones
	}
	if g.Strategy == groups.Failover {
		var out, later []string
		for _, m := range g.Members {
			if bad(m) {
				later = append(later, m)
			} else {
				out = append(out, m)
			}
		}
		out = append(out, later...)
		return out[:min(len(out), limit)]
	}
	tol := time.Duration(g.ToleranceMs) * time.Millisecond
	if tol == 0 {
		tol = groups.DefaultToleranceMs * time.Millisecond
	}
	var next []string
	for _, m := range c.chosenLocked(g.ID, g.Members) {
		if !bad(m) {
			next = append(next, m)
		}
	}
	ranked := slices.Clone(g.Members)
	sort.SliceStable(ranked, func(i, j int) bool { return lat(ranked[i]) < lat(ranked[j]) })
	var spare []string // good members not running, fastest first
	for _, m := range ranked {
		if !bad(m) && !slices.Contains(next, m) {
			spare = append(spare, m)
		}
	}
	for len(next) < limit && len(spare) > 0 {
		next, spare = append(next, spare[0]), spare[1:]
	}
	if len(spare) > 0 && len(next) > 0 {
		worst := slices.MaxFunc(next, func(a, b string) int { return int(lat(a) - lat(b)) })
		if lat(spare[0])+tol < lat(worst) {
			next[slices.Index(next, worst)] = spare[0]
		}
	}
	// Still short (failed ones): they run rather than nothing.
	for _, m := range ranked {
		if len(next) >= limit {
			break
		}
		if !slices.Contains(next, m) {
			next = append(next, m)
		}
	}
	sort.SliceStable(next, func(i, j int) bool { return lat(next[i]) < lat(next[j]) })
	return next
}

// GroupStatus is a group for the web interface.
type GroupStatus struct {
	ID          string         `json:"id"`
	Active      string         `json:"active"`
	Up          int            `json:"up"`
	Running     []string       `json:"running"`
	ProbeBroken bool           `json:"probeBroken"`
	Rejected    int64          `json:"rejected"`
	Used        bool           `json:"used"`
	Members     []MemberStatus `json:"members"`
}

// MemberStatus is one member's measurements.
type MemberStatus struct {
	ID        string `json:"id"`
	LatencyMs int64  `json:"latencyMs"` // 0 = unknown
	Error     string `json:"error,omitempty"`
	Errors    int    `json:"errors"`
	Skipped   bool   `json:"skipped"`
	Reason    string `json:"reason,omitempty"`
}

// groupStatuses reports every group.
func (c *Controller) groupStatuses() []GroupStatus {
	v := c.gview.Load()
	out := []GroupStatus{}
	if v == nil {
		return out
	}
	usable := c.usable(false)
	for _, g := range v.list {
		h := c.groups.Snapshot(g.ID, usable)
		s := GroupStatus{ID: g.ID, Active: h.Active, Up: h.Up, ProbeBroken: h.ProbeBroken, Rejected: h.Rejected,
			Used: slices.Contains(v.used, g.ID), Members: []MemberStatus{}, Running: []string{}}
		for _, m := range h.Members {
			ms := MemberStatus{ID: m.ID, Error: m.ProbeError, Errors: m.Errors, Skipped: m.Skipped, Reason: m.Reason}
			if m.Latency > 0 {
				ms.LatencyMs = max(1, m.Latency.Milliseconds())
			}
			s.Members = append(s.Members, ms)
			if c.tunnels.Get(m.ID) != nil {
				s.Running = append(s.Running, m.ID)
			}
		}
		out = append(out, s)
	}
	return out
}
