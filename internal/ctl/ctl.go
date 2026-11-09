//go:build linux

// Package ctl is HyRouter's controller: it turns the settings in
// /etc/hyrouter (/opt/etc/hyrouter on KeeneticOS) into routing
// (docs/ARCHITECTURE.md) and back. Start readies the cores, the relay,
// the DNS and the policy routing and loads the firewall's rules last (the
// nftables table, or the iptables chains: fw_nft.go, fw_ipt.go), so the
// first connection they send anywhere finds everything in place; Stop
// removes the rules first, so the LAN goes on as without HyRouter.
package ctl

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zilbergsp/hyrouter/internal/cores"
	"github.com/zilbergsp/hyrouter/internal/dnscache"
	"github.com/zilbergsp/hyrouter/internal/dnsd"
	"github.com/zilbergsp/hyrouter/internal/dnspolicy"
	"github.com/zilbergsp/hyrouter/internal/dnsproxy"
	"github.com/zilbergsp/hyrouter/internal/edition"
	"github.com/zilbergsp/hyrouter/internal/flows"
	"github.com/zilbergsp/hyrouter/internal/groups"
	"github.com/zilbergsp/hyrouter/internal/hysteria"
	"github.com/zilbergsp/hyrouter/internal/kernel"
	"github.com/zilbergsp/hyrouter/internal/logx"
	"github.com/zilbergsp/hyrouter/internal/platform"
	"github.com/zilbergsp/hyrouter/internal/relay"
	"github.com/zilbergsp/hyrouter/internal/rules"
	"github.com/zilbergsp/hyrouter/internal/socks5"
	"github.com/zilbergsp/hyrouter/internal/stats"
	"github.com/zilbergsp/hyrouter/internal/store"
	"github.com/zilbergsp/hyrouter/internal/subs"
	"github.com/zilbergsp/hyrouter/internal/tunnels"
)

// Paths on the router.
const (
	RunDir   = "/tmp/hyrouter/run"
	CoresDir = platform.ShareDir + "/bin"
	// SpareCoresDir keeps the cores in RAM when the flash has too little
	// room (HyRouter Lite).
	SpareCoresDir = "/tmp/hyrouter/bin"
)

// Options make a controller.
type Options struct {
	Store    *store.Store
	Log      *slog.Logger
	Redactor *logx.Redactor
	// Version is hyrouterd's (the User-Agent of downloads).
	Version string
}

// Controller owns routing. Its methods are safe for concurrent use.
type Controller struct {
	store    *store.Store
	log      *slog.Logger
	redactor *logx.Redactor
	cores    *cores.Installer
	neigh    kernel.Neighbours
	cache    *dnscache.Cache
	resolver *dnsproxy.Resolver
	tunnels  *tunnels.Manager
	version  string
	groups   *groups.Runtime
	gview    atomic.Pointer[groupView]
	gmu      sync.Mutex // scan
	scan     scanState
	geo      *geoCache
	geoKick  chan bool
	geoMu    sync.Mutex // one update of the rule database at a time
	geoBusy  atomic.Bool
	flows    *flows.Registry
	devs     devices
	stats    *stats.Collector

	rules   rules.Store
	policy  atomic.Pointer[dnspolicy.Policy]
	hasSets atomic.Pointer[map[int]bool]

	mu      sync.Mutex
	st      store.State
	running bool
	relay   *relay.Relay
	dns     *dnsd.Server
	sets    fwSets
	route   kernel.PolicyRouting
	lastErr string
	since   time.Time
	issues  []string
	// probeStop ends the prober and the scanner of groups, ctStop the
	// reader of the kernel's connections.
	probeStop context.CancelFunc
	ctStop    context.CancelFunc
	// fwStop ends the watch of the firewall's rules (fwWatch).
	fwStop context.CancelFunc

	// editMu: one edit of the settings at a time (Edit).
	editMu sync.Mutex
	// subMu: one subscription update at a time.
	subMu sync.Mutex
	// rmu guards restore, the planned restores.
	rmu     sync.Mutex
	restore restoreState
	// zap is the DPI bypass.
	zap zapretCtl
}

// New makes a controller that is not routing yet.
func New(o Options) *Controller {
	c := &Controller{
		store:    o.Store,
		log:      o.Log,
		redactor: o.Redactor,
		version:  o.Version,
		cores:    &cores.Installer{Dir: CoresDir},
		cache:    dnscache.New(),
	}
	if c.log == nil {
		c.log = slog.Default()
	}
	if c.redactor == nil {
		c.redactor = &logx.Redactor{}
	}
	if edition.Lite {
		c.cores.Spare = SpareCoresDir
	}
	c.cache.MaxEntries = edition.Current.DNSCache
	subs.MaxServers = edition.Current.SubServers
	c.geo = newGeoCache(filepath.Join(o.Store.Dir, "geo"))
	c.geoKick = make(chan bool, 1)
	rules.SetGeo(c.geo)
	keep := 300
	if edition.Lite {
		keep = 100
	}
	c.flows = flows.NewRegistry(keep)
	c.stats = stats.New(c.log)
	c.stats.Names = c.statsName
	c.stats.Configure(statFiles{dir: filepath.Join(o.Store.Dir, "stats")})
	c.route = fwRoute
	c.groups = groups.NewRuntime(c.log)
	c.tunnels = &tunnels.Manager{New: c.newRunner, Log: c.log, OnHealth: c.noteHealth, OnDial: c.groups.NoteDial}
	c.resolver = &dnsproxy.Resolver{TunnelDial: c.tunnelDial, Log: c.log}
	return c
}

// noteHealth tells the groups when a server connects or goes down.
func (c *Controller) noteHealth(id string, st hysteria.Status) {
	c.groups.NoteState(id, st.State == hysteria.Connected)
}

// newRunner runs a server's core: Hysteria, or Xray for VLESS.
func (c *Controller) newRunner(p hysteria.Profile, h tunnels.Hooks) tunnels.Runner {
	if r := c.embedded(p, h); r != nil {
		return r
	}
	name := cores.Hysteria
	if p.IsVLESS() {
		name = cores.Xray
	}
	return &hysteria.Supervisor{
		Exe: name,
		ExePath: func() string {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			path, err := c.cores.Path(ctx, name)
			if err != nil {
				c.log.Error("core", "err", err)
				return ""
			}
			return path
		},
		RunDir:       RunDir,
		Profile:      p,
		Redactor:     c.redactor,
		RedactGroup:  h.RedactGroup,
		LogLine:      h.LogLine,
		OnStatus:     h.OnStatus,
		SetServerIPs: h.SetServerIPs,
		Received:     h.Received,
	}
}

// tunnelDial dials through a running server for DNS (nil = not running);
// a group lends its member.
func (c *Controller) tunnelDial(profile string) dnsproxy.Dialer {
	id := c.memberFor(profile)
	if id == "" {
		return nil
	}
	ep := c.tunnels.Get(id)
	if ep == nil || !ep.Available() {
		return nil
	}
	return func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		dst := socks5.Addr{Host: host, Port: port}
		if a, err := netip.ParseAddr(host); err == nil {
			dst = socks5.Addr{IP: a, Port: port}
		}
		return ep.Dial(ctx, dst)
	}
}

// Load reads the settings from the store.
func (c *Controller) Load() error {
	st, err := c.store.Load()
	if err != nil {
		return err
	}
	if st.Settings.DeviceID == "" {
		st.Settings.DeviceID = randomID(16)
		if err := c.store.SaveSettings(st.Settings); err != nil {
			c.log.Warn("settings not saved", "err", err)
		}
	}
	c.mu.Lock()
	c.st = st
	c.mu.Unlock()
	c.setSecrets(st.Servers)
	c.subSecrets(st.Subs)
	c.devs.set(st.Devices)
	if c.stats.Mode() != statsMode(st.Settings) {
		if err := c.stats.SetMode(time.Now(), statsMode(st.Settings)); err != nil {
			c.log.Warn("statistics", "err", err)
		}
	}
	return nil
}

// Run is the controller's background work until ctx ends: the
// subscription updates and the rule database.
func (c *Controller) Run(ctx context.Context) {
	go c.runSubs(ctx)
	go c.runGeo(ctx)
	go c.runStats(ctx)
	go c.runZapretHeal(ctx)
	c.kickGeo()
	<-ctx.Done()
}

// setSecrets hides the servers' passwords in every log line.
func (c *Controller) setSecrets(servers []hysteria.Profile) {
	var secrets []string
	for _, p := range servers {
		secrets = append(secrets, p.Secrets()...)
	}
	c.redactor.SetGroup("servers", secrets...)
}

// State returns a copy of the settings.
func (c *Controller) State() store.State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.st
}

// compiled is what a state makes.
type compiled struct {
	set      *rules.Set
	script   fwScript
	policy   *dnspolicy.Policy
	hasSets  map[int]bool
	profiles []hysteria.Profile
	issues   []string
	// groups are every group with its members expanded; used the ones
	// the routes use; fallback the servers of routes with fallbacks.
	groups   []groups.Group
	used     []string
	fallback []string
	probe    *groups.Probe
}

// compile turns a state into the rule set, the firewall's rules, the DNS
// policy and the servers to run. Issues are what matches nothing for now
// (a missing server or group, a device not in the table, VLESS in Lite).
// run gives the members of a group that run (nil = its first ones);
// extra is the DPI bypass's part of the table.
func compile(st store.State, run func(groups.Group) []string, extra string) (*compiled, error) {
	table := rules.DeviceTable{}
	for _, d := range st.Devices {
		var a rules.DeviceAddrs
		for _, m := range d.MACs {
			if mac, err := rules.ParseMAC(m); err == nil {
				a.MACs = append(a.MACs, mac)
			}
		}
		for _, s := range d.Addrs {
			if p, err := netip.ParsePrefix(s); err == nil {
				a.Prefixes = append(a.Prefixes, p)
			} else if ip, err := netip.ParseAddr(s); err == nil {
				a.Prefixes = append(a.Prefixes, netip.PrefixFrom(ip, ip.BitLen()))
			}
		}
		table[d.ID] = a
	}
	rules.SetDevices(table)
	set, err := rules.Compile(st.Rules)
	if err != nil {
		return nil, err
	}
	set.Main = st.Settings.Main
	out := &compiled{set: set, hasSets: map[int]bool{}, issues: slices.Clone(set.Warnings)}
	byID := map[string]hysteria.Profile{}
	for _, p := range st.Servers {
		byID[p.ID] = p
	}
	out.groups = expandGroups(st)
	gByID := map[string]groups.Group{}
	for _, g := range out.groups {
		gByID[g.ID] = g
	}
	seen := map[string]bool{}
	addServer := func(id string) {
		if seen[id] {
			return
		}
		seen[id] = true
		p, ok := byID[id]
		switch {
		case !ok:
			out.issues = append(out.issues, "сервер "+id+" не найден: соединения через него отклоняются")
		case p.IsVLESS() && !edition.Current.VLESS:
			out.issues = append(out.issues, "«"+p.Name+"»: VLESS не поддерживается в "+edition.Name+", соединения через него отклоняются")
		default:
			out.profiles = append(out.profiles, p)
		}
	}
	for _, id := range set.Profiles() {
		if !groups.IsGroupID(id) {
			addServer(id)
			continue
		}
		g, ok := gByID[id]
		if !ok {
			out.issues = append(out.issues, "группа "+id+" не найдена: соединения через неё отклоняются")
			continue
		}
		out.used = append(out.used, id)
		if len(g.Members) == 0 {
			out.issues = append(out.issues, "в группе «"+g.Name+"» нет серверов: соединения через неё отклоняются")
			continue
		}
		members := firstMembers(g)
		if run != nil {
			members = run(g)
		}
		for _, m := range members {
			addServer(m)
		}
	}
	out.fallback = set.FallbackServers()
	out.probe = st.Groups.Probe
	plan, def := set.Plan()
	for _, r := range plan {
		if !r.Never && r.Sites {
			out.hasSets[r.Pos] = true
		}
	}
	if def.Action == rules.Tunnel && def.Profile == "" {
		out.issues = append(out.issues, "не выбран основной сервер: всё, что идёт «через VPN» без своего сервера, отклоняется")
	}
	var servers []string
	for _, p := range st.Servers {
		servers = append(servers, p.Host)
	}
	if out.policy, err = dnspolicy.Compile(st.Settings.DNS, dnspolicy.Names{Servers: servers}); err != nil {
		return nil, fmt.Errorf("DNS: %w", err)
	}
	out.script, err = fwCompile(plan, def, st.Settings, extra)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// install makes a compiled state the one in force.
func (c *Controller) install(cp *compiled) {
	c.rules.Swap(cp.set)
	c.policy.Store(cp.policy)
	c.hasSets.Store(&cp.hasSets)
	if cp.policy != nil {
		c.resolver.Configure(cp.policy.TunnelSpec, cp.policy.DirectSpec)
	}
	c.groups.SetGroups(cp.groups)
	var probe groups.Probe
	if cp.probe != nil {
		probe = *cp.probe
	}
	_, every := probe.Effective()
	c.groups.SetInterval(every)
	c.gview.Store(newGroupView(cp.groups, cp.used, cp.fallback, cp.probe))
	c.tunnels.Sync(cp.profiles)
	c.issues = cp.issues
}

// resync starts and stops servers after the scanner chose a large
// group's running members again.
func (c *Controller) resync() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return
	}
	cp, err := compile(c.st, c.runMembers, c.zapretExtra())
	if err != nil {
		return
	}
	c.install(cp)
}

// reloadTable loads the table again (the DPI bypass's part changed).
func (c *Controller) reloadTable(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return nil
	}
	cp, err := compile(c.st, c.runMembers, c.zapretExtra())
	if err != nil {
		return err
	}
	c.install(cp)
	if err := c.load(ctx, cp); err != nil {
		return err
	}
	c.dns.Refill()
	return nil
}

// load puts the compiled rules in force; what the firewall could not do
// in full joins the issues. c.mu is held.
func (c *Controller) load(ctx context.Context, cp *compiled) error {
	warnings, err := fwLoad(ctx, cp.script, c.st.Settings.LAN)
	for _, w := range warnings {
		c.log.Warn(w)
	}
	c.issues = append(c.issues, warnings...)
	return err
}

// Running reports whether HyRouter routes the LAN.
func (c *Controller) Running() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.running
}

// Start routes the LAN by the settings.
func (c *Controller) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return nil
	}
	err := c.startLocked(ctx)
	if err != nil {
		c.lastErr = err.Error()
		c.stopLocked()
		return err
	}
	c.running, c.lastErr, c.since = true, "", time.Now()
	go c.zapretApply()
	return nil
}

func (c *Controller) startLocked(ctx context.Context) error {
	cp, err := compile(c.st, c.runMembers, c.zapretExtra())
	if err != nil {
		return err
	}
	// The cores of the servers in use, before any traffic waits for them.
	for _, p := range cp.profiles {
		if !needsCore(p) {
			continue
		}
		name := cores.Hysteria
		if p.IsVLESS() {
			name = cores.Xray
		}
		if _, err := c.cores.Path(ctx, name); err != nil {
			return err
		}
	}
	c.install(cp)
	s := c.st.Settings
	if c.sets, err = fwOpenSets(); err != nil {
		return err
	}
	c.relay, err = relay.Start(relay.Config{
		TunnelPort: s.TunnelPort,
		NamePort:   s.NamePort,
		Rules:      c.rules.Load,
		Names:      c.cache.Names,
		MAC:        c.neigh.Lookup,
		Pick:       c.pick,
		Limit:      edition.Current.Relay,
		Flows:      c.flows,
		Device:     c.devs.name,
		Log:        c.log,
	})
	if err != nil {
		return fmt.Errorf("relay: %w", err)
	}
	c.dns, err = dnsd.Start(dnsd.Config{
		Port:     s.DNSPort,
		Upstream: platform.DNSUpstream(s.LAN),
		Policy:   c.policy.Load,
		Rules:    c.rules.Load,
		HasSets:  c.hasSet,
		MAC:      c.neigh.Lookup,
		Resolver: c.resolver,
		Cache:    c.cache,
		Sets:     c.sets,
		Log:      c.log,
	})
	if err != nil {
		return fmt.Errorf("DNS: %w", err)
	}
	if err := c.route.Install(); err != nil {
		return fmt.Errorf("маршрутизация: %w", err)
	}
	if err := c.load(ctx, cp); err != nil {
		return err
	}
	// HyRouter's rules decide the LAN now: the boot's kill switch goes.
	if err := fwRemoveGuard(ctx); err != nil {
		c.log.Warn("kill switch: not removed", "err", err)
	}
	c.dns.Refill()
	c.startProber()
	ctCtx, ctCancel := context.WithCancel(context.Background())
	c.ctStop = ctCancel
	go c.runConntrack(ctCtx)
	fwCtx, fwCancel := context.WithCancel(context.Background())
	c.fwStop = fwCancel
	go c.fwWatch(fwCtx)
	for _, i := range cp.issues {
		c.log.Warn(i)
	}
	return nil
}

func (c *Controller) hasSet(pos int) bool {
	if m := c.hasSets.Load(); m != nil {
		return (*m)[pos]
	}
	return false
}

// Stop ends routing: the rules go first, then the rest.
func (c *Controller) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	err := c.stopLocked()
	c.running = false
	return err
}

func (c *Controller) stopLocked() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var errs []error
	c.stopProber()
	c.zapretStop()
	if c.ctStop != nil {
		c.ctStop()
		c.ctStop = nil
	}
	if c.fwStop != nil {
		c.fwStop()
		c.fwStop = nil
	}
	if err := fwRemove(ctx); err != nil {
		errs = append(errs, err)
	}
	if err := c.route.Remove(); err != nil {
		errs = append(errs, err)
	}
	if c.relay != nil {
		c.relay.Close()
		c.relay = nil
	}
	if c.dns != nil {
		c.dns.Close()
		c.dns = nil
	}
	if c.sets != nil {
		c.sets.Close()
		c.sets = nil
	}
	c.tunnels.StopAll()
	return errors.Join(errs...)
}

// Apply makes changed settings take effect: while routing, the rules,
// servers and table are replaced at once (connections already open keep
// their route); a change of ports or interfaces restarts routing.
func (c *Controller) Apply(ctx context.Context, st store.State) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	old := c.st
	c.st = st
	c.setSecrets(st.Servers)
	c.devs.set(st.Devices)
	if !c.running {
		return nil
	}
	o, n := old.Settings, st.Settings
	if !slices.Equal(o.LAN, n.LAN) || o.TunnelPort != n.TunnelPort || o.NamePort != n.NamePort || o.DNSPort != n.DNSPort {
		c.stopLocked()
		if err := c.startLocked(ctx); err != nil {
			c.running, c.lastErr = false, err.Error()
			c.stopLocked()
			return err
		}
		return nil
	}
	cp, err := compile(st, c.runMembers, c.zapretExtra())
	if err != nil {
		return err
	}
	for _, p := range cp.profiles {
		if !needsCore(p) {
			continue
		}
		name := cores.Hysteria
		if p.IsVLESS() {
			name = cores.Xray
		}
		if _, err := c.cores.Path(ctx, name); err != nil {
			return err
		}
	}
	c.install(cp)
	if err := c.load(ctx, cp); err != nil {
		return err
	}
	c.dns.Refill()
	return nil
}

// Check compiles a state without applying it: the web interface saves
// nothing the controller would refuse.
func Check(st store.State) error {
	_, err := compile(st, nil, "")
	return err
}

// Status is the controller for the web interface.
type Status struct {
	Edition string           `json:"edition"`
	Running bool             `json:"running"`
	Since   time.Time        `json:"since"`
	Error   string           `json:"error,omitempty"`
	Issues  []string         `json:"issues"`
	Servers []tunnels.Status `json:"servers"`
	Groups  []GroupStatus    `json:"groups"`
	Relay   int64            `json:"relay"`
	// Guard: the boot's kill switch keeps the LAN closed (routing did not
	// start).
	Guard bool `json:"guard"`
	// Platform is the router's system: "openwrt" or "keenetic".
	Platform string `json:"platform"`
}

// Status reports the state of routing.
func (c *Controller) Status() Status {
	c.mu.Lock()
	st := Status{Edition: edition.Name, Platform: platform.ID, Running: c.running, Since: c.since, Error: c.lastErr, Issues: slices.Clone(c.issues)}
	if c.relay != nil {
		st.Relay = c.relay.Active()
	}
	c.mu.Unlock()
	if st.Issues == nil {
		st.Issues = []string{}
	}
	st.Servers = c.tunnels.Statuses()
	if st.Servers == nil {
		st.Servers = []tunnels.Status{}
	}
	st.Groups = c.groupStatuses()
	if !st.Running {
		st.Guard = guardActive()
	}
	return st
}
