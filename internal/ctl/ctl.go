//go:build linux

// Package ctl is HyRouter's controller: it turns the settings in
// /etc/hyrouter into routing (docs/ARCHITECTURE.md) and back. Start
// readies the cores, the relay, the DNS and the policy routing and loads
// the nftables table last, so the first connection it sends anywhere
// finds everything in place; Stop removes the table first, so the LAN
// goes on as without HyRouter.
package ctl

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
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
	"github.com/zilbergsp/hyrouter/internal/hysteria"
	"github.com/zilbergsp/hyrouter/internal/kernel"
	"github.com/zilbergsp/hyrouter/internal/logx"
	"github.com/zilbergsp/hyrouter/internal/nft"
	"github.com/zilbergsp/hyrouter/internal/relay"
	"github.com/zilbergsp/hyrouter/internal/rules"
	"github.com/zilbergsp/hyrouter/internal/socks5"
	"github.com/zilbergsp/hyrouter/internal/store"
	"github.com/zilbergsp/hyrouter/internal/tunnels"
)

// Paths on the router.
const (
	RunDir   = "/tmp/hyrouter/run"
	CoresDir = "/usr/share/hyrouter/bin"
	// SpareCoresDir keeps the cores in RAM when the flash has too little
	// room (HyRouter Lite).
	SpareCoresDir = "/tmp/hyrouter/bin"
	dnsmasq       = "127.0.0.1:53"
)

// Options make a controller.
type Options struct {
	Store    *store.Store
	Log      *slog.Logger
	Redactor *logx.Redactor
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

	rules   rules.Store
	policy  atomic.Pointer[dnspolicy.Policy]
	hasSets atomic.Pointer[map[int]bool]

	mu      sync.Mutex
	st      store.State
	running bool
	relay   *relay.Relay
	dns     *dnsd.Server
	sets    *nft.Sets
	route   kernel.PolicyRouting
	lastErr string
	since   time.Time
	issues  []string
}

// New makes a controller that is not routing yet.
func New(o Options) *Controller {
	c := &Controller{
		store:    o.Store,
		log:      o.Log,
		redactor: o.Redactor,
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
	c.route = kernel.PolicyRouting{Mark: nft.MarkTProxy, Mask: nft.MarkTProxy, Table: nft.RouteTable, Priority: nft.RulePriority}
	c.tunnels = &tunnels.Manager{New: c.newRunner, Log: c.log}
	c.resolver = &dnsproxy.Resolver{TunnelDial: c.tunnelDial, Log: c.log}
	return c
}

// newRunner runs a server's core: Hysteria, or Xray for VLESS.
func (c *Controller) newRunner(p hysteria.Profile, h tunnels.Hooks) tunnels.Runner {
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

// tunnelDial dials through a running server for DNS (nil = not running).
func (c *Controller) tunnelDial(profile string) dnsproxy.Dialer {
	ep := c.tunnels.Get(profile)
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

// tunnelFor gives the relay a server's way out (nil when not running).
func (c *Controller) tunnelFor(profile string) relay.Tunnel {
	if ep := c.tunnels.Get(profile); ep != nil {
		return ep
	}
	return nil
}

// Load reads the settings from the store.
func (c *Controller) Load() error {
	st, err := c.store.Load()
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.st = st
	c.mu.Unlock()
	c.setSecrets(st.Servers)
	return nil
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
	script   string
	policy   *dnspolicy.Policy
	hasSets  map[int]bool
	profiles []hysteria.Profile
	issues   []string
}

// compile turns a state into the rule set, the nftables script, the DNS
// policy and the servers to run. Issues are what matches nothing for now
// (a missing server, a device not in the table, VLESS in Lite).
func compile(st store.State) (*compiled, error) {
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
	for _, id := range set.Profiles() {
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
	s := st.Settings
	out.script, err = nft.Compile(plan, def, nft.Options{LAN: s.LAN, TunnelPort: s.TunnelPort, NamePort: s.NamePort, DNSPort: s.DNSPort})
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
	c.tunnels.Sync(cp.profiles)
	c.issues = cp.issues
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
	return nil
}

func (c *Controller) startLocked(ctx context.Context) error {
	cp, err := compile(c.st)
	if err != nil {
		return err
	}
	// The cores of the servers in use, before any traffic waits for them.
	for _, p := range cp.profiles {
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
	if c.sets, err = nft.OpenSets(); err != nil {
		return err
	}
	c.relay, err = relay.Start(relay.Config{
		TunnelPort: s.TunnelPort,
		NamePort:   s.NamePort,
		Rules:      c.rules.Load,
		Names:      c.cache.Names,
		MAC:        c.neigh.Lookup,
		Tunnel:     c.tunnelFor,
		Limit:      edition.Current.Relay,
		Log:        c.log,
	})
	if err != nil {
		return fmt.Errorf("relay: %w", err)
	}
	c.dns, err = dnsd.Start(dnsd.Config{
		Port:     s.DNSPort,
		Upstream: dnsmasq,
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
	if err := nft.Load(ctx, cp.script); err != nil {
		return err
	}
	c.dns.Refill()
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

// Stop ends routing: the table goes first, then the rest.
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
	if err := nft.Remove(ctx); err != nil {
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
	cp, err := compile(st)
	if err != nil {
		return err
	}
	for _, p := range cp.profiles {
		name := cores.Hysteria
		if p.IsVLESS() {
			name = cores.Xray
		}
		if _, err := c.cores.Path(ctx, name); err != nil {
			return err
		}
	}
	c.install(cp)
	if err := nft.Load(ctx, cp.script); err != nil {
		return err
	}
	c.dns.Refill()
	return nil
}

// Check compiles a state without applying it: the web interface saves
// nothing the controller would refuse.
func Check(st store.State) error {
	_, err := compile(st)
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
	Relay   int64            `json:"relay"`
}

// Status reports the state of routing.
func (c *Controller) Status() Status {
	c.mu.Lock()
	st := Status{Edition: edition.Name, Running: c.running, Since: c.since, Error: c.lastErr, Issues: slices.Clone(c.issues)}
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
	return st
}
