//go:build linux

package ctl

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zilbergsp/hyrouter/internal/edition"
	"github.com/zilbergsp/hyrouter/internal/groups"
	"github.com/zilbergsp/hyrouter/internal/hysteria"
	"github.com/zilbergsp/hyrouter/internal/platform"
	"github.com/zilbergsp/hyrouter/internal/rules"
	"github.com/zilbergsp/hyrouter/internal/store"
	"github.com/zilbergsp/hyrouter/internal/zapret"
)

// «Обход DPI» (docs/ARCHITECTURE.md): nfqws2 of zapret2 processes the
// first packets of what the LAN sends directly, so YouTube, Discord and
// the user's sites open without a VPN. The user ticks services; HyRouter
// keeps rules «Обход DPI: …» at the top of the rules so their traffic
// stays direct, puts the bypass's sets and chains into its table, keeps
// nfqws2 running while it routes and, on «Подобрать», finds a method that
// works on this network: one nfqws2 per method on queues 201…, checked
// from the router's own probe ports. The settings are zapret.json.

// Paths.
const (
	// ZapretDir holds nfqws2, lua/ and blobs/ (the package).
	ZapretDir = platform.ShareDir + "/zapret"
	// ZapretLists holds the lists and the made fakes: readable by
	// everyone, nfqws2 rereads them as daemon.
	ZapretLists = "/tmp/hyrouter/zapret"
	// ZapretRulePrefix starts the name of a rule the bypass keeps.
	ZapretRulePrefix = "Обход DPI: "
	zapretUser       = platform.ZapretUser
)

// Tunables (tests).
var (
	zapretSettle     = 1500 * time.Millisecond // nfqws2 opens its queue and reads its lists
	zapretStartWait  = 15 * time.Second
	zapretStagger    = 100 * time.Millisecond
	zapretPickBudget = 3 * time.Minute
	zapretKeep       = 8
	zapretHealEvery  = 10 * time.Minute
	zapretHealFirst  = 2 * time.Minute
	zapretRepick     = 30 * time.Minute // between automatic picks on one network
	zapretRepickNone = 2 * time.Hour    // after an automatic pick that found nothing
)

// zapretRefine and zapretBroad: the generated candidates tried around what
// worked, and over the whole space when nothing did (fewer on Lite).
func zapretRefine() int {
	if edition.Lite {
		return 12
	}
	return 24
}

func zapretBroad() int {
	if edition.Lite {
		return 24
	}
	return 60
}

// zapretBatch is the testers at once: an nfqws2 each, too many for the
// memory of a Lite router.
func zapretBatch() int {
	if edition.Lite {
		return 4
	}
	return zapret.ProbeSlots - 1
}

// zapretCtl is the controller's part.
type zapretCtl struct {
	mu  sync.Mutex // apply and pick, one at a time
	run *zapret.Runner
	// leftovers: the nfqws2 an earlier hyrouterd left were ended (on the
	// first apply).
	leftovers sync.Once
	// args, key (the network args were built for), net (its name), wan
	// and err (why the bypass does not run) are written with mu and pmu
	// held.
	args  []string
	key   string
	net   string
	wan   []string
	err   string
	extra atomic.Pointer[string]
	// probes: the table holds the probe chains (a pick runs).
	probes atomic.Bool
	// qnum: the queue of the bypass, the testers' queues follow it
	// (PickQueue; 0 before the first apply: QNumBypass). queueNote: who
	// holds the default queues ("" when no one). Written with mu and pmu
	// held.
	qnum      int
	queueNote string

	pmu       sync.Mutex // pick, cancel, heal
	pick      *ZapretPickView
	cancel    context.CancelFunc
	healNote  string
	healAt    time.Time
	autoPicks map[string]autoPick
}

type autoPick struct {
	at    time.Time
	found bool
}

// killLeftovers ends the nfqws2 of an hyrouterd that is gone
// (zapret.Leftovers: they keep their queues and their bypass) and waits a
// moment for them to be gone, so their queues are free; the killed PIDs.
func killLeftovers() []int {
	var pids []int
	for _, h := range zapret.Leftovers(filepath.Join(ZapretDir, "nfqws2"), os.Getpid()) {
		if p, err := os.FindProcess(h.PID); err == nil && p.Kill() == nil {
			pids = append(pids, h.PID)
		}
	}
	for end := time.Now().Add(time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		if !slices.ContainsFunc(pids, func(pid int) bool {
			_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
			return err == nil
		}) {
			break
		}
	}
	return pids
}

// queue is the queue of the bypass (mu held).
func (z *zapretCtl) queue() int {
	if z.qnum == 0 {
		return zapret.QNumBypass
	}
	return z.qnum
}

// zapretQueue is the queue of the bypass: QNumBypass unless another
// program holds a queue of its range (another DPI bypass on the router:
// zapret and nfqws-keenetic take 200), then the next free range; and the
// first queue of the default range another program holds, with who it is
// (0, "" when none). An nfqws2 of HyRouter whose hyrouterd is gone is
// killed instead (mu held).
func (c *Controller) zapretQueue() (base, heldQ int, heldBy string) {
	bound, err := zapret.BoundQueues()
	if err != nil {
		c.log.Warn("zapret: the bound queues not read", "err", err)
		return zapret.QNumBypass, 0, ""
	}
	me, exe := os.Getpid(), filepath.Join(ZapretDir, "nfqws2")
	running := c.zap.run != nil && c.zap.run.Status().State == zapret.Running
	foreign := func(q int, port int64) bool {
		h, ok := zapret.FindHolder(port)
		switch {
		case !ok && running && q == c.zap.queue():
			// A port ID that is no process ID, on the queue of the nfqws2
			// that runs: its own.
			return false
		case ok && h.Parent == me:
			return false // the bypass or a tester
		case ok && h.Exe == exe:
			if p, err := os.FindProcess(h.PID); err == nil && p.Kill() == nil {
				c.log.Warn("zapret: a leftover nfqws2 killed", "pid", h.PID, "queue", q)
				return false
			}
		}
		if heldBy == "" && q < zapret.QNumBypass+zapret.ProbeSlots {
			heldQ, heldBy = q, "неизвестная программа"
			if ok {
				heldBy = fmt.Sprintf("%s (PID %d)", h.Name, h.PID)
			}
		}
		return true
	}
	// foreign sets heldQ and heldBy: read them after the call.
	base = zapret.PickQueue(bound, foreign)
	return base, heldQ, heldBy
}

// queueNote tells the page that another program holds a queue of the
// bypass ("" when none does).
func queueNote(base, heldQ int, heldBy string) string {
	if heldBy == "" {
		return ""
	}
	s := fmt.Sprintf("Очередь NFQUEUE %d занята другой программой: %s. Похоже, на роутере работает ещё один обход DPI (zapret, nfqws-keenetic). ", heldQ, heldBy)
	if base != zapret.QNumBypass {
		s += fmt.Sprintf("HyRouter взял очереди %d–%d, но ", base, base+zapret.ProbeSlots-1)
	}
	return s + "два обхода мешают друг другу, а подбор проверяет сайты вместе с чужим обходом: оставьте один."
}

// zapretExtra is the bypass's part of the firewall's rules (fwZapret).
func (c *Controller) zapretExtra() string {
	if p := c.zap.extra.Load(); p != nil {
		return *p
	}
	return ""
}

// zapretSettings reads zapret.json of a state (the zero settings when it
// was never set up or does not read).
func zapretSettings(st store.State) (zapret.Settings, error) {
	var cfg zapret.Settings
	if len(st.Zapret) == 0 {
		return cfg, nil
	}
	if err := json.Unmarshal(st.Zapret, &cfg); err != nil {
		return zapret.Settings{}, fmt.Errorf("zapret.json: %v", err)
	}
	cfg.Normalize()
	return cfg, nil
}

func (c *Controller) zapretRunner() *zapret.Runner {
	if c.zap.run == nil {
		c.zap.run = &zapret.Runner{Exe: filepath.Join(ZapretDir, "nfqws2"), Log: c.log}
	}
	return c.zap.run
}

// zapretAvailable: the package brought nfqws2.
func zapretAvailable() bool {
	_, err := os.Stat(filepath.Join(ZapretDir, "nfqws2"))
	return err == nil
}

// zapretNetKey names the network the router is on (methods are picked per
// network) and how the page shows it: the MAC of the provider's gateway;
// on a point-to-point link the link itself, as PPPoE's default route has
// no gateway (0.0.0.0) and no MAC.
func (c *Controller) zapretNetKey() (key, name string) {
	dev, gw := platform.DefaultRoute()
	if !gw.IsValid() || gw.IsUnspecified() {
		if dev == "" {
			return "", ""
		}
		return "dev:" + dev, "подключение " + dev
	}
	if mac := c.neigh.Lookup(gw); !mac.IsZero() {
		return "gw:" + mac.String(), "шлюз " + gw.String()
	}
	return "", "шлюз " + gw.String()
}

// zapretServers are the addresses of the servers HyRouter connects to:
// what its cores resolved, and the hosts of the servers that run.
func (c *Controller) zapretServers() []netip.Addr {
	var out []netip.Addr
	byID := map[string]string{}
	for _, p := range c.State().Servers {
		byID[p.ID] = p.Host
	}
	for _, s := range c.tunnels.Statuses() {
		for _, ip := range s.ServerIPs {
			if a, err := netip.ParseAddr(ip); err == nil {
				out = append(out, a.Unmap())
			}
		}
		host := byID[strings.TrimPrefix(s.ID, "test:")]
		if host == "" {
			continue
		}
		if a, err := netip.ParseAddr(host); err == nil {
			out = append(out, a.Unmap())
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		cancel()
		if err == nil {
			for _, a := range ips {
				out = append(out, a.Unmap())
			}
		}
	}
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	return slices.Compact(out)
}

// zapretApply makes the bypass follow the settings: the table's part,
// the lists and nfqws2.
func (c *Controller) zapretApply() {
	c.zap.mu.Lock()
	defer c.zap.mu.Unlock()
	c.zapretApplyLocked()
}

func (c *Controller) zapretApplyLocked() {
	c.zap.leftovers.Do(func() {
		for _, pid := range killLeftovers() {
			c.log.Warn("zapret: an nfqws2 an earlier hyrouterd left was killed", "pid", pid)
		}
	})
	run := c.zapretRunner()
	cfg, err := zapretSettings(c.State())
	set := func(args []string, why string) {
		c.zap.pmu.Lock()
		c.zap.args, c.zap.err = args, why
		c.zap.pmu.Unlock()
	}
	stop := func(why string) {
		set(nil, why)
		c.zap.pmu.Lock()
		c.zap.queueNote = ""
		c.zap.pmu.Unlock()
		run.Stop()
		c.setZapretExtra("")
	}
	switch {
	case err != nil:
		stop(err.Error())
		return
	case !cfg.Enabled || len(cfg.Targets) == 0:
		stop("")
		return
	case !zapretAvailable():
		stop("в пакете нет nfqws2")
		return
	case !c.Running():
		stop("HyRouter выключен: обход работает, пока HyRouter маршрутизирует сеть")
		return
	}
	key, name := c.zapretNetKey()
	wan := platform.WAN(context.Background())
	c.zap.pmu.Lock()
	c.zap.key, c.zap.net, c.zap.wan = key, name, wan
	c.zap.pmu.Unlock()
	plans := map[zapret.Target]zapret.Plan{}
	for _, t := range cfg.Targets {
		if p, ok := cfg.PlanFor(t, key); ok {
			plans[t] = p
		}
	}
	if len(wan) == 0 {
		stop("не найден интерфейс WAN")
		return
	}
	qnum, heldQ, heldBy := c.zapretQueue()
	note := queueNote(qnum, heldQ, heldBy)
	if note != "" && (note != c.zap.queueNote || qnum != c.zap.queue()) {
		c.log.Warn("zapret: a queue is held by another program", "queue", heldQ, "holder", heldBy, "base", qnum)
	}
	c.zap.pmu.Lock()
	c.zap.qnum, c.zap.queueNote = qnum, note
	c.zap.pmu.Unlock()
	skip := c.zapretServers()
	extra, err := fwZapret(zapret.NFTConfig{WAN: wan, Queue: zapret.QueueFor(plans), Probes: c.zap.probes.Load(), Skip: skip, QNum: qnum})
	if err != nil {
		stop(err.Error())
		return
	}
	c.setZapretExtra(extra)
	if len(plans) == 0 {
		set(nil, "")
		run.Stop()
		return
	}
	os.Chmod(filepath.Dir(ZapretLists), 0o755)
	if err := zapret.WriteLists(ZapretLists, cfg.Sites, skip); err != nil {
		stop("списки не записаны: " + err.Error())
		return
	}
	if err := zapret.WriteFakes(ZapretLists); err != nil {
		c.log.Warn("zapret: fakes not written", "err", err)
	}
	args, err := zapret.Build(zapret.BuildConfig{Dir: ZapretDir, Lists: ZapretLists, Plans: plans, Sites: cfg.Sites, QNum: qnum, User: zapretUser})
	if err != nil {
		stop("командная строка не собрана: " + err.Error())
		return
	}
	if slices.Equal(args, c.zap.args) && run.Status().State != zapret.Off {
		set(args, "")
		return
	}
	set(args, "")
	c.log.Info("zapret: nfqws2 starting", "targets", len(plans))
	run.Start(args)
}

// setZapretExtra puts the bypass's part into the table when it changed.
func (c *Controller) setZapretExtra(extra string) {
	if old := c.zap.extra.Load(); old != nil && *old == extra || old == nil && extra == "" {
		return
	}
	c.zap.extra.Store(&extra)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.reloadTable(ctx); err != nil {
		c.log.Error("zapret: the table not loaded", "err", err)
	}
}

// zapretStop ends the bypass with routing.
func (c *Controller) zapretStop() {
	if c.zap.run != nil {
		c.zap.run.Stop()
	}
}

// zapretRules are the rules the bypass keeps for cfg: its services go
// direct (or through the server chosen for them).
func zapretRules(cfg zapret.Settings) []rules.Rule {
	if !cfg.Enabled {
		return nil
	}
	var out []rules.Rule
	for _, t := range zapret.Targets {
		if !cfg.On(t) {
			continue
		}
		act, prof := rules.Direct, ""
		byRules := false
		if cfg.Methods[t] == zapret.VPN {
			act, prof = rules.Tunnel, cfg.Via[t]
			if prof == zapret.ViaRules {
				byRules, prof = true, ""
			}
		}
		if doms := zapretRuleSites(t, cfg.Sites); len(doms) > 0 && !byRules {
			out = append(out, rules.Rule{Name: ZapretRulePrefix + zapret.TargetName(t), Domains: doms, Action: act, Profile: prof})
		}
		if t == zapret.Discord {
			// Voice: addresses without names, by its ports.
			p := prof
			if byRules {
				act, p = rules.Tunnel, ""
			}
			out = append(out, rules.Rule{Name: ZapretRulePrefix + "Discord (голос)", Protocol: "udp",
				Ports: rules.PortList{"19294-19344", "50000-50100"}, Action: act, Profile: p})
		}
	}
	return out
}

func isZapretRule(r rules.Rule) bool { return strings.HasPrefix(r.Name, ZapretRulePrefix) }

// zapretRuleSites: a service's names with their subdomains, its
// addresses as they are.
func zapretRuleSites(t zapret.Target, sites []string) []string {
	var out []string
	for _, d := range zapret.Domains(t, sites) {
		if len(zapret.SiteNets([]string{d})) == 0 {
			d = "." + d
		}
		out = append(out, d)
	}
	return out
}

// syncZapretRules puts the bypass's rules at the top of rc, keeping the
// ones the user switched off switched off.
func syncZapretRules(rc *rules.Config, cfg zapret.Settings, target func(string) bool) {
	for t, v := range cfg.Via {
		if v != zapret.ViaRules && !target(v) {
			// A deleted server or group: the main server instead.
			delete(cfg.Via, t)
		}
	}
	want := zapretRules(cfg)
	off := map[string]bool{}
	for _, r := range rc.Rules {
		if isZapretRule(r) && r.Enabled != nil && !*r.Enabled {
			off[r.Name] = true
		}
	}
	rest := slices.DeleteFunc(slices.Clone(rc.Rules), isZapretRule)
	top := make([]rules.Rule, len(want))
	for i, w := range want {
		w.ID = "zapret-" + strings.ToLower(strings.TrimPrefix(w.Name, ZapretRulePrefix))
		w.ID = strings.NewReplacer(" ", "-", "(", "", ")", "").Replace(w.ID)
		if off[w.Name] {
			f := false
			w.Enabled = &f
		}
		top[i] = w
	}
	rc.Rules = append(top, rest...)
}

// ZapretInput is the page's settings.
type ZapretInput struct {
	Enabled  bool                     `json:"enabled"`
	Targets  []zapret.Target          `json:"targets"`
	Sites    []string                 `json:"sites"`
	Methods  map[zapret.Target]string `json:"methods"`
	Via      map[zapret.Target]string `json:"via"`
	AutoHeal *bool                    `json:"autoHeal,omitempty"`
}

// SaveZapret saves the page's settings and the bypass's rules with them.
func (c *Controller) SaveZapret(ctx context.Context, in ZapretInput) error {
	err := c.Edit(ctx, func(st *store.State) error {
		cfg, err := zapretSettings(*st)
		if err != nil {
			cfg = zapret.Settings{} // a broken file is replaced by the page's choice
		}
		cfg.Enabled, cfg.Targets, cfg.Sites, cfg.Methods, cfg.AutoHeal = in.Enabled, in.Targets, nil, in.Methods, in.AutoHeal
		for _, s := range in.Sites {
			if n := zapret.NormalizeSite(s); n != "" {
				cfg.Sites = append(cfg.Sites, n)
			} else if strings.TrimSpace(s) != "" {
				return fmt.Errorf("«%s» — не имя сайта и не внешний адрес или сеть", strings.TrimSpace(s))
			}
		}
		cfg.Via = map[zapret.Target]string{}
		for t, v := range in.Via {
			if v != "" && cfg.Methods[t] == zapret.VPN {
				cfg.Via[t] = v
			}
		}
		cfg.Normalize()
		if err := cfg.Validate(); err != nil {
			return err
		}
		syncZapretRules(&st.Rules, cfg, func(id string) bool { return targetExists(st, id) })
		b, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return err
		}
		st.Zapret = b
		return nil
	}, func(st store.State) error {
		if err := c.store.SaveZapret(st.Zapret); err != nil {
			return err
		}
		return c.store.SaveRules(st.Rules)
	})
	if err == nil {
		go c.zapretApply()
	}
	return err
}

// targetExists: id is a server or a group of st.
func targetExists(st *store.State, id string) bool {
	if groups.IsGroupID(id) {
		return st.Groups.Find(id) != nil
	}
	return slices.ContainsFunc(st.Servers, func(p hysteria.Profile) bool { return p.ID == id })
}

// ZapretTargetView is a service on the page.
type ZapretTargetView struct {
	Target   zapret.Target `json:"target"`
	Name     string        `json:"name"`
	On       bool          `json:"on"`
	Fixed    string        `json:"fixed,omitempty"`
	Picked   string        `json:"picked,omitempty"`
	PickedAt time.Time     `json:"pickedAt,omitzero"`
	Using    string        `json:"using"`
	Via      string        `json:"via,omitempty"`
}

// ZapretMethodView is a method the page offers.
type ZapretMethodView struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ZapretDiag is how a service is blocked.
type ZapretDiag struct {
	Kind   zapret.Kind `json:"kind"`
	Text   string      `json:"text"`
	Detail string      `json:"detail"`
	Bypass bool        `json:"bypass"`
}

// ZapretPickView is an auto-pick under way or done.
type ZapretPickView struct {
	Running   bool                         `json:"running"`
	Step      string                       `json:"step"`
	Done      int                          `json:"done"`
	Total     int                          `json:"total"`
	Results   map[zapret.Target]string     `json:"results"`
	Tried     int                          `json:"tried"`
	Working   map[zapret.Target][]string   `json:"working,omitempty"`
	Diagnosis map[zapret.Target]ZapretDiag `json:"diagnosis,omitempty"`
	Error     string                       `json:"error,omitempty"`
	Skipped   []string                     `json:"skipped,omitempty"`
	Auto      bool                         `json:"auto,omitempty"`
	Why       string                       `json:"why,omitempty"`
	// Open: the hosts of the targets that opened from the router without
	// a bypass (their result is zapret.None).
	Open map[zapret.Target][]string `json:"open,omitempty"`
}

// ZapretView is the «Обход DPI» page.
type ZapretView struct {
	Available   bool               `json:"available"`
	Routing     bool               `json:"routing"`
	Settings    zapret.Settings    `json:"settings"`
	Status      zapret.Status      `json:"status"`
	Error       string             `json:"error,omitempty"`
	QueueNote   string             `json:"queueNote,omitempty"`
	Network     string             `json:"network"`
	WAN         []string           `json:"wan"`
	Offload     bool               `json:"offload"`
	Targets     []ZapretTargetView `json:"targets"`
	Methods     []ZapretMethodView `json:"methods"`
	Pick        *ZapretPickView    `json:"pick,omitempty"`
	CommandLine string             `json:"commandLine,omitempty"`
	HealNote    string             `json:"healNote,omitempty"`
	HealAt      time.Time          `json:"healAt,omitzero"`
}

// ZapretInfo is the page.
func (c *Controller) ZapretInfo() ZapretView {
	cfg, err := zapretSettings(c.State())
	c.zap.pmu.Lock()
	v := ZapretView{Available: zapretAvailable(), Routing: c.Running(), Settings: cfg, Network: c.zap.net,
		WAN: slices.Clone(c.zap.wan), Error: c.zap.err, QueueNote: c.zap.queueNote}
	args, key := c.zap.args, c.zap.key
	c.zap.pmu.Unlock()
	v.Status, v.Offload = c.zapretRunner().Status(), platform.Offload(context.Background())
	if err != nil {
		v.Error = err.Error()
	}
	if v.WAN == nil {
		v.WAN = []string{}
	}
	if args != nil {
		v.CommandLine = zapret.CommandLine(args)
	}
	for _, t := range zapret.Targets {
		tv := ZapretTargetView{Target: t, Name: zapret.TargetName(t), On: cfg.On(t), Fixed: cfg.Methods[t], Via: cfg.Via[t]}
		if pk, ok := cfg.Picked[key]; ok {
			tv.Picked, tv.PickedAt = pk.Methods[t], pk.At
		}
		switch p, ok := cfg.PlanFor(t, key); {
		case !tv.On:
		case cfg.Methods[t] == zapret.VPN:
			tv.Using = "через VPN"
		case !ok:
			tv.Using = "без обхода: здесь не блокируется"
		case p.Circular:
			tv.Using = "перебор методов, первый — " + zapret.MethodName(p.Methods[0])
		default:
			tv.Using = zapret.MethodName(p.Methods[0])
		}
		v.Targets = append(v.Targets, tv)
	}
	for _, m := range zapret.Methods {
		v.Methods = append(v.Methods, ZapretMethodView{ID: m.ID, Name: m.Name})
	}
	c.zap.pmu.Lock()
	if c.zap.pick != nil {
		p := *c.zap.pick
		p.Results = maps.Clone(p.Results)
		p.Diagnosis = maps.Clone(p.Diagnosis)
		p.Working = maps.Clone(p.Working)
		v.Pick = &p
	}
	v.HealNote, v.HealAt = c.zap.healNote, c.zap.healAt
	c.zap.pmu.Unlock()
	return v
}

// ZapretPick starts an auto-pick; the page follows it by ZapretInfo.
func (c *Controller) ZapretPick() error {
	c.zap.pmu.Lock()
	busy := c.zap.pick != nil && c.zap.pick.Running
	c.zap.pmu.Unlock()
	if busy {
		return errors.New("подбор уже идёт")
	}
	cfg, err := zapretSettings(c.State())
	switch {
	case err != nil:
		return err
	case !c.Running():
		return errors.New("включите HyRouter: подбор проверяет сайты через его правила")
	case !zapretAvailable():
		return errors.New("в пакете нет nfqws2")
	case len(cfg.Targets) == 0:
		return errors.New("выберите, что обходить")
	}
	go c.zapretPickRun("")
	return nil
}

// ZapretPickCancel stops a pick under way.
func (c *Controller) ZapretPickCancel() {
	c.zap.pmu.Lock()
	if c.zap.cancel != nil {
		c.zap.cancel()
	}
	c.zap.pmu.Unlock()
}

type timed struct {
	id string
	d  time.Duration
}

func methodIndex(id string) int {
	if i := slices.IndexFunc(zapret.Methods, func(m zapret.Method) bool { return m.ID == id }); i >= 0 {
		return i
	}
	return len(zapret.Methods)
}

func fastest(ws []timed) []timed {
	ws = slices.Clone(ws)
	slices.SortStableFunc(ws, func(a, b timed) int {
		if d := cmp.Compare(a.d, b.d); d != 0 {
			return d
		}
		return cmp.Compare(methodIndex(a.id), methodIndex(b.id))
	})
	return ws
}

// checkHosts are the hosts of check addresses, each once.
func checkHosts(urls []string) []string {
	var out []string
	for _, u := range urls {
		if p, err := url.Parse(u); err == nil && p.Hostname() != "" && !slices.Contains(out, p.Hostname()) {
			out = append(out, p.Hostname())
		}
	}
	return out
}

// zapretPickRun finds the methods that open each service on this network
// (HyRoute's pick): a check without the bypass first, then the library's
// methods all at once, one nfqws2 each on its probe slot, then generated
// variants around what worked (or across the space when nothing did),
// and the best checked again. why is set for a pick self-healing started.
func (c *Controller) zapretPickRun(why string) {
	c.zap.mu.Lock()
	defer c.zap.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg, err := zapretSettings(c.State())
	pick := &ZapretPickView{Running: true, Step: "Готовлю подбор…", Total: len(zapret.Methods) + 1,
		Results: map[zapret.Target]string{}, Diagnosis: map[zapret.Target]ZapretDiag{}, Open: map[zapret.Target][]string{},
		Auto: why != "", Why: why}
	c.zap.pmu.Lock()
	c.zap.pick, c.zap.cancel = pick, cancel
	c.zap.pmu.Unlock()
	update := func(f func(p *ZapretPickView)) {
		c.zap.pmu.Lock()
		f(pick)
		c.zap.pmu.Unlock()
	}
	finish := func(err error) {
		update(func(p *ZapretPickView) {
			p.Running = false
			if err != nil {
				p.Error = err.Error()
			}
		})
		c.zap.pmu.Lock()
		c.zap.cancel = nil
		c.zap.pmu.Unlock()
		c.zap.probes.Store(false)
		c.zapretApplyLocked()
		if err != nil {
			c.log.Warn("zapret: pick failed", "err", err)
		}
	}
	if err != nil {
		finish(err)
		return
	}
	// The probe chains go into the table for the pick.
	c.zap.probes.Store(true)
	c.zapretApplyLocked()
	if c.zap.err != "" {
		finish(errors.New(c.zap.err))
		return
	}
	key := c.zap.key
	checks := map[zapret.Target][]string{}
	for _, t := range cfg.Targets {
		checks[t] = zapret.Checks(t, cfg.Sites)
	}
	check := func(slot int, urls []string) zapret.Result {
		return (&zapret.Prober{Slot: slot}).Check(ctx, urls)
	}
	checkAll := func(slot int, ts []zapret.Target) map[zapret.Target]zapret.Result {
		out := map[zapret.Target]zapret.Result{}
		var mu sync.Mutex
		var wg sync.WaitGroup
		for _, t := range ts {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r := check(slot, checks[t])
				mu.Lock()
				out[t] = r
				mu.Unlock()
			}()
		}
		wg.Wait()
		return out
	}
	left := slices.DeleteFunc(slices.Clone(cfg.Targets), func(t zapret.Target) bool {
		return cfg.Methods[t] == zapret.VPN || len(checks[t]) == 0
	})
	if len(left) == 0 {
		finish(errors.New("подбирать нечего: выбранные сервисы идут через VPN или заданы только адресами"))
		return
	}
	update(func(p *ZapretPickView) {
		p.Step = "Проверяю без обхода: что блокируется и как"
	})
	var skipped []string
	if slices.Contains(left, zapret.Sites) {
		r := check(0, zapret.SiteProbes(cfg.Sites))
		var notes []string
		for _, f := range r.Failed {
			if !f.Kind.Bypassable() && !slices.Contains(skipped, f.Host) {
				skipped = append(skipped, f.Host)
				notes = append(notes, f.Host+" — "+f.Kind.Explain())
			}
		}
		if cs := zapret.ChecksSkip(zapret.Sites, cfg.Sites, skipped); len(skipped) > 0 && len(cs) > 0 {
			checks[zapret.Sites] = cs
			update(func(p *ZapretPickView) { p.Skipped = notes })
		} else {
			skipped = nil
		}
	}
	first := checkAll(0, left)
	// A failure no bypass beats (an address that does not answer, a name
	// that does not resolve) may be passing. Such a target is checked once
	// more before methods are tried for it: otherwise the first method
	// would "open" what opens without one by the time it is tried.
	var again []zapret.Target
	for t, r := range first {
		if !r.OK && !r.Bypassable() {
			again = append(again, t)
		}
	}
	if len(again) > 0 && ctx.Err() == nil {
		update(func(p *ZapretPickView) {
			p.Step = "Часть адресов не ответила: проверяю без обхода ещё раз"
		})
		maps.Copy(first, checkAll(0, again))
	}
	for t, r := range first {
		if r.OK {
			update(func(p *ZapretPickView) {
				p.Results[t] = zapret.None
				p.Open[t] = checkHosts(checks[t])
				delete(p.Diagnosis, t)
			})
			left = slices.DeleteFunc(left, func(x zapret.Target) bool { return x == t })
			continue
		}
		d := r.Diagnosis()
		update(func(p *ZapretPickView) {
			p.Diagnosis[t] = ZapretDiag{Kind: d.Kind, Text: d.Kind.Explain(), Detail: d.String(), Bypass: r.Bypassable()}
		})
	}
	update(func(p *ZapretPickView) { p.Done = 1 })
	if ctx.Err() != nil {
		finish(errors.New("подбор остановлен"))
		return
	}

	deadline := time.Now().Add(zapretPickBudget)
	tried := map[string]bool{}
	works := map[zapret.Target][]timed{}
	round := func(cands []string, targets []zapret.Target) (map[zapret.Target][]timed, error) {
		out := map[zapret.Target][]timed{}
		retried := false
		for len(cands) > 0 && ctx.Err() == nil {
			batch := cands[:min(len(cands), zapretBatch())]
			testers := make([]*zapret.Runner, len(batch))
			for i, id := range batch {
				tried[id] = true
				plans := map[zapret.Target]zapret.Plan{}
				for _, t := range targets {
					plans[t] = zapret.Plan{Methods: []string{id}}
				}
				args, err := zapret.Build(zapret.BuildConfig{Dir: ZapretDir, Lists: ZapretLists, Plans: plans, Sites: cfg.Sites,
					QNum: c.zap.queue() + i + 1, User: zapretUser})
				if err != nil {
					for _, r := range testers[:i] {
						r.Stop()
					}
					return nil, err
				}
				testers[i] = &zapret.Runner{Exe: filepath.Join(ZapretDir, "nfqws2"), Log: c.log}
				if i > 0 {
					select {
					case <-ctx.Done():
					case <-time.After(zapretStagger):
					}
				}
				testers[i].Start(args)
			}
			up := time.Now().Add(zapretStartWait)
			for ctx.Err() == nil && time.Now().Before(up) && slices.ContainsFunc(testers, func(r *zapret.Runner) bool { return r.Status().State == zapret.Off }) {
				select {
				case <-ctx.Done():
				case <-time.After(100 * time.Millisecond):
				}
			}
			select {
			case <-ctx.Done():
			case <-time.After(zapretSettle):
			}
			var mu sync.Mutex
			var wg sync.WaitGroup
			started, firstErr := 0, ""
			for i, id := range batch {
				if st := testers[i].Status(); st.State != zapret.Running {
					c.log.Warn("zapret: tester not running", "method", id, "state", st.State, "err", st.Error)
					if firstErr == "" {
						firstErr = st.Error
						if firstErr == "" {
							firstErr = fmt.Sprintf("не успел запуститься за %d с — роутер занят", int(zapretStartWait.Seconds()))
						}
					}
					testers[i].Stop()
					update(func(p *ZapretPickView) { p.Done++ })
					continue
				}
				started++
				wg.Add(1)
				go func() {
					defer wg.Done()
					for t, r := range checkAll(i+1, targets) {
						if r.OK && ctx.Err() == nil {
							mu.Lock()
							out[t] = append(out[t], timed{id, r.Elapsed})
							mu.Unlock()
						}
					}
					testers[i].Stop()
					update(func(p *ZapretPickView) { p.Done++; p.Tried = len(tried) })
				}()
			}
			wg.Wait()
			if started == 0 {
				if !retried && ctx.Err() == nil {
					retried = true
					update(func(p *ZapretPickView) { p.Done -= len(batch) })
					select {
					case <-ctx.Done():
					case <-time.After(3 * time.Second):
					}
					continue
				}
				return nil, fmt.Errorf("nfqws2 не запускается: %s", firstErr)
			}
			retried = false
			cands = cands[len(batch):]
		}
		return out, nil
	}
	workingCount := func() int {
		seen := map[string]bool{}
		for _, ws := range works {
			for _, w := range ws {
				seen[w.id] = true
			}
		}
		return len(seen)
	}
	merge := func(got map[zapret.Target][]timed) {
		for t, ws := range got {
			works[t] = append(works[t], ws...)
		}
	}
	if len(left) > 0 {
		var lib []string
		for _, m := range zapret.Methods {
			lib = append(lib, m.ID)
		}
		for _, t := range left {
			for _, id := range cfg.Picked[key].Working[t] {
				if !slices.Contains(lib, id) {
					lib = append(lib, id)
				}
			}
		}
		update(func(p *ZapretPickView) {
			p.Step = fmt.Sprintf("Пробую %d известных и найденных раньше методов", len(lib))
			p.Total = 1 + len(lib)
		})
		got, err := round(lib, left)
		if err != nil {
			finish(err)
			return
		}
		merge(got)
		var cands []string
		add := func(id string) {
			if !tried[id] && !slices.Contains(cands, id) {
				cands = append(cands, id)
			}
		}
		lost := false
		for _, t := range left {
			ws := fastest(works[t])
			if len(ws) == 0 {
				lost = true
				continue
			}
			for _, w := range ws[:min(2, len(ws))] {
				if st, ok := zapret.AsStrategy(w.id); ok {
					for _, n := range zapret.Neighbors(st) {
						add(n.ID())
					}
				}
			}
		}
		budget := zapretRefine()
		if lost {
			for _, st := range zapret.Broad(zapretBroad(), rand.Uint64()) {
				add(st.ID())
			}
			budget += zapretBroad()
		}
		cands = cands[:min(len(cands), budget)]
		for len(cands) > 0 && ctx.Err() == nil && time.Now().Before(deadline) {
			batch := cands[:min(len(cands), zapretBatch())]
			cands = cands[len(batch):]
			update(func(p *ZapretPickView) {
				p.Step = fmt.Sprintf("Генерирую свои варианты: проверено %d, рабочих найдено %d", len(tried), workingCount())
				p.Total = p.Done + len(batch) + len(cands) + 1
			})
			got, err := round(batch, left)
			if err != nil {
				finish(err)
				return
			}
			merge(got)
		}
		var again []string
		for _, t := range left {
			for _, w := range fastest(works[t])[:min(zapretKeep, len(works[t]))] {
				if !slices.Contains(again, w.id) {
					again = append(again, w.id)
				}
			}
		}
		if len(again) > 0 && ctx.Err() == nil {
			update(func(p *ZapretPickView) {
				p.Step = fmt.Sprintf("Перепроверяю %d лучших", len(again))
				p.Total = p.Done + len(again)
			})
			got, err := round(again, left)
			if err != nil {
				finish(err)
				return
			}
			for _, t := range left {
				var kept []timed
				for _, w := range works[t] {
					if i := slices.IndexFunc(got[t], func(g timed) bool { return g.id == w.id }); i >= 0 {
						kept = append(kept, timed{w.id, (w.d + got[t][i].d) / 2})
					}
				}
				works[t] = kept
			}
		}
	}
	if ctx.Err() != nil {
		finish(errors.New("подбор остановлен"))
		return
	}
	working := map[zapret.Target][]string{}
	results := map[zapret.Target]string{}
	for _, t := range left {
		ws := fastest(works[t])
		for _, w := range ws[:min(zapretKeep, len(ws))] {
			working[t] = append(working[t], w.id)
		}
		results[t] = ""
		if len(ws) > 0 {
			results[t] = ws[0].id
		}
	}
	update(func(p *ZapretPickView) {
		maps.Copy(p.Results, results)
		p.Working = working
	})
	found := map[zapret.Target]string{}
	c.zap.pmu.Lock()
	for t, m := range pick.Results {
		if m != "" {
			found[t] = m
		}
	}
	c.zap.pmu.Unlock()
	err = c.Edit(ctx, func(st *store.State) error {
		cfg, err := zapretSettings(*st)
		if err != nil {
			return err
		}
		if cfg.Picked == nil {
			cfg.Picked = map[string]zapret.Picked{}
		}
		cfg.Picked[key] = zapret.Picked{At: time.Now(), Methods: found, Working: working, SkippedSites: skipped}
		trimPicked(cfg.Picked)
		b, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return err
		}
		st.Zapret = b
		return nil
	}, func(st store.State) error { return c.store.SaveZapret(st.Zapret) })
	if err != nil {
		finish(err)
		return
	}
	update(func(p *ZapretPickView) { p.Step = "Готово" })
	c.log.Info("zapret: methods picked", "network", key != "", "found", len(found), "left", len(left))
	c.zap.pmu.Lock()
	if c.zap.autoPicks == nil {
		c.zap.autoPicks = map[string]autoPick{}
	}
	if why != "" {
		c.zap.autoPicks[key] = autoPick{at: time.Now(), found: len(found) == len(left)}
	}
	c.zap.pmu.Unlock()
	finish(nil)
}

// trimPicked keeps the picks of the last MaxNetKeys networks.
func trimPicked(m map[string]zapret.Picked) {
	for len(m) > zapret.MaxNetKeys {
		oldest, first := "", true
		for k, p := range m {
			if first || p.At.Before(m[oldest].At) {
				oldest, first = k, false
			}
		}
		delete(m, oldest)
	}
}

// runZapretHeal is the self-check (Settings.Heals): every few minutes the
// services are opened through the running bypass, from an ordinary port
// of the router as a device would; a service that fails twice is checked
// without the bypass, and picked again when the bypass can still help. A
// network without a pick gets one when a service is blocked there.
func (c *Controller) runZapretHeal(ctx context.Context) {
	t := time.NewTimer(zapretHealFirst)
	defer t.Stop()
	fails := map[zapret.Target]int{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		t.Reset(zapretHealEvery)
		c.zapretHealOnce(ctx, fails)
	}
}

func (c *Controller) setHeal(note string) {
	c.zap.pmu.Lock()
	c.zap.healNote, c.zap.healAt = note, time.Now()
	c.zap.pmu.Unlock()
}

func (c *Controller) zapretHealOnce(ctx context.Context, fails map[zapret.Target]int) {
	cfg, err := zapretSettings(c.State())
	if err != nil || !cfg.Enabled || !cfg.Heals() || !c.Running() || !zapretAvailable() {
		return
	}
	c.zap.pmu.Lock()
	busy := c.zap.pick != nil && c.zap.pick.Running
	c.zap.pmu.Unlock()
	if busy {
		return
	}
	var ts []zapret.Target
	for _, t := range cfg.Targets {
		if cfg.Methods[t] != zapret.VPN && len(zapret.Checks(t, cfg.Sites)) > 0 {
			ts = append(ts, t)
		}
	}
	if len(ts) == 0 {
		return
	}
	key, _ := c.zapretNetKey()
	urls := func(t zapret.Target) []string {
		return zapret.ChecksSkip(t, cfg.Sites, cfg.Picked[key].SkippedSites)
	}
	check := func(slot int, t zapret.Target) zapret.Result {
		cctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		return (&zapret.Prober{Slot: slot}).Check(cctx, urls(t))
	}
	c.zap.pmu.Lock()
	last := c.zap.autoPicks[key]
	c.zap.pmu.Unlock()
	wait := zapretRepick
	if !last.found && !last.at.IsZero() {
		wait = zapretRepickNone
	}
	canPick := last.at.IsZero() || time.Since(last.at) >= wait
	if _, picked := cfg.Picked[key]; !picked {
		// A network without a pick: a pick when a service is blocked here
		// in a way the bypass can open.
		var need []string
		for _, t := range ts {
			if r := check(0, t); !r.OK && r.Bypassable() {
				need = append(need, zapret.TargetName(t))
			}
		}
		if len(need) > 0 && canPick && ctx.Err() == nil {
			c.setHeal("На новой сети не открывается " + strings.Join(need, ", ") + ": подбираю методы")
			c.zapretPickRun("новая сеть")
		}
		return
	}
	var broken []string
	for _, t := range ts {
		if r := check(zapret.Live, t); r.OK {
			fails[t] = 0
			continue
		} else if d := r.Diagnosis(); d.Host != "" {
			fails[t]++
			if fails[t] < 2 {
				continue
			}
			c.log.Info("zapret: a service does not open through the bypass", "target", zapret.TargetName(t))
			direct := check(0, t)
			if direct.OK || direct.Bypassable() {
				broken = append(broken, zapret.TargetName(t)+" ("+d.String()+")")
			} else {
				c.setHeal(zapret.TargetName(t) + " не открывается и без обхода: " + direct.Diagnosis().Kind.Explain())
			}
		}
	}
	if len(broken) == 0 {
		return
	}
	if !canPick {
		c.setHeal("Не открывается " + strings.Join(broken, ", ") + "; подбор недавно был, следующий позже")
		return
	}
	for k := range fails {
		fails[k] = 0
	}
	c.setHeal("Не открывалось " + strings.Join(broken, ", ") + ": подобрал методы заново")
	c.zapretPickRun("сервис перестал открываться")
}
