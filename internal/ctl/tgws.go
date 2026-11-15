//go:build linux

package ctl

// «Telegram без VPN» (internal/tgws, HyRoute 1.3.26-1.3.27): Telegram's
// connections from every device of the LAN go to Telegram over the
// WebSocket endpoints of its web version, which a DPI that blocks the data
// centers' addresses tends to let through; when those do not open, over
// Cloudflare (tg-ws-proxy's domains or the user's Workers), through the
// main VPN server, else straight to the data center. The rule «Обход DPI:
// Telegram» (Telegram's networks, TCP 80, 443, 5222) names tgws.ProfileID
// as its server: the relay hands those connections to the bridge, which
// reads their first bytes. Nothing is set on the devices. Unlike HyRoute
// there is no MTProto proxy port: the router takes Telegram's connections
// as they are. The bridge runs while the switch is on and HyRouter routes.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/zilbergsp/hyrouter/internal/rules"
	"github.com/zilbergsp/hyrouter/internal/socks5"
	"github.com/zilbergsp/hyrouter/internal/store"
	"github.com/zilbergsp/hyrouter/internal/tgws"
	"github.com/zilbergsp/hyrouter/internal/zapret"
)

// tgCtl is the controller's part; bridge, on and stop under zap.mu, live
// for any goroutine (the relay).
type tgCtl struct {
	bridge *tgws.Bridge
	on     zapret.TelegramSettings
	stop   context.CancelFunc // ends the self-checks and the fetches
	live   atomic.Pointer[tgws.Bridge]
	// cf: tg-ws-proxy's Cloudflare domains as last fetched (nil: the
	// built-in list); covered: nfqws2 runs with them in its lists, so
	// Cloudflare goes before the VPN.
	cf      atomic.Pointer[[]string]
	covered atomic.Bool
}

// Test hooks: when the self-checks run and the Cloudflare list is fetched
// (after a failure: sooner).
var (
	tgCheckFirst      = 5 * time.Second
	tgCheckEvery      = 5 * time.Minute
	tgCloudflareFirst = 20 * time.Second
	tgCloudflareEvery = time.Hour
	tgCloudflareRetry = 10 * time.Minute
)

// tgApplyLocked makes the bridge follow the settings (zap.mu held).
func (c *Controller) tgApplyLocked(cfg zapret.Settings) {
	want := cfg.Telegram
	if !c.Running() {
		want.Enabled = false
	}
	t := &c.tg
	if t.bridge != nil && want.Enabled && want.Equal(t.on) {
		return
	}
	if t.bridge != nil {
		t.stop()
		t.live.Store(nil)
		t.bridge.Close()
		t.bridge, t.stop = nil, nil
		c.log.Info("tgws: stopped")
	}
	t.on = want
	if !want.Enabled {
		return
	}
	b := tgws.New(tgws.Config{Log: c.log, VPN: c.tgVPNDial, Workers: slices.Clone(want.Workers),
		Cloudflare: c.tgCloudflareDomains(want), CloudflareFirst: t.covered.Load()})
	b.Warm()
	t.bridge = b
	t.live.Store(b)
	ctx, cancel := context.WithCancel(context.Background())
	t.stop = cancel
	go c.tgChecks(ctx, b)
	if !want.NoCloudflare {
		go c.tgFetchCloudflare(ctx)
	}
	c.log.Info("tgws: started")
}

// tgStop ends the bridge with routing.
func (c *Controller) tgStop() {
	c.zap.mu.Lock()
	defer c.zap.mu.Unlock()
	t := &c.tg
	if t.bridge != nil {
		t.stop()
		t.live.Store(nil)
		t.bridge.Close()
		t.bridge, t.stop, t.on = nil, nil, zapret.TelegramSettings{}
		c.log.Info("tgws: stopped")
	}
}

// tgCloudflareDomains: the Cloudflare domains for t (nil: that route off).
func (c *Controller) tgCloudflareDomains(t zapret.TelegramSettings) []string {
	if !t.Enabled || t.NoCloudflare {
		return nil
	}
	if p := c.tg.cf.Load(); p != nil {
		return *p
	}
	return tgws.DefaultCloudflare()
}

// tgCloudflareLists: the hosts of the Cloudflare routes go into the list
// of a target the bypass runs for — Discord's, whose methods are picked
// against Cloudflare's addresses (its media live there), else the own
// sites' — so nfqws2 carries them past a provider that cuts Cloudflare.
// nil: no Cloudflare route, or no such target.
func (c *Controller) tgCloudflareLists(cfg zapret.Settings, plans map[zapret.Target]zapret.Plan) map[zapret.Target][]string {
	t := cfg.Telegram
	hosts := slices.Concat(c.tgCloudflareDomains(t), t.Workers)
	if !t.Enabled || len(hosts) == 0 {
		return nil
	}
	for _, target := range []zapret.Target{zapret.Discord, zapret.Sites} {
		if _, ok := plans[target]; ok {
			return map[zapret.Target][]string{target: hosts}
		}
	}
	return nil
}

// tgCloudflareLocked gives the bridge the current domains and whether
// Cloudflare goes before the VPN (zap.mu held).
func (c *Controller) tgCloudflareLocked(covered bool) {
	c.tg.covered.Store(covered)
	if b := c.tg.bridge; b != nil {
		b.SetCloudflare(c.tgCloudflareDomains(c.tg.on), covered)
	}
}

// tgFetchCloudflare keeps the Cloudflare domains current while the bridge
// runs: tg-ws-proxy's author replaces the domains that get blocked.
func (c *Controller) tgFetchCloudflare(ctx context.Context) {
	t := time.NewTimer(tgCloudflareFirst)
	defer t.Stop()
	client := &http.Client{Timeout: 30 * time.Second}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		list, err := tgws.FetchCloudflare(ctx, client)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			c.log.Info("tgws: Cloudflare domains not fetched, the known ones stay", "err", err)
			t.Reset(tgCloudflareRetry)
			continue
		}
		t.Reset(tgCloudflareEvery)
		if cur := c.tg.cf.Load(); cur != nil && slices.Equal(*cur, list) {
			continue
		}
		c.tg.cf.Store(&list)
		c.log.Info("tgws: Cloudflare domains updated", "count", len(list))
		go c.zapretApply() // the bridge's domains, nfqws2's lists
	}
}

// tgChecks runs the bridge's self-checks while it runs: a WebSocket that
// stops answering is skipped (Telegram goes another way at once), one
// that answers again is used again.
func (c *Controller) tgChecks(ctx context.Context, b *tgws.Bridge) {
	t := time.NewTimer(tgCheckFirst)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		before := b.Health()
		h := b.Check(ctx)
		if ctx.Err() != nil {
			return
		}
		if before == nil || before.WS != h.WS || before.Fallback != h.Fallback {
			c.log.Info("tgws: self-check", "websocket", h.WS, "route", h.WSRoute, "fallback", h.Fallback)
		}
		t.Reset(tgCheckEvery)
	}
}

// tgVPNDial reaches a data center through the main server (the bridge's
// fallback before a direct connection).
func (c *Controller) tgVPNDial(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	id := c.memberFor(c.State().Settings.Main)
	if id == "" {
		return nil, errors.New("основной сервер не выбран или не работает")
	}
	ep := c.tunnels.Get(id)
	if ep == nil || !ep.Available() {
		return nil, errors.New("основной сервер не подключён")
	}
	return ep.Dial(ctx, socks5.AddrFromAddrPort(dst))
}

// telegramRule is the rule «Обход DPI: Telegram»: Telegram's addresses go
// to the bridge; when it does not run, through the main server.
func telegramRule() rules.Rule {
	return rules.Rule{Name: ZapretRulePrefix + "Telegram", Domains: slices.Clone(tgws.Networks), Protocol: "tcp",
		Ports: rules.PortList(slices.Clone(tgws.Ports)), Action: rules.Tunnel, Profile: tgws.ProfileID, Fallback: []string{""}}
}

// tgTunnel is the bridge as the relay's way out (relay.Tunnel): TCP only.
type tgTunnel struct{ c *Controller }

func (t tgTunnel) Available() bool    { return t.c.tg.live.Load() != nil }
func (t tgTunnel) UDPAvailable() bool { return false }

func (t tgTunnel) Dial(ctx context.Context, dst socks5.Addr) (net.Conn, error) {
	return tgws.Tunnel{Get: t.c.tg.live.Load}.Dial(ctx, dst)
}

func (t tgTunnel) UDPAssociate(context.Context) (*socks5.UDPAssoc, error) {
	return nil, errors.New("Telegram без VPN несёт только TCP")
}

// TelegramView is the Telegram part of the DPI page.
type TelegramView struct {
	Enabled bool `json:"enabled"`
	// Running: the bridge runs (the switch is on and HyRouter routes).
	Running bool       `json:"running"`
	Stats   tgws.Stats `json:"stats"`
	// Health: the latest self-check (nil: none yet).
	Health *tgws.Health `json:"health,omitempty"`
	// Cloudflare: the route through tg-ws-proxy's Cloudflare domains is
	// on; CloudflareFirst: the DPI bypass carries it, so it goes before
	// the VPN. Workers: the user's Cloudflare Workers.
	Cloudflare      bool     `json:"cloudflare"`
	CloudflareFirst bool     `json:"cloudflareFirst"`
	Workers         []string `json:"workers"`
}

// telegramView is the Telegram part of the page for cfg.
func (c *Controller) telegramView(cfg zapret.Settings) TelegramView {
	t := cfg.Telegram
	v := TelegramView{Enabled: t.Enabled, Cloudflare: !t.NoCloudflare, Workers: slices.Clone(t.Workers)}
	if v.Workers == nil {
		v.Workers = []string{}
	}
	if b := c.tg.live.Load(); b != nil {
		v.Running = true
		v.Stats, v.Health = b.Stats(), b.Health()
		v.CloudflareFirst = !t.NoCloudflare && c.tg.covered.Load()
	}
	return v
}

// TelegramInput is what the page saves.
type TelegramInput struct {
	Enabled    bool     `json:"enabled"`
	Cloudflare bool     `json:"cloudflare"`
	Workers    []string `json:"workers"`
}

// SaveTelegram turns «Telegram без VPN» on or off with its rule.
func (c *Controller) SaveTelegram(ctx context.Context, in TelegramInput) error {
	var workers []string
	for _, w := range in.Workers {
		if strings.TrimSpace(w) == "" {
			continue
		}
		h := zapret.NormalizeWorkers([]string{w})
		if len(h) == 0 {
			return fmt.Errorf("«%s» — не адрес Worker'а (нужен вида имя.аккаунт.workers.dev)", strings.TrimSpace(w))
		}
		if !slices.Contains(workers, h[0]) {
			workers = append(workers, h[0])
		}
	}
	if len(workers) > zapret.MaxWorkers {
		return fmt.Errorf("Worker'ов — не больше %d", zapret.MaxWorkers)
	}
	err := c.Edit(ctx, func(st *store.State) error {
		cfg, err := zapretSettings(*st)
		if err != nil {
			cfg = zapret.Settings{}
		}
		cfg.Telegram.Enabled, cfg.Telegram.NoCloudflare, cfg.Telegram.Workers = in.Enabled, !in.Cloudflare, workers
		cfg.Normalize()
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
		go c.zapretApply() // the bridge follows the switch
	}
	return err
}
