//go:build linux

package ctl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zilbergsp/hyrouter/internal/geodata"
	"github.com/zilbergsp/hyrouter/internal/rules"
	"github.com/zilbergsp/hyrouter/internal/socks5"
	"github.com/zilbergsp/hyrouter/internal/store"
)

// The rule database (docs/ARCHITECTURE.md, «Базы geosite и geoip»). Its
// files are tens of megabytes: too much for a router's flash, and for its
// memory to keep. An update downloads them into /tmp, writes the
// categories the rules use into the cache on flash (/etc/hyrouter/geo)
// and removes them. Rules are compiled from the cache, so they work right
// after a reboot; a category the rules name that is not in the cache yet
// starts a download. geoip categories go into the nftables sets of their
// rules, geosite ones are matched by the names HyRouter's DNS answers.

// GeoTmpDir holds the downloaded databases until their categories are
// written out.
const GeoTmpDir = "/tmp/hyrouter/geo"

var (
	geoRetry = 10 * time.Minute // a failed download of missing categories
	geoDaily = 24 * time.Hour   // the automatic update
)

// geoCatRe is a category name as the cache stores it.
var geoCatRe = regexp.MustCompile(`^[a-z0-9][a-z0-9@!_.\-]{0,63}$`)

// geoCache is the rules' rules.Geo: categories from the cache, else from
// a downloaded database (then written to the cache).
type geoCache struct {
	dir string
	db  *geodata.DB

	mu    sync.Mutex
	sites map[string]*geodata.DomainSet
	ips   map[string]*geodata.IPSet
}

func newGeoCache(dir string) *geoCache {
	return &geoCache{dir: dir, db: &geodata.DB{Dir: GeoTmpDir}, sites: map[string]*geodata.DomainSet{}, ips: map[string]*geodata.IPSet{}}
}

func (g *geoCache) path(kind, name string) string {
	return filepath.Join(g.dir, kind+"-"+name+".txt")
}

func readLines(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return strings.FieldsFunc(string(b), func(r rune) bool { return r == '\n' || r == '\r' }), nil
}

func writeLines(path string, lines []string) error {
	return store.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"))
}

func geoErr(err error) error {
	if errors.Is(err, geodata.ErrNoData) {
		return rules.ErrGeoNoData
	}
	return err
}

func (g *geoCache) Site(name string) (rules.DomainMatcher, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if !geoCatRe.MatchString(name) {
		return nil, fmt.Errorf("неверное имя категории %q", name)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if d := g.sites[name]; d != nil {
		return d, nil
	}
	if lines, err := readLines(g.path("site", name)); err == nil {
		if d, err := geodata.ParseEntries(lines); err == nil {
			g.sites[name] = d
			return d, nil
		}
	}
	d, err := g.db.Site(name)
	if err != nil {
		return nil, geoErr(err)
	}
	if err := writeLines(g.path("site", name), d.Entries()); err != nil {
		return nil, err
	}
	g.sites[name] = d
	return d, nil
}

func (g *geoCache) IP(name string) (rules.IPMatcher, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if !geoCatRe.MatchString(name) {
		return nil, fmt.Errorf("неверное имя категории %q", name)
	}
	if name == "private" {
		return geodata.Private, nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if s := g.ips[name]; s != nil {
		return s, nil
	}
	if lines, err := readLines(g.path("ip", name)); err == nil {
		var pfx []netip.Prefix
		ok := true
		for _, l := range lines {
			p, err := netip.ParsePrefix(l)
			if err != nil {
				ok = false
				break
			}
			pfx = append(pfx, p)
		}
		if ok {
			s := geodata.NewIPSet(pfx)
			g.ips[name] = s
			return s, nil
		}
	}
	s, err := g.db.IP(name)
	if err != nil {
		return nil, geoErr(err)
	}
	var lines []string
	for _, p := range s.Prefixes() {
		lines = append(lines, p.String())
	}
	if err := writeLines(g.path("ip", name), lines); err != nil {
		return nil, err
	}
	g.ips[name] = s
	return s, nil
}

// cached lists the categories in the cache.
func (g *geoCache) cached() (sites, ips []string) {
	entries, _ := os.ReadDir(g.dir)
	for _, e := range entries {
		n, ok := strings.CutSuffix(e.Name(), ".txt")
		if !ok {
			continue
		}
		if s, ok := strings.CutPrefix(n, "site-"); ok {
			sites = append(sites, s)
		} else if s, ok := strings.CutPrefix(n, "ip-"); ok {
			ips = append(ips, s)
		}
	}
	return sites, ips
}

// reset forgets what is in memory: the next compile reads the cache and
// the database again.
func (g *geoCache) reset() {
	g.mu.Lock()
	g.sites = map[string]*geodata.DomainSet{}
	g.ips = map[string]*geodata.IPSet{}
	g.mu.Unlock()
	g.db.Forget()
}

// extract writes the categories names of the downloaded databases into
// the cache and removes the cache files of categories no rule uses.
func (g *geoCache) extract(sites, ips []string) error {
	var errs []error
	for _, n := range sites {
		if d, err := g.db.Site(n); err == nil {
			errs = append(errs, writeLines(g.path("site", n), d.Entries()))
		} else if !errors.Is(err, geodata.ErrNoData) {
			errs = append(errs, fmt.Errorf("geosite:%s: %v", n, err))
		}
	}
	for _, n := range ips {
		if n == "private" {
			continue
		}
		if s, err := g.db.IP(n); err == nil {
			var lines []string
			for _, p := range s.Prefixes() {
				lines = append(lines, p.String())
			}
			errs = append(errs, writeLines(g.path("ip", n), lines))
		} else if !errors.Is(err, geodata.ErrNoData) {
			errs = append(errs, fmt.Errorf("geoip:%s: %v", n, err))
		}
	}
	cs, ci := g.cached()
	for _, n := range cs {
		if !slices.Contains(sites, n) {
			os.Remove(g.path("site", n))
		}
	}
	for _, n := range ci {
		if !slices.Contains(ips, n) {
			os.Remove(g.path("ip", n))
		}
	}
	g.reset()
	return errors.Join(errs...)
}

// geoNeeded are the geosite and geoip categories the rules name.
func geoNeeded(c rules.Config) (sites, ips []string) {
	add := func(list *[]string, name string) {
		name = strings.ToLower(strings.TrimSpace(name))
		if geoCatRe.MatchString(name) && !slices.Contains(*list, name) {
			*list = append(*list, name)
		}
	}
	for _, r := range c.Rules {
		for _, d := range r.AllDomains() {
			d = strings.TrimSpace(d)
			if len(d) > 8 && strings.EqualFold(d[:8], "geosite:") {
				add(&sites, d[8:])
			} else if len(d) > 6 && strings.EqualFold(d[:6], "geoip:") {
				add(&ips, d[6:])
			}
		}
	}
	return sites, ips
}

// geoState is what the cache was made from (geo/state.json).
type geoState struct {
	Source  string    `json:"source"`
	SiteSum string    `json:"siteSum,omitempty"`
	IPSum   string    `json:"ipSum,omitempty"`
	Updated time.Time `json:"updated,omitzero"`
	Checked time.Time `json:"checked,omitzero"`
	Error   string    `json:"error,omitempty"`
}

func (g *geoCache) state() geoState {
	var st geoState
	if b, err := os.ReadFile(filepath.Join(g.dir, "state.json")); err == nil {
		json.Unmarshal(b, &st)
	}
	return st
}

func (g *geoCache) saveState(st geoState) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return store.WriteFile(filepath.Join(g.dir, "state.json"), b)
}

// GeoStatus is the rule database for the web interface.
type GeoStatus struct {
	Source  string           `json:"source"`
	Sources []geodata.Source `json:"sources"`
	Auto    bool             `json:"auto"`
	Updated time.Time        `json:"updated,omitzero"`
	Checked time.Time        `json:"checked,omitzero"`
	Error   string           `json:"error,omitempty"`
	Busy    bool             `json:"busy"`
	Sites   []string         `json:"sites"`
	IPs     []string         `json:"ips"`
	// Missing are the categories the rules name that are not in the
	// cache (they match nothing until a download brings them).
	Missing []string `json:"missing"`
	// Categories are the well-known categories with the databases that
	// have them: the rule templates warn about a list the chosen one lacks.
	Categories []geodata.Category `json:"categories"`
}

// geoSource is the chosen source.
func geoSource(s store.Settings) geodata.Source {
	if src, ok := geodata.FindSource(s.Geo.Source); ok {
		return src
	}
	src, _ := geodata.FindSource(geodata.DefaultSource)
	return src
}

// GeoStatus reports the rule database.
func (c *Controller) GeoStatus() GeoStatus {
	st := c.State()
	gs := c.geo.state()
	out := GeoStatus{Source: geoSource(st.Settings).ID, Sources: geodata.Sources, Auto: st.Settings.Geo.Auto,
		Updated: gs.Updated, Checked: gs.Checked, Error: gs.Error, Busy: c.geoBusy.Load(), Missing: []string{}}
	out.Categories = geodata.Popular
	out.Sites, out.IPs = c.geo.cached()
	if out.Sites == nil {
		out.Sites = []string{}
	}
	if out.IPs == nil {
		out.IPs = []string{}
	}
	sites, ips := geoNeeded(st.Rules)
	for _, n := range sites {
		if !slices.Contains(out.Sites, n) {
			out.Missing = append(out.Missing, "geosite:"+n)
		}
	}
	for _, n := range ips {
		if n != "private" && !slices.Contains(out.IPs, n) {
			out.Missing = append(out.Missing, "geoip:"+n)
		}
	}
	return out
}

// kickGeo asks the updater to bring the categories the rules miss.
func (c *Controller) kickGeo() {
	select {
	case c.geoKick <- false:
	default:
	}
}

// UpdateGeo downloads the databases now (the web interface's button) and
// waits for the result.
func (c *Controller) UpdateGeo(ctx context.Context) error {
	return c.updateGeo(ctx, true)
}

// runGeo is the updater: categories the rules miss (kickGeo, at most once
// in geoRetry), and the daily update when it is chosen.
func (c *Controller) runGeo(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	var lastMiss time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.geoKick:
		case <-t.C:
		}
		st := c.State()
		missing := len(c.GeoStatus().Missing) > 0
		gs := c.geo.state()
		switch {
		case missing && time.Since(lastMiss) >= geoRetry:
			lastMiss = time.Now()
		case st.Settings.Geo.Auto && time.Since(gs.Checked) >= geoDaily:
			sites, ips := geoNeeded(st.Rules)
			if len(sites)+len(ips) == 0 {
				continue
			}
		default:
			continue
		}
		if err := c.updateGeo(ctx, false); err != nil {
			c.log.Warn("rule database not updated", "err", err)
		}
	}
}

// updateGeo downloads what the rules need from the chosen source, unless
// its published checksums say nothing changed (force: always), writes the
// categories into the cache, frees the memory and recompiles the rules.
func (c *Controller) updateGeo(ctx context.Context, force bool) error {
	c.geoMu.Lock()
	defer c.geoMu.Unlock()
	c.geoBusy.Store(true)
	defer c.geoBusy.Store(false)
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	st := c.State()
	src := geoSource(st.Settings)
	sites, ips := geoNeeded(st.Rules)
	gs := c.geo.state()
	if gs.Source != src.ID {
		force = true
	}
	up := &geodata.Updater{DB: c.geo.db, Download: c.geoDownload}
	// Only the kinds the rules use.
	want := geodata.Source{ID: src.ID}
	if len(sites) > 0 {
		want.Site = src.Site
	}
	if len(ips) > 0 && slices.ContainsFunc(ips, func(n string) bool { return n != "private" }) {
		want.IP = src.IP
	}
	gs.Checked = time.Now()
	if want.Site == "" && want.IP == "" {
		gs.Error = ""
		c.geo.extract(nil, nil)
		return c.geo.saveState(gs)
	}
	status := c.GeoStatus()
	if !force && len(status.Missing) == 0 {
		siteSum, err1 := "", error(nil)
		if want.Site != "" {
			siteSum, err1 = up.PublishedSum(ctx, want.Site)
		}
		ipSum, err2 := "", error(nil)
		if want.IP != "" {
			ipSum, err2 = up.PublishedSum(ctx, want.IP)
		}
		if err1 == nil && err2 == nil && (want.Site == "" || siteSum != "" && siteSum == gs.SiteSum) && (want.IP == "" || ipSum != "" && ipSum == gs.IPSum) {
			gs.Error = ""
			return c.geo.saveState(gs)
		}
	}
	defer os.RemoveAll(GeoTmpDir)
	res, err := up.Update(ctx, want, true)
	if err != nil {
		gs.Error = err.Error()
		c.geo.saveState(gs)
		return err
	}
	us := up.State()
	gs.Source, gs.Updated, gs.Error = src.ID, time.Now(), ""
	if us.Site != nil {
		gs.SiteSum = us.Site.SHA256
	}
	if us.IP != nil {
		gs.IPSum = us.IP.SHA256
	}
	if err := c.geo.extract(sites, ips); err != nil {
		gs.Error = err.Error()
	}
	c.geo.saveState(gs)
	c.log.Info("rule database updated", "source", src.ID, "notes", strings.Join(res.Notes, "; "))
	// The rules see the new categories.
	return c.Edit(ctx, func(*store.State) error { return nil }, func(store.State) error { return nil })
}

// geoDownload fetches a database: directly, and the retry through the
// main server (GitHub may be blocked).
func (c *Controller) geoDownload(ctx context.Context, url string, attempt int) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "HyRouter/"+c.version)
	if attempt > 0 {
		if tun := c.mainTunnel(); tun != nil {
			return c.tunnelHTTP(tun).Do(req)
		}
	}
	return (&http.Client{CheckRedirect: geodata.NoDowngrade}).Do(req)
}

// mainTunnel is the main server's way out, nil when it does not run.
func (c *Controller) mainTunnel() interface {
	Dial(context.Context, socks5.Addr) (net.Conn, error)
} {
	id := c.memberFor(c.State().Settings.Main)
	if id == "" {
		return nil
	}
	ep := c.tunnels.Get(id)
	if ep == nil || !ep.Available() {
		return nil
	}
	return ep
}

// tunnelHTTP is a client that goes through a server.
func (c *Controller) tunnelHTTP(tun interface {
	Dial(context.Context, socks5.Addr) (net.Conn, error)
}) *http.Client {
	return &http.Client{CheckRedirect: geodata.NoDowngrade, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			pn, err := strconv.Atoi(port)
			if err != nil {
				return nil, err
			}
			return tun.Dial(ctx, socks5.Addr{Host: host, Port: uint16(pn)})
		},
		TLSHandshakeTimeout: 20 * time.Second,
		DisableKeepAlives:   true,
	}}
}
