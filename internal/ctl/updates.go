//go:build linux

package ctl

// Updates («Настройки → Обновления»): HyRouter's newer releases, offered
// and installed on request with the router's package manager
// (selfupdate), and newer releases of the cores of the full edition,
// installed on request and rolled back when the servers that ran on the
// old core do not connect on the new one (cores). Checks run a while
// after the start and then once a day; a build that is not a release
// checks only on request.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/zilbergsp/hyrouter/internal/cores"
	"github.com/zilbergsp/hyrouter/internal/edition"
	"github.com/zilbergsp/hyrouter/internal/hysteria"
	"github.com/zilbergsp/hyrouter/internal/release"
	"github.com/zilbergsp/hyrouter/internal/selfupdate"
)

var (
	updatesFirst = 2 * time.Minute
	updatesEvery = 24 * time.Hour
	// coreSettle: the servers a new core restarted have this long to
	// connect before it is rolled back.
	coreSettle = time.Minute
)

// updatesCtl is the controller's part.
type updatesCtl struct {
	mu       sync.Mutex
	checked  time.Time
	checking bool
	err      string
	app      *selfupdate.Available
	busy     bool   // HyRouter is being downloaded or installed
	stage    string // downloading | installing
	progress float64
	instErr  string
	result   *selfupdate.Result
	cores    map[string]*coreUpd

	find   sync.Once
	pkg    selfupdate.Installed
	pkgErr error
}

type coreUpd struct {
	update   *cores.Update
	err      string // the last check
	busy     bool
	progress float64
	note     string // how the last install or rollback went
	failed   bool   // the note is an error
}

// UpdatesView is the section of the page.
type UpdatesView struct {
	Version string `json:"version"`
	// Dev: a build that is not from a release; it checks only on request
	// and is never offered to replace.
	Dev      bool                  `json:"dev"`
	Package  string                `json:"package,omitempty"` // "hyrouter-lite 0.5.0-1 (mipsel_24kc, opkg)"
	Checked  time.Time             `json:"checked,omitzero"`
	Checking bool                  `json:"checking"`
	Error    string                `json:"error,omitempty"` // the last check of HyRouter
	Update   *selfupdate.Available `json:"update,omitempty"`
	Stage    string                `json:"stage,omitempty"` // downloading | installing
	Progress float64               `json:"progress"`
	// InstallError: the download or the start of the installation failed.
	InstallError string             `json:"installError,omitempty"`
	Result       *selfupdate.Result `json:"result,omitempty"` // the last upgrade
	// Embedded: HyRouter Lite, whose Hysteria is inside hyrouterd.
	Embedded bool       `json:"embedded"`
	Cores    []CoreView `json:"cores"`
}

// CoreView is a core in UpdatesView.
type CoreView struct {
	cores.Info
	Update     *cores.Update `json:"update,omitempty"`
	CheckError string        `json:"checkError,omitempty"`
	Busy       bool          `json:"busy"`
	Progress   float64       `json:"progress"`
	Note       string        `json:"note,omitempty"`
	Failed     bool          `json:"failed,omitempty"`
}

// coreNames are the cores this edition downloads and updates: none in
// Lite (Hysteria is inside hyrouterd, and VLESS is not there).
func coreNames() []string {
	if edition.Lite {
		return nil
	}
	return []string{cores.Hysteria, cores.Xray}
}

// coreOf is the core a server runs on.
func coreOf(p hysteria.Profile) string {
	if p.IsVLESS() {
		return cores.Xray
	}
	return cores.Hysteria
}

// coreVersion runs a core's "version" (cores.Installer.Version).
func coreVersion(name, path string) (string, error) {
	if name == cores.Xray {
		return hysteria.XrayVersion(path)
	}
	return hysteria.ExeVersion(path)
}

// isDev: hyrouterd's version is not a release's.
func isDev(v string) bool {
	_, err := release.Parse(v)
	return err != nil
}

// releases reads GitHub. HYROUTER_RELEASES_API replaces GitHub's API in
// CI's test of the upgrade.
func (c *Controller) releases() *release.Client {
	return &release.Client{UserAgent: "HyRouter/" + c.version, API: os.Getenv("HYROUTER_RELEASES_API")}
}

// installed is HyRouter's package (read once: it changes only with an
// upgrade, which brings another hyrouterd).
func (c *Controller) installed() (selfupdate.Installed, error) {
	u := &c.upd
	u.find.Do(func() { u.pkg, u.pkgErr = selfupdate.Find() })
	return u.pkg, u.pkgErr
}

func (u *updatesCtl) core(name string) *coreUpd {
	if u.cores == nil {
		u.cores = map[string]*coreUpd{}
	}
	if u.cores[name] == nil {
		u.cores[name] = &coreUpd{}
	}
	return u.cores[name]
}

// Updates is the section of the page.
func (c *Controller) Updates() UpdatesView {
	u := &c.upd
	r := selfupdate.ReadResult(c.version)
	v := UpdatesView{Version: c.version, Dev: isDev(c.version), Embedded: edition.Lite, Cores: []CoreView{}}
	if in, err := c.installed(); err == nil {
		v.Package = fmt.Sprintf("%s %s (%s, %s)", in.Package, in.Version, in.Arch, in.Manager)
	}
	infos := map[string]cores.Info{}
	for _, name := range coreNames() {
		infos[name] = c.cores.Info(name)
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if r != nil {
		u.result = r
		if r.Done {
			u.busy, u.stage = false, ""
		}
		if r.OK {
			u.app = nil
		}
	}
	v.Checked, v.Checking, v.Error, v.Update = u.checked, u.checking, u.err, u.app
	v.Stage, v.Progress, v.InstallError, v.Result = u.stage, u.progress, u.instErr, u.result
	for _, name := range coreNames() {
		cu := u.core(name)
		v.Cores = append(v.Cores, CoreView{Info: infos[name], Update: cu.update, CheckError: cu.err, Busy: cu.busy,
			Progress: cu.progress, Note: cu.note, Failed: cu.failed})
	}
	return v
}

// availableUpdate is the version of HyRouter on offer ("" = none), for
// the home page.
func (c *Controller) availableUpdate() string {
	c.upd.mu.Lock()
	defer c.upd.mu.Unlock()
	if c.upd.app == nil {
		return ""
	}
	return c.upd.app.Version
}

// CheckUpdates looks for a newer HyRouter and newer cores.
func (c *Controller) CheckUpdates(ctx context.Context) {
	u := &c.upd
	u.mu.Lock()
	if u.checking {
		u.mu.Unlock()
		return
	}
	u.checking = true
	u.mu.Unlock()
	cl := c.releases()

	var app *selfupdate.Available
	var appErr string
	if in, err := c.installed(); err != nil {
		appErr = err.Error()
	} else if a, ok, err := selfupdate.Check(ctx, cl, in, c.version); err != nil {
		appErr = err.Error()
	} else if ok {
		app = &a
	}
	type coreCheck struct {
		up  *cores.Update
		err string
	}
	checks := map[string]coreCheck{}
	for _, name := range coreNames() {
		up, ok, err := c.cores.Check(ctx, cl, name)
		switch {
		case err != nil:
			checks[name] = coreCheck{err: err.Error()}
		case ok:
			checks[name] = coreCheck{up: &up}
		default:
			checks[name] = coreCheck{}
		}
	}

	u.mu.Lock()
	defer u.mu.Unlock()
	u.checking, u.checked, u.err = false, time.Now(), appErr
	if !u.busy {
		if app != nil && (u.app == nil || u.app.Version != app.Version) {
			c.log.Info("update: a newer HyRouter", "version", app.Version)
		}
		u.app = app
	}
	for name, ch := range checks {
		cu := u.core(name)
		if cu.busy {
			continue
		}
		cu.update, cu.err = ch.up, ch.err
	}
}

// InstallUpdate downloads the HyRouter on offer and starts its
// installation; the package manager restarts hyrouterd.
func (c *Controller) InstallUpdate() error {
	in, err := c.installed()
	if err != nil {
		return err
	}
	u := &c.upd
	u.mu.Lock()
	switch {
	case u.busy:
		u.mu.Unlock()
		return errors.New("обновление уже идёт")
	case u.app == nil:
		u.mu.Unlock()
		return errors.New("обновления нет: проверьте ещё раз")
	}
	a := *u.app
	u.busy, u.stage, u.progress, u.instErr, u.result = true, "downloading", 0, "", nil
	u.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		file, err := selfupdate.Download(ctx, c.releases(), a, func(done, total int64) {
			if total > 0 {
				u.mu.Lock()
				u.progress = float64(done) / float64(total)
				u.mu.Unlock()
			}
		})
		if err == nil {
			u.mu.Lock()
			u.stage = "installing"
			u.mu.Unlock()
			c.log.Info("update: installing", "from", c.version, "to", a.Version, "package", a.Asset)
			err = selfupdate.Launch(in, file, c.version, a.Version)
		}
		if err != nil {
			c.log.Warn("update: not installed", "version", a.Version, "err", err)
			u.mu.Lock()
			u.busy, u.stage, u.instErr = false, "", err.Error()
			u.mu.Unlock()
		}
	}()
	return nil
}

// InstallCore installs the newer release of a core on offer and restarts
// the servers on it; when the ones that were connected do not connect
// again within coreSettle, the core is rolled back.
func (c *Controller) InstallCore(name string) error {
	if !slices.Contains(coreNames(), name) {
		return fmt.Errorf("ядро %s здесь не обновляется", name)
	}
	u := &c.upd
	u.mu.Lock()
	cu := u.core(name)
	switch {
	case cu.busy:
		u.mu.Unlock()
		return errors.New("ядро уже обновляется")
	case cu.update == nil:
		u.mu.Unlock()
		return errors.New("обновления ядра нет: проверьте ещё раз")
	}
	up := *cu.update
	cu.busy, cu.progress, cu.note, cu.failed = true, 0, "", false
	u.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		c.log.Info("update: installing a core", "core", name, "version", up.Version)
		err := c.cores.Install(ctx, c.releases(), up, func(done, total int64) {
			if total > 0 {
				u.mu.Lock()
				cu.progress = float64(done) / float64(total)
				u.mu.Unlock()
			}
		})
		var note string
		if err == nil {
			note, err = c.tryCore(name, up.Version)
		}
		if err != nil {
			c.log.Warn("update: the core not installed", "core", name, "version", up.Version, "err", err)
			note = err.Error()
		}
		u.mu.Lock()
		cu.busy, cu.note, cu.failed = false, note, err != nil
		if err == nil {
			cu.update = nil
		}
		u.mu.Unlock()
	}()
	return nil
}

// RollbackCore returns a core to the one it replaced and restarts the
// servers on it.
func (c *Controller) RollbackCore(name string) error {
	if !slices.Contains(coreNames(), name) {
		return fmt.Errorf("ядро %s здесь не обновляется", name)
	}
	u := &c.upd
	u.mu.Lock()
	cu := u.core(name)
	if cu.busy {
		u.mu.Unlock()
		return errors.New("ядро сейчас обновляется")
	}
	cu.busy = true
	u.mu.Unlock()
	err := c.cores.Rollback(name)
	if err == nil {
		c.log.Info("update: a core rolled back", "core", name)
		c.restartCore(name)
	}
	u.mu.Lock()
	cu.busy = false
	if err == nil {
		cu.note, cu.failed = "Возвращено прежнее ядро, серверы на нём перезапущены.", false
	}
	u.mu.Unlock()
	return err
}

// coreServers are the routing servers on a core and which of them are
// connected.
func (c *Controller) coreServers(name string) (ids []string, connected map[string]bool) {
	byID := map[string]hysteria.Profile{}
	if ps := c.inUse.Load(); ps != nil {
		for _, p := range *ps {
			byID[p.ID] = p
		}
	}
	connected = map[string]bool{}
	for _, s := range c.tunnels.Statuses() {
		p, ok := byID[s.ID]
		if s.Test || !ok || coreOf(p) != name {
			continue
		}
		ids = append(ids, s.ID)
		if s.State == "connected" {
			connected[s.ID] = true
		}
	}
	return ids, connected
}

// restartCore starts the servers on a core again, so they run the core
// installed now.
func (c *Controller) restartCore(name string) {
	if !c.Running() {
		return
	}
	ps := c.inUse.Load()
	if ps == nil {
		return
	}
	var keep []hysteria.Profile
	for _, p := range *ps {
		if coreOf(p) != name {
			keep = append(keep, p)
		}
	}
	c.tunnels.Sync(keep)
	c.tunnels.Sync(*ps)
}

// tryCore restarts the servers on a core just installed and waits for
// those that were connected to connect again; otherwise the core is
// rolled back. The note says how it went.
func (c *Controller) tryCore(name, version string) (string, error) {
	ids, before := c.coreServers(name)
	if len(ids) == 0 {
		return "Ядро " + version + " установлено: серверы возьмут его при следующем подключении.", nil
	}
	c.restartCore(name)
	if len(before) == 0 {
		return "Ядро " + version + " установлено, серверы на нём перезапущены.", nil
	}
	for end := time.Now().Add(coreSettle); time.Now().Before(end); time.Sleep(time.Second) {
		_, now := c.coreServers(name)
		for id := range before {
			if now[id] {
				return "Ядро " + version + " установлено: серверы подключились с ним.", nil
			}
		}
	}
	if err := c.cores.Rollback(name); err != nil {
		return "", fmt.Errorf("с ядром %s серверы не подключились, и прежнее ядро не вернулось: %v", version, err)
	}
	c.restartCore(name)
	return "", fmt.Errorf("с ядром %s серверы не подключились за %d с: возвращено прежнее ядро", version, int(coreSettle.Seconds()))
}

// runUpdates checks for updates a while after the start, then once a day
// (not in a build that is not a release's).
func (c *Controller) runUpdates(ctx context.Context) {
	if isDev(c.version) {
		return
	}
	t := time.NewTimer(updatesFirst)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		c.CheckUpdates(cctx)
		cancel()
		t.Reset(updatesEvery)
	}
}
