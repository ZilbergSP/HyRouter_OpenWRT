//go:build linux

package ctl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/zilbergsp/hyrouter/internal/edition"
	"github.com/zilbergsp/hyrouter/internal/rules"
	"github.com/zilbergsp/hyrouter/internal/store"
)

// The backup (docs/ARCHITECTURE.md, «Резервная копия»): every settings
// file in one JSON file. A restore is planned first (what comes, what
// matches nothing, what sends the whole network direct), then written
// over the files; the files of before are kept for «Вернуть как было».
// When a restore cannot be written and its rollback cannot be either,
// that record is the only copy of the old files: it is marked partial,
// and no new restore runs until «Вернуть как было» puts them back.

// BackupFormat names HyRouter's backups.
const BackupFormat = "hyrouter-backup"

const (
	backupVersion = 1
	maxBackup     = 16 << 20
	planLife      = 15 * time.Minute
)

// Backup is the backup file.
type Backup struct {
	Format  string                     `json:"format"`
	Version int                        `json:"version"`
	Edition string                     `json:"edition"`
	Created time.Time                  `json:"created"`
	Files   map[string]json.RawMessage `json:"files"`
}

// Backup makes the backup of the settings as they are on disk.
func (c *Controller) Backup() ([]byte, error) {
	files, err := c.store.ReadFiles()
	if err != nil {
		return nil, err
	}
	b := Backup{Format: BackupFormat, Version: backupVersion, Edition: edition.Name, Created: time.Now(), Files: map[string]json.RawMessage{}}
	for name, data := range files {
		if !json.Valid(data) {
			return nil, fmt.Errorf("%s повреждён: копия не сделана", name)
		}
		b.Files[name] = data
	}
	return json.MarshalIndent(b, "", "  ")
}

// RestorePlan is what a restore brings, for the user to confirm.
type RestorePlan struct {
	Token    string    `json:"token"`
	Created  time.Time `json:"created"`
	Edition  string    `json:"edition"`
	Servers  int       `json:"servers"`
	Rules    int       `json:"rules"`
	Devices  int       `json:"devices"`
	Groups   int       `json:"groups"`
	Subs     int       `json:"subs"`
	Routing  bool      `json:"routing"`
	Warnings []string  `json:"warnings"`
}

type plannedRestore struct {
	st    store.State
	files map[string][]byte
	until time.Time
}

// restoreState is the controller's part (Controller.rmu).
type restoreState struct {
	plans map[string]plannedRestore
}

// undoDir keeps the files of before the last restore.
func (c *Controller) undoDir() string { return filepath.Join(c.store.Dir, "undo") }

// UndoInfo is the record «Вернуть как было» returns to.
type UndoInfo struct {
	At time.Time `json:"at"`
	// Partial: the restore was not written whole and could not be rolled
	// back; the files of before are only here.
	Partial bool `json:"partial"`
}

func (c *Controller) readUndo() (*UndoInfo, map[string][]byte) {
	b, err := os.ReadFile(filepath.Join(c.undoDir(), "undo.json"))
	if err != nil {
		return nil, nil
	}
	var u UndoInfo
	if json.Unmarshal(b, &u) != nil {
		return nil, nil
	}
	files := map[string][]byte{}
	for _, name := range store.Files {
		if data, err := os.ReadFile(filepath.Join(c.undoDir(), name)); err == nil {
			files[name] = data
		}
	}
	return &u, files
}

// Undo reports the record «Вернуть как было» returns to (nil = none).
func (c *Controller) Undo() *UndoInfo {
	u, _ := c.readUndo()
	return u
}

func (c *Controller) writeUndo(files map[string][]byte, partial bool) error {
	dir := c.undoDir()
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	for name, data := range files {
		if err := store.WriteFile(filepath.Join(dir, name), data); err != nil {
			return err
		}
	}
	b, _ := json.Marshal(UndoInfo{At: time.Now(), Partial: partial})
	return store.WriteFile(filepath.Join(dir, "undo.json"), b)
}

func (c *Controller) markUndoPartial() {
	u, _ := c.readUndo()
	if u == nil {
		return
	}
	u.Partial = true
	b, _ := json.Marshal(u)
	store.WriteFile(filepath.Join(c.undoDir(), "undo.json"), b)
}

// sendsAllDirect reports a rule that sends every site of every device
// direct: only ports, or no condition at all. On a router it takes the
// whole network past the VPN.
func sendsAllDirect(r rules.Rule) bool {
	return r.Action == rules.Direct && (r.Enabled == nil || *r.Enabled) && len(r.Devices) == 0 && len(r.AllDomains()) == 0 && len(r.AllApps()) == 0
}

// PlanRestore reads a backup and says what a restore of it brings. The
// plan is kept for planLife; Restore takes it by its token.
func (c *Controller) PlanRestore(b []byte) (RestorePlan, error) {
	if len(b) > maxBackup {
		return RestorePlan{}, errors.New("файл больше 16 МБ: это не копия HyRouter")
	}
	var bk Backup
	if err := json.Unmarshal(b, &bk); err != nil || bk.Format != BackupFormat {
		return RestorePlan{}, errors.New("это не резервная копия HyRouter")
	}
	if bk.Version > backupVersion {
		return RestorePlan{}, errors.New("копия сделана более новой версией HyRouter: обновите HyRouter")
	}
	files := map[string][]byte{}
	for name, data := range bk.Files {
		if !slices.Contains(store.Files, name) {
			continue // a file of a later version: not ours to write
		}
		files[name] = data
	}
	// The files go through the store's own reading, in a folder of their
	// own: what loads there loads after the restore.
	tmp, err := os.MkdirTemp("", "hyrouter-restore-")
	if err != nil {
		return RestorePlan{}, err
	}
	defer os.RemoveAll(tmp)
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(tmp, name), data, 0o600); err != nil {
			return RestorePlan{}, err
		}
	}
	st, err := (&store.Store{Dir: tmp}).Load()
	if err != nil {
		return RestorePlan{}, fmt.Errorf("копия повреждена: %v", err)
	}
	cur := c.State().Settings
	var warnings []string
	// The router's own side stays: its ID for the panels.
	st.Settings.DeviceID = cur.DeviceID
	for i := range st.Servers {
		p := &st.Servers[i]
		if ca := p.TLS.CA; ca != "" {
			if _, err := os.Stat(ca); err != nil {
				p.TLS.CA = ""
				warnings = append(warnings, fmt.Sprintf("«%s»: файла сертификата %s на роутере нет, сервер проверяется без него", p.Name, ca))
			}
		}
	}
	for _, r := range st.Rules.Rules {
		if sendsAllDirect(r) {
			warnings = append(warnings, fmt.Sprintf("правило «%s» отправляет напрямую весь трафик всех устройств: VPN после него не работает", r.Name))
		}
	}
	for _, n := range st.Settings.LAN {
		if !interfaceExists(n) {
			warnings = append(warnings, fmt.Sprintf("интерфейса %s на этом роутере нет: проверьте «Интерфейсы LAN» после восстановления", n))
		}
	}
	cp, err := compile(st, nil)
	if err != nil {
		return RestorePlan{}, fmt.Errorf("правила копии не применяются: %v", err)
	}
	warnings = append(warnings, cp.issues...)
	// The written files are the parsed state, so what is restored is what
	// was checked.
	raw, err := stateFiles(st, files)
	if err != nil {
		return RestorePlan{}, err
	}
	token := randomID(12)
	c.rmu.Lock()
	if c.restore.plans == nil {
		c.restore.plans = map[string]plannedRestore{}
	}
	for k, p := range c.restore.plans {
		if time.Now().After(p.until) {
			delete(c.restore.plans, k)
		}
	}
	c.restore.plans[token] = plannedRestore{st: st, files: raw, until: time.Now().Add(planLife)}
	c.rmu.Unlock()
	if warnings == nil {
		warnings = []string{}
	}
	return RestorePlan{Token: token, Created: bk.Created, Edition: bk.Edition, Servers: len(st.Servers), Rules: len(st.Rules.Rules),
		Devices: len(st.Devices), Groups: len(st.Groups.Groups), Subs: len(st.Subs), Routing: st.Settings.Enabled, Warnings: warnings}, nil
}

// stateFiles writes a state as the store would; the DPI bypass stays as
// the backup had it.
func stateFiles(st store.State, from map[string][]byte) (map[string][]byte, error) {
	out := map[string][]byte{}
	for name, v := range map[string]any{
		store.SettingsFile: st.Settings, store.ServersFile: st.Servers, store.RulesFile: st.Rules,
		store.DevicesFile: st.Devices, store.GroupsFile: st.Groups, store.SubsFile: st.Subs,
	} {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return nil, err
		}
		out[name] = append(b, '\n')
	}
	if z, ok := from[store.ZapretFile]; ok {
		out[store.ZapretFile] = z
	}
	return out, nil
}

// interfaceExists reports a network interface of the router.
func interfaceExists(name string) bool {
	_, err := os.Stat(filepath.Join("/sys/class/net", name))
	return err == nil
}

// Restore writes a planned restore over the settings and applies it.
func (c *Controller) Restore(ctx context.Context, token string) error {
	c.rmu.Lock()
	p, ok := c.restore.plans[token]
	delete(c.restore.plans, token)
	c.rmu.Unlock()
	if !ok || time.Now().After(p.until) {
		return &EditError{Refused, errors.New("план восстановления устарел: выберите файл ещё раз")}
	}
	c.editMu.Lock()
	defer c.editMu.Unlock()
	if u := c.Undo(); u != nil && u.Partial {
		return &EditError{Refused, errors.New("прошлое восстановление не завершилось: сначала нажмите «Вернуть как было»")}
	}
	before, err := c.store.ReadFiles()
	if err != nil {
		return &EditError{NotSaved, err}
	}
	if err := c.writeUndo(before, false); err != nil {
		return &EditError{NotSaved, fmt.Errorf("копия текущих настроек не сохранена, восстановление не начато: %v", err)}
	}
	if err := c.store.WriteFiles(p.files); err != nil {
		if rerr := c.store.WriteFiles(before); rerr != nil {
			c.markUndoPartial()
			return &EditError{NotSaved, fmt.Errorf("восстановление записано не полностью, и прежние файлы не вернулись: нажмите «Вернуть как было» (%v)", err)}
		}
		return &EditError{NotSaved, fmt.Errorf("восстановление не записано, настройки прежние: %v", err)}
	}
	c.log.Info("settings restored from a backup")
	return c.applyState(ctx, p.st)
}

// UndoRestore puts back the files of before the last restore.
func (c *Controller) UndoRestore(ctx context.Context) error {
	c.editMu.Lock()
	defer c.editMu.Unlock()
	u, files := c.readUndo()
	if u == nil {
		return &EditError{Refused, errors.New("возвращать нечего")}
	}
	if err := c.store.WriteFiles(files); err != nil {
		c.markUndoPartial()
		return &EditError{NotSaved, fmt.Errorf("прежние файлы вернулись не все, попробуйте ещё раз: %v", err)}
	}
	st, err := c.store.Load()
	if err != nil {
		// The files are back, but they do not load: routing stops (with
		// the kill switch the LAN stays closed) rather than routing by
		// rules nobody wrote.
		c.Shutdown()
		os.RemoveAll(c.undoDir())
		return &EditError{NotApplied, fmt.Errorf("прежние файлы возвращены, но не читаются, маршрутизация остановлена: %v", err)}
	}
	os.RemoveAll(c.undoDir())
	c.log.Info("settings of before the restore are back")
	return c.applyState(ctx, st)
}

// applyState makes a state read from new files the one in force: routing
// starts or stops as it says.
func (c *Controller) applyState(ctx context.Context, st store.State) error {
	store.Fill(&st)
	c.subSecrets(st.Subs)
	if err := c.Apply(ctx, st); err != nil {
		return &EditError{NotApplied, err}
	}
	switch on := st.Settings.Enabled; {
	case on && !c.Running():
		if err := c.Start(ctx); err != nil {
			return &EditError{NotApplied, fmt.Errorf("маршрутизация не запустилась: %w", err)}
		}
	case !on && c.Running():
		c.Stop()
	}
	if c.stats.Mode() != statsMode(st.Settings) {
		c.stats.SetMode(time.Now(), statsMode(st.Settings))
	}
	c.syncGuard(st.Settings)
	c.kickGeo()
	return nil
}

// backupName is the file name the interface offers.
func backupName(now time.Time) string {
	return "hyrouter-" + strings.ReplaceAll(now.Format("2006-01-02"), "-", "") + ".json"
}

// BackupName is backupName of now.
func BackupName() string { return backupName(time.Now()) }
