//go:build linux

package ctl

// Modules («Настройки → Модули»): what HyRouter downloads only by a
// button. Since 0.7.0 that is VLESS (the Xray core): Hysteria runs inside
// hyrouterd. A VLESS server without the module refuses its connections,
// and the home page says why.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/zilbergsp/hyrouter/internal/cores"
	"github.com/zilbergsp/hyrouter/internal/edition"
)

// module is one module of the page.
type module struct {
	id, core, title, hint string
}

var modules = []module{
	{id: "vless", core: cores.Xray, title: "VLESS (Xray)",
		hint: "Нужен серверам vless://. Ядро Xray занимает около 32 МБ (скачивается архив 15 МБ). Если на флеше нет места, оно хранится во временном хранилище и после перезагрузки роутера скачивается заново."},
}

func findModule(id string) (module, bool) {
	for _, m := range modules {
		if m.id == id {
			return m, true
		}
	}
	return module{}, false
}

// modCtl is the controller's part.
type modCtl struct {
	mu   sync.Mutex
	busy map[string]bool
	err  map[string]string
}

// ModuleView is a module on the page.
type ModuleView struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Hint  string `json:"hint"`
	cores.ModuleInfo
	// Available: this edition runs it (Lite has no VLESS).
	Available bool   `json:"available"`
	Busy      bool   `json:"busy"`
	Error     string `json:"error,omitempty"`
	// Servers: the servers of the settings that need it.
	Servers int `json:"servers"`
}

// Modules lists the modules.
func (c *Controller) Modules() []ModuleView {
	vless := 0
	for _, p := range c.State().Servers {
		if p.IsVLESS() {
			vless++
		}
	}
	c.mods.mu.Lock()
	defer c.mods.mu.Unlock()
	out := make([]ModuleView, 0, len(modules))
	for _, m := range modules {
		v := ModuleView{ID: m.id, Title: m.title, Hint: m.hint, Available: edition.Current.VLESS,
			Busy: c.mods.busy[m.id], Error: c.mods.err[m.id], Servers: vless}
		if v.Available {
			v.ModuleInfo = c.cores.Module(m.core)
		}
		out = append(out, v)
	}
	return out
}

// ModuleInstalled reports whether a module is installed.
func (c *Controller) ModuleInstalled(id string) bool {
	m, ok := findModule(id)
	return ok && edition.Current.VLESS && c.cores.Installed(m.core)
}

// InstallModule downloads a module by the button; the servers that need it
// start again with it.
func (c *Controller) InstallModule(id string) error {
	m, ok := findModule(id)
	switch {
	case !ok:
		return fmt.Errorf("нет модуля «%s»", id)
	case !edition.Current.VLESS:
		return errors.New("в " + edition.Name + " нет VLESS: только Hysteria 2")
	}
	c.mods.mu.Lock()
	if c.mods.busy[id] {
		c.mods.mu.Unlock()
		return errors.New("модуль уже скачивается")
	}
	if c.mods.busy == nil {
		c.mods.busy, c.mods.err = map[string]bool{}, map[string]string{}
	}
	c.mods.busy[id], c.mods.err[id] = true, ""
	c.mods.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		c.log.Info("modules: installing", "module", id)
		err := c.cores.InstallModule(ctx, m.core)
		if err == nil {
			c.reapply()
			c.restartCore(m.core)
		} else {
			c.log.Warn("modules: not installed", "module", id, "err", err)
		}
		c.mods.mu.Lock()
		c.mods.busy[id] = false
		if err != nil {
			c.mods.err[id] = err.Error()
		}
		c.mods.mu.Unlock()
	}()
	return nil
}

// RemoveModule deletes a module; the servers that need it stop.
func (c *Controller) RemoveModule(id string) error {
	m, ok := findModule(id)
	if !ok {
		return fmt.Errorf("нет модуля «%s»", id)
	}
	c.mods.mu.Lock()
	busy := c.mods.busy[id]
	c.mods.mu.Unlock()
	if busy {
		return errors.New("модуль сейчас скачивается")
	}
	if err := c.cores.RemoveModule(m.core); err != nil {
		return err
	}
	c.log.Info("modules: removed", "module", id)
	c.reapply()
	c.restartCore(m.core)
	return nil
}

// reapply applies the settings in force again while routing: the issues
// of the home page follow a module installed or removed.
func (c *Controller) reapply() {
	if !c.Running() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := c.Apply(ctx, c.State()); err != nil {
		c.log.Warn("modules: the settings not applied again", "err", err)
	}
}
