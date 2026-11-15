//go:build linux

package cores

// Modules: cores the user downloads by a button and may remove again (the
// VLESS module: Xray; Hysteria runs inside hyrouterd). modules.json in Dir
// records the installed ones. Path never downloads a module's core before
// it is installed; an installed one that a reboot took from RAM is
// downloaded again.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// ErrNotInstalled: a module the user has not downloaded.
var ErrNotInstalled = errors.New("модуль не установлен")

// Modules are the cores that are modules.
var Modules = []string{Xray}

func isModule(name string) bool { return slices.Contains(Modules, name) }

// loadModules reads modules.json (in.mu held). Without one (an earlier
// version, which downloaded Xray by itself) a module whose core is already
// there counts as installed.
func (in *Installer) loadModules() {
	if in.modules != nil {
		return
	}
	in.modules = map[string]bool{}
	if b, err := os.ReadFile(filepath.Join(in.Dir, "modules.json")); err == nil {
		json.Unmarshal(b, &in.modules)
		return
	}
	in.loadUpdates()
	for _, name := range Modules {
		has := in.updates[name] != nil && in.updates[name].Current != nil
		for _, dir := range []string{in.Dir, in.Spare, in.Staging} {
			if dir == "" {
				continue
			}
			if m, _ := filepath.Glob(filepath.Join(dir, name+"-*")); len(m) > 0 {
				has = true
			}
		}
		in.modules[name] = has
	}
	in.saveModules()
}

// saveModules writes modules.json (in.mu held).
func (in *Installer) saveModules() error {
	if err := os.MkdirAll(in.Dir, 0o755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(in.modules, "", "  ")
	tmp := filepath.Join(in.Dir, "modules.json.tmp")
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(in.Dir, "modules.json"))
}

// Installed reports whether a core may run: always for one that is no
// module.
func (in *Installer) Installed(name string) bool {
	if !isModule(name) {
		return true
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	in.loadModules()
	return in.modules[name]
}

// InstallModule downloads a module's pinned core (or keeps the one there)
// and marks the module installed.
func (in *Installer) InstallModule(ctx context.Context, name string) error {
	if !isModule(name) {
		return fmt.Errorf("%s — не модуль", name)
	}
	c, err := Pinned(name)
	if err != nil {
		return err
	}
	return in.installModule(ctx, name, c)
}

func (in *Installer) installModule(ctx context.Context, name string, c Core) error {
	if _, err := in.install(ctx, name, c); err != nil {
		return err
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	in.loadModules()
	in.modules[name] = true
	return in.saveModules()
}

// RemoveModule deletes a module's cores (the pinned one and downloaded
// updates) and marks it not installed: its servers stop working.
func (in *Installer) RemoveModule(name string) error {
	if !isModule(name) {
		return fmt.Errorf("%s — не модуль", name)
	}
	in.fetch.Lock()
	defer in.fetch.Unlock()
	in.mu.Lock()
	defer in.mu.Unlock()
	in.dropLocked(name)
	in.loadModules()
	in.modules[name] = false
	return in.saveModules()
}

// Drop removes every file of a core and its updates (a core no longer
// used: Hysteria runs inside hyrouterd since 0.7.0).
func (in *Installer) Drop(name string) {
	in.fetch.Lock()
	defer in.fetch.Unlock()
	in.mu.Lock()
	defer in.mu.Unlock()
	in.dropLocked(name)
}

func (in *Installer) dropLocked(name string) {
	for _, dir := range []string{in.Dir, in.Spare, in.Staging} {
		if dir != "" {
			prune(dir, name+"-")
		}
	}
	in.loadUpdates()
	if _, ok := in.updates[name]; ok {
		delete(in.updates, name)
		in.saveUpdates()
	}
}

// ModuleInfo is a module for the page.
type ModuleInfo struct {
	Installed bool   `json:"installed"`
	Version   string `json:"version"` // in use: a downloaded update or the pinned one
	// RAM: the core lives in RAM (the flash had no room for it) and is
	// downloaded again after a reboot.
	RAM  bool  `json:"ram,omitempty"`
	Size int64 `json:"size,omitempty"` // bytes of the core's file (0: none there now)
}

// Module describes a module.
func (in *Installer) Module(name string) ModuleInfo {
	pinned, err := Pinned(name)
	if err != nil {
		return ModuleInfo{}
	}
	mi := ModuleInfo{Installed: in.Installed(name), Version: in.info(name, pinned).Version}
	in.mu.Lock()
	p, _ := in.updated(name, pinned.Version)
	in.mu.Unlock()
	if p == "" {
		p = in.pinnedFile(fileName(name, pinned.Version))
	}
	if p != "" {
		if fi, err := os.Stat(p); err == nil {
			mi.Size = fi.Size()
		}
		mi.RAM = !strings.HasPrefix(p, filepath.Clean(in.Dir)+string(filepath.Separator))
	}
	return mi
}
