//go:build linux

package ctl

import (
	"context"
	"errors"

	"github.com/zilbergsp/hyrouter/internal/cores"
	"github.com/zilbergsp/hyrouter/internal/hycore"
	"github.com/zilbergsp/hyrouter/internal/hysteria"
	"github.com/zilbergsp/hyrouter/internal/tunnels"
)

// embedded runs a Hysteria 2 server inside hyrouterd (hycore), in both
// editions since 0.7.0: no hysteria process and no core to download. A
// VLESS server runs Xray, the VLESS module (cores.Modules).
func (c *Controller) embedded(p hysteria.Profile, h tunnels.Hooks) tunnels.Runner {
	if p.IsVLESS() {
		return nil
	}
	return &hycore.Runner{Profile: p, Hooks: h, Log: c.log, Tune: tuneQUIC}
}

// needsCore: only a VLESS server runs a core of its own (Xray).
func needsCore(p hysteria.Profile) bool { return p.IsVLESS() }

// fetchCores readies the cores of the servers in use before any traffic
// waits for them. A module not installed or a failed download is an issue
// (its servers refuse their connections), never a reason not to route.
func (c *Controller) fetchCores(ctx context.Context, cp *compiled) {
	seen := map[string]bool{}
	for _, p := range cp.profiles {
		if !needsCore(p) || seen[coreOf(p)] {
			continue
		}
		seen[coreOf(p)] = true
		if _, err := c.cores.Path(ctx, coreOf(p)); err != nil {
			cp.issues = append(cp.issues, coreIssue(err))
		}
	}
}

// coreIssue tells why VLESS servers do not run.
func coreIssue(err error) string {
	if errors.Is(err, cores.ErrNotInstalled) {
		return "модуль VLESS не установлен: серверы VLESS не работают. Скачайте его в «Настройки → Модули»"
	}
	return "ядро Xray не скачалось, серверы VLESS не работают: " + err.Error()
}
