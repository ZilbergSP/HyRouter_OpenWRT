//go:build linux && keenetic

package ctl

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/zilbergsp/hyrouter/internal/ipt"
	"github.com/zilbergsp/hyrouter/internal/kernel"
	"github.com/zilbergsp/hyrouter/internal/rules"
	"github.com/zilbergsp/hyrouter/internal/store"
	"github.com/zilbergsp/hyrouter/internal/zapret"
)

// The firewall of KeeneticOS: HyRouter's iptables chains and ipsets
// (internal/ipt). The firmware rebuilds its tables when a connection
// changes: the netfilter.d hook loads HyRouter's chains again, and
// fwWatch checks them and the policy routing every few seconds.

// fwScript is the compiled rules.
type fwScript = *ipt.Part

// fwSets fills the rules' DNS sets.
type fwSets = *ipt.Sets

const (
	fwCTMask   = ipt.CTMask
	fwCTDirect = ipt.CTDirect
	fwCTBlock  = ipt.CTBlock
)

var fwRoute = kernel.PolicyRouting{Mark: ipt.MarkTProxy, Mask: ipt.MarkTProxy, Table: ipt.RouteTable, Priority: ipt.RulePriority}

// fwWatchEvery is how often fwWatch checks the rules.
var fwWatchEvery = 15 * time.Second

// fwCompile compiles the rules; extra is the DPI bypass's part as JSON
// (fwZapret).
func fwCompile(plan []rules.PlanRule, def rules.Result, s store.Settings, extra string) (fwScript, error) {
	p, err := ipt.Compile(plan, def, ipt.Options{LAN: s.LAN, TunnelPort: s.TunnelPort, NamePort: s.NamePort, DNSPort: s.DNSPort}, ipt.HaveIPv6())
	if err != nil {
		return nil, err
	}
	if extra != "" {
		var z ipt.Part
		if err := json.Unmarshal([]byte(extra), &z); err != nil {
			return nil, err
		}
		p.Merge(z)
	}
	return p, nil
}

func fwLoad(ctx context.Context, script fwScript, lan []string) ([]string, error) {
	return ipt.Load(ctx, script, lan)
}

func fwRemove(ctx context.Context) error                  { return ipt.Remove(ctx) }
func fwOpenSets() (fwSets, error)                         { return ipt.OpenSets() }
func fwLoadGuard(ctx context.Context, lan []string) error { return ipt.LoadGuard(ctx, lan) }
func fwRemoveGuard(ctx context.Context) error             { return ipt.RemoveGuard(ctx) }
func fwGuardActive(ctx context.Context) bool              { return ipt.GuardActive(ctx) }

// fwZapret is the DPI bypass's part of the rules, as JSON: the
// controller keeps it as text, as the nftables one.
func fwZapret(c zapret.NFTConfig) (string, error) {
	p, err := zapret.IPT(c, ipt.HaveIPv6())
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(p)
	return string(b), err
}

// fwWatch puts back what the firmware took while routing runs: the
// chains and their jumps, and the policy routing rule.
func (c *Controller) fwWatch(ctx context.Context) {
	t := time.NewTicker(fwWatchEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		fixed, err := ipt.Heal(cctx)
		cancel()
		if len(fixed) > 0 {
			c.log.Warn("firewall: the firmware dropped HyRouter's rules, loaded again", "tables", strings.Join(fixed, " "))
		}
		if err != nil && ctx.Err() == nil {
			c.log.Warn("firewall: the rules could not be checked", "err", err)
		}
		if ok, err := c.route.Present(); err == nil && !ok {
			if err := c.route.Install(); err != nil {
				c.log.Error("routing rule not restored", "err", err)
			} else {
				c.log.Warn("the firmware dropped HyRouter's routing rule, added again")
			}
		}
	}
}
