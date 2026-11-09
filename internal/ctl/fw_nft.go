//go:build linux && !keenetic

package ctl

import (
	"context"

	"github.com/zilbergsp/hyrouter/internal/kernel"
	"github.com/zilbergsp/hyrouter/internal/nft"
	"github.com/zilbergsp/hyrouter/internal/rules"
	"github.com/zilbergsp/hyrouter/internal/store"
	"github.com/zilbergsp/hyrouter/internal/zapret"
)

// The firewall of OpenWrt: HyRouter's nftables table (internal/nft). The
// adapter of KeeneticOS (iptables) is fw_ipt.go.

// fwScript is a compiled table, loaded in one transaction.
type fwScript = string

// fwSets fills the table's DNS sets.
type fwSets = *nft.Sets

// The connection marks of the table.
const (
	fwCTMask   = nft.CTMask
	fwCTDirect = nft.CTDirect
	fwCTBlock  = nft.CTBlock
)

// fwRoute is the policy routing of the relay's packets.
var fwRoute = kernel.PolicyRouting{Mark: nft.MarkTProxy, Mask: nft.MarkTProxy, Table: nft.RouteTable, Priority: nft.RulePriority}

func fwCompile(plan []rules.PlanRule, def rules.Result, s store.Settings, extra string) (fwScript, error) {
	return nft.Compile(plan, def, nft.Options{LAN: s.LAN, TunnelPort: s.TunnelPort, NamePort: s.NamePort, DNSPort: s.DNSPort, Extra: extra})
}

// fwLoad replaces the table; nftables needs no fallbacks to warn of.
func fwLoad(ctx context.Context, script fwScript, lan []string) ([]string, error) {
	return nil, nft.Load(ctx, script)
}

func fwRemove(ctx context.Context) error { return nft.Remove(ctx) }
func fwOpenSets() (fwSets, error) { return nft.OpenSets() }
func fwLoadGuard(ctx context.Context, lan []string) error { return nft.LoadGuard(ctx, lan) }
func fwRemoveGuard(ctx context.Context) error { return nft.RemoveGuard(ctx) }
func fwGuardActive(ctx context.Context) bool { return nft.GuardActive(ctx) }

// fwZapret is the DPI bypass's part of the table.
func fwZapret(c zapret.NFTConfig) (string, error) { return zapret.NFT(c) }

// fwWatch: fw4 leaves HyRouter's own table alone; nothing to watch.
func (c *Controller) fwWatch(ctx context.Context) {}
