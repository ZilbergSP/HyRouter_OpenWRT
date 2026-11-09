//go:build linux

package ipt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// Dir holds the files the netfilter.d hook loads again
// (build/keenetic/50-hyrouter.sh): <owner>-<family>-<table>.rules and
// .hooks, for the routing and for the boot guard.
var Dir = "/tmp/hyrouter/fw"

// order of the tables a part is loaded in: the DNS redirect, then the
// routing, then the filter (which may take what failed of the others).
var order = []string{"nat", "mangle", "filter"}

var (
	mu sync.Mutex
	// applied are the tables in force by owner, for Heal.
	applied = map[string][]Table{}
)

// HaveIPv6 reports whether the kernel has IPv6.
func HaveIPv6() bool {
	_, err := os.Stat("/proc/net/if_inet6")
	return err == nil
}

func tool(fam int, suffix string) string {
	if fam == 6 {
		return "ip6tables" + suffix
	}
	return "iptables" + suffix
}

// run runs a program with stdin; the error carries its output and what
// to do about it.
func run(ctx context.Context, stdin, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return "", fmt.Errorf("нет программы %s: установите из Entware (opkg install iptables ipset)", name)
		}
		return string(out), fmt.Errorf("%s: %v: %s%s", name, err, bytes.TrimSpace(out), hint(out))
	}
	return string(out), nil
}

// hint says what to do when the kernel lacks a part of netfilter.
func hint(out []byte) string {
	for _, s := range []string{"No chain/target/match", "Couldn't load", "can't initialize", "Unable to open table", "Kernel error received", "Set cannot be created", "Unknown set type"} {
		if bytes.Contains(out, []byte(s)) {
			return " (включите в KeeneticOS компонент «Модули ядра подсистемы Netfilter» и перезагрузите роутер)"
		}
	}
	return ""
}

// transient: another program changed the table between our read and our
// commit, or a jump we meant to delete went away.
func transient(out string) bool {
	return strings.Contains(out, "Resource temporarily unavailable") || strings.Contains(out, "Bad rule") ||
		strings.Contains(out, "does a matching rule exist") || strings.Contains(out, "No such file")
}

func save(ctx context.Context, fam int, table string) (saved, error) {
	out, err := run(ctx, "", tool(fam, "-save"), "-t", table)
	if err != nil {
		return saved{}, err
	}
	return parseSave(out), nil
}

// applyTable makes the owner's part of a table as t says, in one commit,
// again if the table changed under it.
func applyTable(ctx context.Context, owner string, t Table) error {
	var err error
	for range 4 {
		var cur saved
		if cur, err = save(ctx, t.Family, t.Name); err != nil {
			return err
		}
		var out string
		out, err = run(ctx, restoreInput(owner, t, cur), tool(t.Family, "-restore"), "--noflush")
		if err == nil || !transient(out) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(150 * time.Millisecond):
		}
	}
	return err
}

// Load puts HyRouter's rules in force: the sets, then each table in one
// commit, the IPv6 ones only when the kernel has IPv6. A router without
// IPv6 NAT gets its LAN's IPv6 DNS refused, one without IPv6 routing its
// LAN's IPv6 connections: warnings say so. lan is for those rules.
func Load(ctx context.Context, p *Part, lan []string) (warnings []string, err error) {
	mu.Lock()
	defer mu.Unlock()
	loadModules()
	if err := p.Check(OwnerRoute); err != nil {
		return nil, err
	}
	if err := applySets(ctx, p.Sets); err != nil {
		return nil, err
	}
	var done []Table
	for _, fam := range p.Families() {
		var extra []string
		for _, name := range order {
			i := slices.IndexFunc(p.Tables, func(t Table) bool { return t.Family == fam && t.Name == name })
			if i < 0 {
				continue
			}
			t := p.Tables[i]
			if name == "filter" && len(extra) > 0 {
				t.Rules = append(slices.Clone(t.Rules), extra...)
			}
			err := applyTable(ctx, OwnerRoute, t)
			switch {
			case err == nil:
				done = append(done, t)
			case fam == 6 && name == "nat":
				warnings = append(warnings, "IPv6 DNS устройств к роутеру отклоняется: в ядре нет NAT IPv6 ("+err.Error()+")")
				extra = append(extra, DNS6Fallback(lan)...)
			case fam == 6 && name == "mangle":
				warnings = append(warnings, "соединения IPv6 устройств отклоняются: правила IPv6 не загрузились ("+err.Error()+")")
				extra = append(extra, Closed6(lan)...)
			default:
				return warnings, err
			}
		}
	}
	applied[OwnerRoute] = done
	if err := writeFiles(OwnerRoute, done); err != nil {
		warnings = append(warnings, "файлы для перезагрузки правил прошивкой не записаны: "+err.Error())
	}
	destroyUnused(ctx, p.Sets)
	return warnings, nil
}

// Remove takes HyRouter's chains, hooks and sets away: the LAN goes on as
// without HyRouter. What is not there is no error.
func Remove(ctx context.Context) error {
	mu.Lock()
	defer mu.Unlock()
	err := removeOwner(ctx, OwnerRoute)
	destroyUnused(ctx, nil)
	return err
}

func removeOwner(ctx context.Context, owner string) error {
	delete(applied, owner)
	removeFiles(owner, nil)
	fams := []int{4}
	if HaveIPv6() {
		fams = append(fams, 6)
	}
	var errs []error
	for _, fam := range fams {
		for _, name := range []string{"mangle", "nat", "filter"} {
			for range 4 {
				cur, err := save(ctx, fam, name)
				if err != nil {
					break // no such table: nothing of ours in it
				}
				if !cur.owns(owner) {
					break
				}
				out, err := run(ctx, removeInput(owner, name, cur), tool(fam, "-restore"), "--noflush")
				if err == nil {
					break
				}
				if !transient(out) {
					errs = append(errs, err)
					break
				}
			}
		}
	}
	return errors.Join(errs...)
}

// owns: the table has a chain of the owner.
func (s saved) owns(owner string) bool {
	return slices.ContainsFunc(s.chains, func(c string) bool { return strings.HasPrefix(c, owner) })
}

// LoadGuard closes the LAN's way beyond the router (OwnerGuard): routing
// should run and does not yet.
func LoadGuard(ctx context.Context, lan []string) error {
	mu.Lock()
	defer mu.Unlock()
	loadModules()
	p, err := Guard(lan, HaveIPv6())
	if err != nil {
		return err
	}
	if err := p.Check(OwnerGuard); err != nil {
		return err
	}
	var done []Table
	for _, t := range p.Tables {
		if err := applyTable(ctx, OwnerGuard, t); err != nil {
			if t.Family == 6 {
				continue // the kernel's IPv6 filter is missing: nothing to close
			}
			return err
		}
		done = append(done, t)
	}
	applied[OwnerGuard] = done
	return writeFiles(OwnerGuard, done)
}

// RemoveGuard opens the LAN again; a guard that is not there is no error.
func RemoveGuard(ctx context.Context) error {
	mu.Lock()
	defer mu.Unlock()
	return removeOwner(ctx, OwnerGuard)
}

// GuardActive reports whether the guard's chain is loaded.
func GuardActive(ctx context.Context) bool {
	cur, err := save(ctx, 4, "filter")
	return err == nil && cur.owns(OwnerGuard)
}

// Heal puts back the tables the firmware rebuilt without HyRouter's
// chains or with its own rules ahead of them; it names what it fixed.
func Heal(ctx context.Context) ([]string, error) {
	mu.Lock()
	defer mu.Unlock()
	var fixed []string
	var errs []error
	for _, owner := range []string{OwnerGuard, OwnerRoute} {
		for _, t := range applied[owner] {
			cur, err := save(ctx, t.Family, t.Name)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if cur.healthy(t) {
				continue
			}
			if err := applyTable(ctx, owner, t); err != nil {
				errs = append(errs, err)
				continue
			}
			fixed = append(fixed, fmt.Sprintf("%s%d/%s", strings.TrimSuffix(strings.ToLower(owner), "_"), t.Family, t.Name))
		}
	}
	return fixed, errors.Join(errs...)
}

// fileBase is the files' name of an owner's table.
func fileBase(owner string, fam int, table string) string {
	kind := "route"
	if owner == OwnerGuard {
		kind = "guard"
	}
	return filepath.Join(Dir, fmt.Sprintf("%s-%d-%s", kind, fam, table))
}

// writeFiles writes the hook's files of the tables and removes the
// owner's others.
func writeFiles(owner string, tables []Table) error {
	if err := os.MkdirAll(Dir, 0o700); err != nil {
		return err
	}
	keep := map[string]bool{}
	var errs []error
	for _, t := range tables {
		base := fileBase(owner, t.Family, t.Name)
		keep[base] = true
		rules, hooks := hookFile(t)
		for _, f := range []struct{ path, data string }{{base + ".rules", rules}, {base + ".hooks", hooks}} {
			tmp := f.path + ".tmp"
			if err := os.WriteFile(tmp, []byte(f.data), 0o600); err != nil {
				errs = append(errs, err)
				continue
			}
			if err := os.Rename(tmp, f.path); err != nil {
				errs = append(errs, err)
			}
		}
	}
	removeFiles(owner, keep)
	return errors.Join(errs...)
}

// removeFiles deletes the owner's files but those of keep.
func removeFiles(owner string, keep map[string]bool) {
	for _, fam := range []int{4, 6} {
		for _, name := range []string{"mangle", "nat", "filter"} {
			base := fileBase(owner, fam, name)
			if keep[base] {
				continue
			}
			os.Remove(base + ".hooks")
			os.Remove(base + ".rules")
		}
	}
}

// applySets makes the sets (ipset restore).
func applySets(ctx context.Context, sets []Set) error {
	if len(sets) == 0 {
		return nil
	}
	_, err := run(ctx, ipsetInput(sets), "ipset", "-exist", "restore")
	return err
}

// destroyUnused removes HyRouter's sets that keep does not have; a set
// some rule still uses stays.
func destroyUnused(ctx context.Context, keep []Set) {
	out, err := run(ctx, "", "ipset", "list", "-n")
	if err != nil {
		return
	}
	for _, name := range strings.Fields(out) {
		if !strings.HasPrefix(name, SetPrefix) {
			continue
		}
		if slices.ContainsFunc(keep, func(s Set) bool { return s.FullName() == name }) {
			continue
		}
		run(ctx, "", "ipset", "destroy", name)
	}
}
