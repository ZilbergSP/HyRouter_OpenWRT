package ipt

import (
	"fmt"
	"slices"
	"strings"
)

// saved is a table as iptables-save prints it: the chains, and the rules
// of each built-in chain in order.
type saved struct {
	chains []string
	rules  map[string][]string // built-in chain → its rules without "-A CHAIN "
}

// parseSave reads one table of iptables-save's output.
func parseSave(out string) saved {
	s := saved{rules: map[string][]string{}}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, ":"):
			if f := strings.Fields(line[1:]); len(f) > 0 {
				s.chains = append(s.chains, f[0])
			}
		case strings.HasPrefix(line, "-A "):
			f := strings.SplitN(line[3:], " ", 2)
			rest := ""
			if len(f) == 2 {
				rest = f[1]
			}
			s.rules[f[0]] = append(s.rules[f[0]], rest)
		}
	}
	return s
}

// jumps counts the jumps "-j to" in a built-in chain.
func (s saved) jumps(from, to string) int {
	n := 0
	for _, r := range s.rules[from] {
		if r == "-j "+to {
			n++
		}
	}
	return n
}

// hooked reports whether the jump to "to" is in "from" and only jumps to
// HyRouter's chains come before it: nothing of the firmware's decides a
// packet first.
func (s saved) hooked(from, to string) bool {
	for _, r := range s.rules[from] {
		if r == "-j "+to {
			return true
		}
		if !strings.HasPrefix(r, "-j "+OwnerRoute) && !strings.HasPrefix(r, "-j "+OwnerGuard) {
			return false
		}
	}
	return false
}

// healthy: every chain of t is there and every hook in place.
func (s saved) healthy(t Table) bool {
	for _, c := range t.Chains {
		if !slices.Contains(s.chains, c) {
			return false
		}
	}
	for _, h := range t.Hooks {
		if !s.hooked(h.From, h.To) || s.jumps(h.From, h.To) != 1 {
			return false
		}
	}
	return true
}

// restoreInput is what iptables-restore --noflush takes to make the
// owner's part of a table t, in one commit: its chains (emptied) with
// their rules, its hooks first in their built-in chains, and the owner's
// chains and hooks t no longer has removed. cur is the table now.
func restoreInput(owner string, t Table, cur saved) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	w("*%s", t.Name)
	for _, c := range t.Chains {
		w(":%s - [0:0]", c)
	}
	for _, r := range t.Rules {
		w("%s", r)
	}
	// Hooks no longer wanted, then the chains no one jumps to.
	var stale []string
	for _, c := range cur.chains {
		if strings.HasPrefix(c, owner) && !slices.Contains(t.Chains, c) {
			stale = append(stale, c)
		}
	}
	// Jumps from the owner's own chains go with their flush.
	builtins := make([]string, 0, len(cur.rules))
	for from := range cur.rules {
		if !strings.HasPrefix(from, owner) {
			builtins = append(builtins, from)
		}
	}
	slices.Sort(builtins)
	for _, from := range builtins {
		for _, c := range stale {
			for range cur.jumps(from, c) {
				w("-D %s -j %s", from, c)
			}
		}
	}
	// Hooks: the old jumps go and one goes first, in one commit. The last
	// hook of a chain is inserted first, so they keep their order.
	for i := len(t.Hooks) - 1; i >= 0; i-- {
		h := t.Hooks[i]
		for range cur.jumps(h.From, h.To) {
			w("-D %s -j %s", h.From, h.To)
		}
		w("-I %s 1 -j %s", h.From, h.To)
	}
	for _, c := range stale {
		w("-F %s", c)
	}
	for _, c := range stale {
		w("-X %s", c)
	}
	w("COMMIT")
	return b.String()
}

// removeInput removes all of the owner's chains and hooks from a table.
func removeInput(owner, table string, cur saved) string {
	return restoreInput(owner, Table{Name: table}, cur)
}

// hookFile is the part of a table the netfilter.d hook loads again after
// the firmware rebuilt it: the chains with their rules (iptables-restore
// --noflush), the hooks listed apart ("FROM TO" lines).
func hookFile(t Table) (rules, hooks string) {
	var b strings.Builder
	fmt.Fprintf(&b, "*%s\n", t.Name)
	for _, c := range t.Chains {
		fmt.Fprintf(&b, ":%s - [0:0]\n", c)
	}
	for _, r := range t.Rules {
		b.WriteString(r + "\n")
	}
	b.WriteString("COMMIT\n")
	var h strings.Builder
	for _, k := range t.Hooks {
		fmt.Fprintf(&h, "%s %s\n", k.From, k.To)
	}
	return b.String(), h.String()
}

// ipsetInput is what "ipset -exist restore" takes to make the sets: a
// set of fixed elements is filled under a temporary name and swapped in
// whole; a set of DNS addresses is made if missing and emptied (the DNS
// fills it again).
func ipsetInput(sets []Set) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	for _, s := range sets {
		typ := "hash:ip"
		if s.Net {
			typ = "hash:net"
		}
		fam := "inet"
		if s.Family == 6 {
			fam = "inet6"
		}
		opts := "family " + fam
		if s.Timeout {
			opts += " timeout 3600"
		} else {
			// geoip lists can be long; a fixed bound keeps "create -exist"
			// and swap agreeing between loads.
			opts += " maxelem 262144"
		}
		name := s.FullName()
		if s.Timeout {
			w("create %s %s %s", name, typ, opts)
			w("flush %s", name)
			continue
		}
		tmp := tmpName(name)
		w("create %s %s %s", tmp, typ, opts)
		w("flush %s", tmp)
		for _, e := range s.Elems {
			w("add %s %s", tmp, e)
		}
		w("create %s %s %s", name, typ, opts)
		w("swap %s %s", tmp, name)
		w("destroy %s", tmp)
	}
	return b.String()
}

// tmpName is the temporary twin of a set (at most 31 bytes).
func tmpName(name string) string {
	t := name + "_t"
	if len(t) > 31 {
		t = name[:29] + "_t"
	}
	return t
}

// Files is the part as files for a check by hand or in CI:
// <name>.ipset for "ipset restore", <name>-<family>-<table>.rules for
// "iptables-restore --test".
func (p *Part) Files(name string) map[string]string {
	out := map[string]string{name + ".ipset": ipsetInput(p.Sets)}
	for _, t := range p.Tables {
		rules, _ := hookFile(t)
		out[fmt.Sprintf("%s-%d-%s.rules", name, t.Family, t.Name)] = rules
	}
	return out
}
