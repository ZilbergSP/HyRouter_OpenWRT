//go:build linux

package ctl

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zilbergsp/hyrouter/internal/edition"
	"github.com/zilbergsp/hyrouter/internal/groups"
	"github.com/zilbergsp/hyrouter/internal/hysteria"
	"github.com/zilbergsp/hyrouter/internal/rules"
	"github.com/zilbergsp/hyrouter/internal/store"
)

func server(id string) hysteria.Profile {
	return hysteria.Profile{ID: id, Name: id, Host: id + ".example", Ports: "443", Auth: "x"}
}

// A group's members are its servers, then its subscriptions' servers that
// the subscription still lists; a missing ID is left out.
func TestExpandGroups(t *testing.T) {
	st := store.Defaults()
	a, b, c := server("srv-a"), server("srv-b"), server("srv-c")
	b.Source, c.Source = "sub:s1", "sub:s1"
	c.Missing = true
	st.Servers = []hysteria.Profile{a, b, c}
	st.Groups.Groups = []groups.Group{{ID: "grp-000000000001", Name: "g", Strategy: groups.Failover, Members: []string{"srv-gone", "srv-a"}, Subs: []string{"s1"}}}
	got := expandGroups(st)
	if len(got) != 1 || !slices.Equal(got[0].Members, []string{"srv-a", "srv-b"}) {
		t.Fatalf("members %+v", got)
	}
	if len(st.Groups.Groups[0].Members) != 2 || st.Groups.Groups[0].Members[0] != "srv-gone" {
		t.Fatal("expandGroups changed the state")
	}
}

// The servers that run are the ones the routes use: a used group's
// members (at most GroupRun of them) and the fallbacks; a missing group
// or an empty one is an issue, never a direct route.
func TestCompileGroups(t *testing.T) {
	st := store.Defaults()
	var ids []string
	for i := range edition.Current.GroupRun + 2 {
		p := server("srv-" + string(rune('a'+i)))
		st.Servers = append(st.Servers, p)
		ids = append(ids, p.ID)
	}
	st.Servers = append(st.Servers, server("srv-x"), server("srv-unused"))
	big := groups.Group{ID: "grp-000000000001", Name: "Большая", Strategy: groups.Latency, Members: ids}
	empty := groups.Group{ID: "grp-000000000002", Name: "Пустая", Strategy: groups.Failover, Members: []string{}}
	st.Groups.Groups = []groups.Group{big, empty}
	st.Settings.Main = big.ID
	st.Rules = rules.Config{DefaultAction: rules.Tunnel, Rules: []rules.Rule{
		{Name: "x", Ports: rules.PortList{"25"}, Action: rules.Tunnel, Profile: "srv-x", Fallback: []string{empty.ID}},
		{Name: "gone", Ports: rules.PortList{"26"}, Action: rules.Tunnel, Profile: "grp-00000000000f"},
	}}
	cp, err := compile(st, nil)
	if err != nil {
		t.Fatal(err)
	}
	var run []string
	for _, p := range cp.profiles {
		run = append(run, p.ID)
	}
	want := append([]string{"srv-x"}, ids[:edition.Current.GroupRun]...)
	slices.Sort(run)
	slices.Sort(want)
	if !slices.Equal(run, want) {
		t.Errorf("running %v, want %v", run, want)
	}
	if !slices.Equal(cp.used, []string{big.ID, empty.ID}) {
		t.Errorf("used groups %v", cp.used)
	}
	issues := strings.Join(cp.issues, "\n")
	if !strings.Contains(issues, "«Пустая»") || !strings.Contains(issues, "grp-00000000000f") {
		t.Errorf("issues:\n%s", issues)
	}
	// The members the controller chose run instead of the first ones.
	cp, err = compile(st, func(g groups.Group) []string { return g.Members[len(g.Members)-1:] })
	if err != nil {
		t.Fatal(err)
	}
	if len(cp.profiles) != 2 || !slices.ContainsFunc(cp.profiles, func(p hysteria.Profile) bool { return p.ID == ids[len(ids)-1] }) {
		t.Errorf("chosen members: %+v", cp.profiles)
	}
}

// A small group runs every member; a large one its chosen members, the
// ones whose measurement failed last.
func TestChosenMembers(t *testing.T) {
	c := &Controller{}
	limit := edition.Current.GroupRun
	var all []string
	for i := range limit + 2 {
		all = append(all, "srv-"+string(rune('a'+i)))
	}
	if got := c.runMembers(groups.Group{ID: "g", Members: all[:limit]}); len(got) != limit {
		t.Errorf("small group runs %v", got)
	}
	c.scan.scanned = map[string]scanResult{all[0]: {at: time.Now(), ok: false}}
	got := c.runMembers(groups.Group{ID: "g", Members: all})
	if len(got) != limit || slices.Contains(got, all[0]) {
		t.Errorf("large group runs %v", got)
	}
	c.scan.run = map[string][]string{"g": {all[limit+1], "srv-gone"}}
	if got := c.runMembers(groups.Group{ID: "g", Members: all}); got[0] != all[limit+1] || slices.Contains(got, "srv-gone") {
		t.Errorf("chosen members kept: %v", got)
	}
}
