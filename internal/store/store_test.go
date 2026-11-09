package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/zilbergsp/hyrouter/internal/groups"
	"github.com/zilbergsp/hyrouter/internal/hysteria"
	"github.com/zilbergsp/hyrouter/internal/rules"
)

func TestDefaultsAndRoundTrip(t *testing.T) {
	s := &Store{Dir: filepath.Join(t.TempDir(), "hyrouter")}
	st, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if st.Settings.Enabled || st.Settings.LAN[0] != "br-lan" || !st.Settings.DNS.ByRules || st.Settings.WebPort != DefaultWebPort || st.Rules.DefaultAction != rules.Direct {
		t.Fatalf("defaults: %+v", st)
	}
	st.Settings.Enabled, st.Settings.Main = true, "srv-1"
	st.Settings.WebPort = 0 // a port left out gets its default back
	if err := s.SaveSettings(st.Settings); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveServers([]hysteria.Profile{{ID: "srv-1", Name: "Нидерланды", Host: "vpn.example.com", Ports: "443", Auth: "secret"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveRules(rules.Config{DefaultAction: rules.Tunnel, Rules: []rules.Rule{{Name: "tv", Devices: []string{"dev:tv"}, Action: rules.Tunnel}}}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveDevices([]Device{{ID: "tv", Name: "Телевизор", MACs: []string{"aa:bb:cc:dd:ee:01"}}}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !got.Settings.Enabled || got.Settings.Main != "srv-1" || got.Settings.WebPort != DefaultWebPort {
		t.Errorf("settings: %+v", got.Settings)
	}
	if len(got.Servers) != 1 || got.Servers[0].Auth != "secret" || got.Rules.DefaultAction != rules.Tunnel || len(got.Devices) != 1 {
		t.Errorf("state: %+v", got)
	}
	st2, err := os.Stat(filepath.Join(s.Dir, ServersFile))
	if err != nil {
		t.Fatal(err)
	}
	if st2.Mode().Perm() != 0o600 {
		t.Errorf("servers.json mode %v", st2.Mode().Perm())
	}
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Errorf("files left: %v", entries)
	}
}

// A damaged file is an error, not the defaults: routing must not start
// with rules the user never wrote.
func TestDamaged(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	if err := os.WriteFile(filepath.Join(s.Dir, RulesFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); err == nil {
		t.Fatal("a damaged rules.json loaded")
	}
}

func TestGroupsSubsAndFiles(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	st, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if st.Groups.Version != groups.FormatVersion || st.Groups.Groups == nil || st.Subs == nil || !st.Settings.Stats || !st.Settings.Geo.Auto {
		t.Fatalf("defaults: %+v", st)
	}
	before, err := s.ReadFiles()
	if err != nil || len(before) != 0 {
		t.Fatalf("files of a new installation: %v %v", before, err)
	}
	g := groups.Group{ID: "grp-0123456789ab", Name: "Европа", Strategy: groups.Failover, Members: []string{"srv-1"}}
	st.Groups.Groups = append(st.Groups.Groups, g)
	st.Subs = append(st.Subs, Sub{ID: "s1", Name: "Панель", URL: "https://panel.example/sub", Enabled: true, IntervalH: 12})
	st.Zapret = json.RawMessage(`{"enabled":true}`)
	if err := s.SaveAll(st); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Groups.Groups) != 1 || got.Groups.Groups[0].Name != "Европа" || len(got.Subs) != 1 || got.Subs[0].IntervalH != 12 {
		t.Fatalf("round trip: %+v", got)
	}
	var z map[string]bool
	if err := json.Unmarshal(got.Zapret, &z); err != nil || !z["enabled"] {
		t.Fatalf("zapret: %s %v", got.Zapret, err)
	}
	// A clone is edited without touching the original.
	c := got.Clone()
	c.Groups.Groups[0].Members[0] = "srv-2"
	c.Subs[0].Name = "другая"
	if got.Groups.Groups[0].Members[0] != "srv-1" || got.Subs[0].Name != "Панель" {
		t.Fatal("Clone shares memory with the original")
	}
	// «Вернуть как было» puts back the files of before, removing the
	// ones that were not there.
	if err := s.WriteFiles(before); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(s.Dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("after WriteFiles: %v %v", entries, err)
	}
}

// A groups.json that breaks the load rules is an error.
func TestBadGroups(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	if err := os.WriteFile(filepath.Join(s.Dir, GroupsFile), []byte(`{"version":1,"groups":[{"id":"bad","name":"x","strategy":"failover","members":[]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); err == nil {
		t.Fatal("a bad group ID loaded")
	}
}
