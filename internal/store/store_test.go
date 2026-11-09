package store

import (
	"os"
	"path/filepath"
	"testing"

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
	st2, err := os.Stat(filepath.Join(s.Dir, serversFile))
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
	if err := os.WriteFile(filepath.Join(s.Dir, rulesFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); err == nil {
		t.Fatal("a damaged rules.json loaded")
	}
}
