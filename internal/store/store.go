// Package store keeps HyRouter's settings in /etc/hyrouter: one JSON file
// per part (settings, servers, rules, devices), written atomically with
// mode 0600 (servers hold passwords). A missing file is the defaults; a
// damaged one is an error, never a silent reset.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/zilbergsp/hyrouter/internal/dnspolicy"
	"github.com/zilbergsp/hyrouter/internal/hysteria"
	"github.com/zilbergsp/hyrouter/internal/rules"
)

// Default ports (docs/ARCHITECTURE.md): the relay's TPROXY ports, the
// DNS behind the LAN's port 53 and the web interface.
const (
	DefaultTunnelPort = 7701
	DefaultNamePort   = 7702
	DefaultDNSPort    = 7753
	DefaultWebPort    = 8088
)

// Settings are the router's side (settings.json).
type Settings struct {
	// Enabled: HyRouter routes the LAN, also after a reboot.
	Enabled bool `json:"enabled"`
	// LAN are the interfaces whose traffic HyRouter decides.
	LAN []string `json:"lan"`
	// Main is the server ID of «через VPN» rules without a server of
	// their own.
	Main string `json:"main"`
	// DNS is the DNS policy (dnspolicy): names of «через VPN» sites are
	// resolved through their server.
	DNS dnspolicy.Config `json:"dns"`
	// Ports of the relay, the DNS and the web interface.
	TunnelPort uint16 `json:"tunnelPort"`
	NamePort   uint16 `json:"namePort"`
	DNSPort    uint16 `json:"dnsPort"`
	WebPort    uint16 `json:"webPort"`
}

// Device is a LAN device the rules name as "dev:<ID>" (devices.json).
type Device struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	MACs  []string `json:"macs,omitempty"`
	Addrs []string `json:"addrs,omitempty"`
}

// State is everything HyRouter keeps.
type State struct {
	Settings Settings
	Servers  []hysteria.Profile
	Rules    rules.Config
	Devices  []Device
}

// Defaults are the settings of a new installation: not routing yet, the
// LAN bridge, names of «через VPN» sites through the server.
func Defaults() State {
	return State{
		Settings: Settings{
			LAN:        []string{"br-lan"},
			DNS:        dnspolicy.Config{ByRules: true},
			TunnelPort: DefaultTunnelPort,
			NamePort:   DefaultNamePort,
			DNSPort:    DefaultDNSPort,
			WebPort:    DefaultWebPort,
		},
		Rules: rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{}},
	}
}

// Store reads and writes the files in Dir.
type Store struct {
	Dir string
	mu  sync.Mutex
}

const (
	settingsFile = "settings.json"
	serversFile  = "servers.json"
	rulesFile    = "rules.json"
	devicesFile  = "devices.json"
)

// Load reads every file; a missing one keeps its defaults.
func (s *Store) Load() (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Defaults()
	for _, f := range []struct {
		name string
		v    any
	}{{settingsFile, &st.Settings}, {serversFile, &st.Servers}, {rulesFile, &st.Rules}, {devicesFile, &st.Devices}} {
		b, err := os.ReadFile(filepath.Join(s.Dir, f.name))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return st, err
		}
		if err := json.Unmarshal(b, f.v); err != nil {
			return st, fmt.Errorf("%s повреждён: %v", f.name, err)
		}
	}
	fillPorts(&st.Settings)
	if st.Servers == nil {
		st.Servers = []hysteria.Profile{}
	}
	if st.Rules.Rules == nil {
		st.Rules.Rules = []rules.Rule{}
	}
	if st.Devices == nil {
		st.Devices = []Device{}
	}
	return st, nil
}

// fillPorts gives unset ports their defaults.
func fillPorts(s *Settings) {
	for _, p := range []struct {
		v   *uint16
		def uint16
	}{{&s.TunnelPort, DefaultTunnelPort}, {&s.NamePort, DefaultNamePort}, {&s.DNSPort, DefaultDNSPort}, {&s.WebPort, DefaultWebPort}} {
		if *p.v == 0 {
			*p.v = p.def
		}
	}
	if len(s.LAN) == 0 {
		s.LAN = []string{"br-lan"}
	}
}

// SaveSettings writes settings.json.
func (s *Store) SaveSettings(v Settings) error { return s.save(settingsFile, v) }

// SaveServers writes servers.json.
func (s *Store) SaveServers(v []hysteria.Profile) error { return s.save(serversFile, v) }

// SaveRules writes rules.json.
func (s *Store) SaveRules(v rules.Config) error { return s.save(rulesFile, v) }

// SaveDevices writes devices.json.
func (s *Store) SaveDevices(v []Device) error { return s.save(devicesFile, v) }

// save writes a file atomically: a temporary file, synced, renamed.
func (s *Store) save(name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(s.Dir, "."+name+".*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(s.Dir, name))
}
