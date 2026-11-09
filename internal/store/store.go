// Package store keeps HyRouter's settings in /etc/hyrouter: one JSON file
// per part (settings, servers, rules, devices, groups, subscriptions,
// DPI bypass), written atomically with mode 0600 (servers hold
// passwords). A missing file is the defaults; a damaged one is an error,
// never a silent reset.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/zilbergsp/hyrouter/internal/dnspolicy"
	"github.com/zilbergsp/hyrouter/internal/groups"
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
	// Main is the server or group ID of «через VPN» rules without a
	// server of their own.
	Main string `json:"main"`
	// DNS is the DNS policy (dnspolicy): names of «через VPN» sites are
	// resolved through their server.
	DNS dnspolicy.Config `json:"dns"`
	// Ports of the relay, the DNS and the web interface.
	TunnelPort uint16 `json:"tunnelPort"`
	NamePort   uint16 `json:"namePort"`
	DNSPort    uint16 `json:"dnsPort"`
	WebPort    uint16 `json:"webPort"`
	// KillSwitch: while the router boots, the LAN reaches nothing beyond
	// the router until HyRouter routes it (the hyrouter-guard service);
	// only with Enabled.
	KillSwitch bool `json:"killSwitch,omitempty"`
	// DeviceID is the router's ID for the panels of subscriptions that
	// limit devices (X-Hwid); made once.
	DeviceID string `json:"deviceId,omitempty"`
	// Geo is the rule database (geosite and geoip).
	Geo GeoSettings `json:"geo"`
	// Stats: statistics of traffic by device, server and group are kept
	// (never by site).
	Stats bool `json:"stats"`
}

// GeoSettings are the rule database's source and updates.
type GeoSettings struct {
	// Source is a geodata source ID ("" = the default one).
	Source string `json:"source,omitempty"`
	// Auto: the database is updated once a day.
	Auto bool `json:"auto"`
}

// Device is a LAN device the rules name as "dev:<ID>" (devices.json).
type Device struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	MACs  []string `json:"macs,omitempty"`
	Addrs []string `json:"addrs,omitempty"`
}

// Sub is a subscription (subs.json): a panel's link that lists servers.
// Its servers are in servers.json with Source "sub:<ID>".
type Sub struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
	// IntervalH is the hours between automatic updates; 0 = by hand.
	IntervalH int `json:"intervalH"`

	LastUpdate  time.Time `json:"lastUpdate,omitzero"`
	LastAttempt time.Time `json:"lastAttempt,omitzero"`
	LastError   string    `json:"lastError,omitempty"`
	// Count is the servers the last update brought; Ignored the links of
	// other protocols by scheme; Warnings what was not carried over.
	Count    int            `json:"count"`
	Ignored  map[string]int `json:"ignored,omitempty"`
	Warnings []string       `json:"warnings,omitempty"`
	// ViaVPN: the last update came through the main server (the panel did
	// not answer directly).
	ViaVPN bool `json:"viaVPN,omitempty"`
	// UserInfo is the panel's Subscription-Userinfo (traffic, expiry),
	// InfoAt when it came, Support the panel's support-url.
	UserInfo string    `json:"userInfo,omitempty"`
	InfoAt   time.Time `json:"infoAt,omitzero"`
	Support  string    `json:"supportUrl,omitempty"`
}

// State is everything HyRouter keeps.
type State struct {
	Settings Settings
	Servers  []hysteria.Profile
	Rules    rules.Config
	Devices  []Device
	Groups   groups.File
	Subs     []Sub
	// Zapret is the DPI bypass (zapret.json) as the controller's own
	// JSON: the store does not know its shape. Empty = never set up.
	Zapret json.RawMessage
}

// Clone copies the parts an edit changes in place.
func (st State) Clone() State {
	st.Servers = slices.Clone(st.Servers)
	st.Devices = slices.Clone(st.Devices)
	st.Settings.LAN = slices.Clone(st.Settings.LAN)
	st.Rules.Rules = slices.Clone(st.Rules.Rules)
	st.Rules.DefaultFallback = slices.Clone(st.Rules.DefaultFallback)
	st.Groups = *st.Groups.Clone()
	st.Subs = slices.Clone(st.Subs)
	st.Zapret = slices.Clone(st.Zapret)
	return st
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
			Geo:        GeoSettings{Auto: true},
			Stats:      true,
		},
		Rules:  rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{}},
		Groups: groups.File{Version: groups.FormatVersion, Groups: []groups.Group{}},
		Subs:   []Sub{},
	}
}

// Store reads and writes the files in Dir.
type Store struct {
	Dir string
	mu  sync.Mutex
}

// The files in Dir.
const (
	SettingsFile = "settings.json"
	ServersFile  = "servers.json"
	RulesFile    = "rules.json"
	DevicesFile  = "devices.json"
	GroupsFile   = "groups.json"
	SubsFile     = "subs.json"
	ZapretFile   = "zapret.json"
)

// Files are every file of the settings, in the order Load reads them.
var Files = []string{SettingsFile, ServersFile, RulesFile, DevicesFile, GroupsFile, SubsFile, ZapretFile}

// Load reads every file; a missing one keeps its defaults.
func (s *Store) Load() (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Defaults()
	var zapret json.RawMessage
	for _, f := range []struct {
		name string
		v    any
	}{{SettingsFile, &st.Settings}, {ServersFile, &st.Servers}, {RulesFile, &st.Rules}, {DevicesFile, &st.Devices}, {GroupsFile, &st.Groups}, {SubsFile, &st.Subs}, {ZapretFile, &zapret}} {
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
	st.Zapret = zapret
	Fill(&st)
	if err := st.Groups.Validate(); err != nil {
		return st, fmt.Errorf("%s: %v", GroupsFile, err)
	}
	return st, nil
}

// Fill gives unset fields their defaults.
func Fill(st *State) {
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
	if st.Groups.Groups == nil {
		st.Groups.Groups = []groups.Group{}
	}
	if st.Groups.Version == 0 {
		st.Groups.Version = groups.FormatVersion
	}
	if st.Subs == nil {
		st.Subs = []Sub{}
	}
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
func (s *Store) SaveSettings(v Settings) error { return s.save(SettingsFile, v) }

// SaveServers writes servers.json.
func (s *Store) SaveServers(v []hysteria.Profile) error { return s.save(ServersFile, v) }

// SaveRules writes rules.json.
func (s *Store) SaveRules(v rules.Config) error { return s.save(RulesFile, v) }

// SaveDevices writes devices.json.
func (s *Store) SaveDevices(v []Device) error { return s.save(DevicesFile, v) }

// SaveGroups writes groups.json.
func (s *Store) SaveGroups(v groups.File) error { return s.save(GroupsFile, v) }

// SaveSubs writes subs.json.
func (s *Store) SaveSubs(v []Sub) error { return s.save(SubsFile, v) }

// SaveZapret writes zapret.json.
func (s *Store) SaveZapret(v json.RawMessage) error { return s.save(ZapretFile, v) }

// SaveAll writes every file of a state (a restored backup).
func (s *Store) SaveAll(st State) error {
	for _, f := range []func() error{
		func() error { return s.SaveServers(st.Servers) },
		func() error { return s.SaveRules(st.Rules) },
		func() error { return s.SaveDevices(st.Devices) },
		func() error { return s.SaveGroups(st.Groups) },
		func() error { return s.SaveSubs(st.Subs) },
		func() error {
			if len(st.Zapret) == 0 {
				return s.remove(ZapretFile)
			}
			return s.SaveZapret(st.Zapret)
		},
		// Settings last: they say whether to route at all.
		func() error { return s.SaveSettings(st.Settings) },
	} {
		if err := f(); err != nil {
			return err
		}
	}
	return nil
}

// ReadFiles returns the files as they are on disk (a missing one is
// absent): what «Вернуть как было» puts back.
func (s *Store) ReadFiles() (map[string][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string][]byte{}
	for _, name := range Files {
		b, err := os.ReadFile(filepath.Join(s.Dir, name))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out[name] = b
	}
	return out, nil
}

// WriteFiles puts files back as ReadFiles returned them: a file absent
// from files is removed. It goes on past an error and reports them all.
func (s *Store) WriteFiles(files map[string][]byte) error {
	var errs []error
	for _, name := range Files {
		var err error
		if b, ok := files[name]; ok {
			err = s.writeRaw(name, b)
		} else {
			err = s.remove(name)
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (s *Store) remove(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(filepath.Join(s.Dir, name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// save writes a file atomically as indented JSON.
func (s *Store) save(name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return s.writeRaw(name, append(b, '\n'))
}

func (s *Store) writeRaw(name string, b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return WriteFile(filepath.Join(s.Dir, name), b)
}

// WriteFile writes path atomically with mode 0600: a temporary file,
// synced, renamed.
func WriteFile(path string, b []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
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
	return os.Rename(f.Name(), path)
}
