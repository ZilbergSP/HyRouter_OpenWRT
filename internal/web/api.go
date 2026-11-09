//go:build linux

package web

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/zilbergsp/hyrouter/internal/ctl"
	"github.com/zilbergsp/hyrouter/internal/dnspolicy"
	"github.com/zilbergsp/hyrouter/internal/edition"
	"github.com/zilbergsp/hyrouter/internal/groups"
	"github.com/zilbergsp/hyrouter/internal/hysteria"
	"github.com/zilbergsp/hyrouter/internal/platform"
	"github.com/zilbergsp/hyrouter/internal/rules"
	"github.com/zilbergsp/hyrouter/internal/store"
)

// presetView is a DNS server the interface offers for «через VPN» names.
type presetView struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// stateView is the settings as the interface sees them: the servers'
// passwords never leave the router.
type stateView struct {
	Edition    string             `json:"edition"`
	Lite       bool               `json:"lite"`
	VLESS      bool               `json:"vless"`
	GroupRun   int                `json:"groupRun"`
	Settings   store.Settings     `json:"settings"`
	Servers    []hysteria.Profile `json:"servers"`
	Rules      rules.Config       `json:"rules"`
	Devices    []store.Device     `json:"devices"`
	Groups     groups.File        `json:"groups"`
	Subs       []subView          `json:"subs"`
	Strategies []presetView       `json:"strategies"`
	Undo       *ctl.UndoInfo      `json:"undo"`
	Presets    []presetView       `json:"dnsPresets"`
	// Platform is the router's system ("openwrt", "keenetic"),
	// StopCommand how to stop HyRouter from SSH.
	Platform    string `json:"platform"`
	StopCommand string `json:"stopCommand"`
}

func (s *Server) view(st store.State) stateView {
	v := stateView{
		Edition:  edition.Name,
		Lite:     edition.Lite,
		VLESS:    edition.Current.VLESS,
		GroupRun: edition.Current.GroupRun,
		Settings: st.Settings,
		Rules:    st.Rules,
		Devices:  st.Devices,
		Groups:   st.Groups,
		Subs:     subViews(st),
		Undo:     s.Ctl.Undo(),
		Servers:  make([]hysteria.Profile, 0, len(st.Servers)),
	}
	v.Platform, v.StopCommand = platform.ID, platform.StopCommand
	for _, g := range []groups.Strategy{groups.Failover, groups.Latency, groups.RoundRobin, groups.Random, groups.Sticky} {
		v.Strategies = append(v.Strategies, presetView{string(g), groups.StrategyLabel(g)})
	}
	for _, p := range st.Servers {
		p.ClearSecrets()
		v.Servers = append(v.Servers, p)
	}
	for _, p := range dnspolicy.Presets {
		if p.Tunnel {
			v.Presets = append(v.Presets, presetView{p.ID, p.Name})
		}
	}
	return v
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.view(s.Ctl.State()))
}

// handleRouting turns routing on or off; the choice is kept for the next
// boot.
func (s *Server) handleRouting(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Ctl.SetRouting(r.Context(), req.Enabled); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": s.Ctl.Status()})
}

func (s *Server) saveServers(st store.State) error {
	if err := s.Store.SaveServers(st.Servers); err != nil {
		return err
	}
	if err := s.Store.SaveGroups(st.Groups); err != nil {
		return err
	}
	return s.Store.SaveSettings(st.Settings)
}

// handleAddServer adds a server from its share link (hysteria2://, hy2://,
// vless://). The first server becomes the main one.
func (s *Server) handleAddServer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Link string `json:"link"`
		Name string `json:"name"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	p, warnings, err := hysteria.ParseURI(req.Link)
	if err != nil {
		writeError(w, http.StatusBadRequest, "ссылка не читается: "+err.Error())
		return
	}
	if p.IsVLESS() && !edition.Current.VLESS {
		writeError(w, http.StatusBadRequest, "VLESS не поддерживается в "+edition.Name+": только Hysteria 2")
		return
	}
	p.ID = "srv-" + randomHex(6)
	if n := strings.TrimSpace(req.Name); n != "" {
		p.Name = n
	}
	if p.Name == "" {
		p.Name = p.Host
	}
	p.Normalize()
	if err := p.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if warnings == nil {
		warnings = []string{}
	}
	s.edit(w, r, func(st *store.State) error {
		for _, e := range st.Servers {
			if hysteria.SameConnection(e, p) {
				return fmt.Errorf("такой сервер уже есть: «%s»", e.Name)
			}
		}
		st.Servers = append(st.Servers, p)
		if st.Settings.Main == "" {
			st.Settings.Main = p.ID
		}
		return nil
	}, s.saveServers, map[string]any{"warnings": warnings, "id": p.ID})
}

func (s *Server) handleRenameServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Name string `json:"name"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	name := strings.TrimSpace(req.Name)
	s.edit(w, r, func(st *store.State) error {
		if name == "" {
			return errors.New("пустое имя")
		}
		i := slices.IndexFunc(st.Servers, func(p hysteria.Profile) bool { return p.ID == id })
		if i < 0 {
			return errors.New("нет такого сервера")
		}
		st.Servers[i].Name = name
		return nil
	}, s.saveServers, nil)
}

// handleDeleteServer removes a server, also from its groups. Rules that
// name it are kept: their traffic is refused until another server is
// chosen.
func (s *Server) handleDeleteServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.edit(w, r, func(st *store.State) error {
		i := slices.IndexFunc(st.Servers, func(p hysteria.Profile) bool { return p.ID == id })
		if i < 0 {
			return errors.New("нет такого сервера")
		}
		if st.Servers[i].Source != "" && !st.Servers[i].Missing {
			return errors.New("сервер подписки удаляется вместе с подпиской")
		}
		st.Servers = slices.Delete(st.Servers, i, i+1)
		st.Groups.Prune(func(m string) bool { return m != id })
		if st.Settings.Main == id {
			st.Settings.Main = firstTarget(st)
		}
		return nil
	}, s.saveServers, nil)
}

func (s *Server) handleMain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.edit(w, r, func(st *store.State) error {
		if !isTarget(st, req.ID) {
			return errors.New("нет такого сервера или группы")
		}
		st.Settings.Main = req.ID
		return nil
	}, func(st store.State) error { return s.Store.SaveSettings(st.Settings) }, nil)
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	var cfg rules.Config
	if err := readJSON(r, &cfg); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if cfg.Rules == nil {
		cfg.Rules = []rules.Rule{}
	}
	s.edit(w, r, func(st *store.State) error {
		st.Rules = cfg
		return nil
	}, func(st store.State) error { return s.Store.SaveRules(st.Rules) }, nil)
}

// validID: a device ID is what "dev:<ID>" in a rule can name.
func validID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	var devs []store.Device
	if err := readJSON(r, &devs); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	seen := map[string]bool{}
	for i := range devs {
		d := &devs[i]
		d.Name = strings.TrimSpace(d.Name)
		if !validID(d.ID) || seen[d.ID] {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("неверный или повторный код устройства %q", d.ID))
			return
		}
		seen[d.ID] = true
		for j, m := range d.MACs {
			mac, err := rules.ParseMAC(m)
			if err != nil {
				writeError(w, http.StatusBadRequest, d.Name+": "+err.Error())
				return
			}
			d.MACs[j] = mac.String()
		}
		for _, a := range d.Addrs {
			if _, err := netip.ParsePrefix(a); err != nil {
				if _, err := netip.ParseAddr(a); err != nil {
					writeError(w, http.StatusBadRequest, fmt.Sprintf("%s: неверный адрес %q", d.Name, a))
					return
				}
			}
		}
	}
	if devs == nil {
		devs = []store.Device{}
	}
	s.edit(w, r, func(st *store.State) error {
		st.Devices = devs
		return nil
	}, func(st store.State) error { return s.Store.SaveDevices(st.Devices) }, nil)
}

// neighbour is a device of the LAN the router knows (DHCP).
type neighbour struct {
	MAC  string `json:"mac"`
	IP   string `json:"ip"`
	Name string `json:"name"`
}

// handleNeighbours lists the devices the router gave an address to: the
// devices to add by a click.
func (s *Server) handleNeighbours(w http.ResponseWriter, r *http.Request) {
	out := []neighbour{}
	for _, h := range platform.Hosts(r.Context()) {
		mac, err := rules.ParseMAC(h.MAC)
		if err != nil || h.IP == "" {
			continue
		}
		out = append(out, neighbour{MAC: mac.String(), IP: h.IP, Name: h.Name})
	}
	slices.SortFunc(out, func(a, b neighbour) int { return strings.Compare(a.Name+a.IP, b.Name+b.IP) })
	writeJSON(w, http.StatusOK, out)
}

// handleSettings changes the LAN interfaces and the DNS of «через VPN»
// names.
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LAN        []string `json:"lan"`
		DNSByRules bool     `json:"dnsByRules"`
		DNSTunnel  string   `json:"dnsTunnel"`
		KillSwitch bool     `json:"killSwitch"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.edit(w, r, func(st *store.State) error {
		var lan []string
		for _, n := range req.LAN {
			n = strings.TrimSpace(n)
			if n == "" {
				continue
			}
			if _, err := net.InterfaceByName(n); err != nil {
				return fmt.Errorf("нет интерфейса %q", n)
			}
			lan = append(lan, n)
		}
		if len(lan) == 0 {
			return errors.New("укажите хотя бы один интерфейс LAN")
		}
		if p := dnspolicy.FindPreset(req.DNSTunnel); req.DNSTunnel != "" && (p == nil || !p.Tunnel) {
			return errors.New("неизвестный DNS-сервер")
		}
		st.Settings.LAN = lan
		st.Settings.DNS.ByRules = req.DNSByRules
		st.Settings.DNS.Tunnel = dnspolicy.Upstream{Preset: req.DNSTunnel}
		st.Settings.KillSwitch = req.KillSwitch
		return nil
	}, func(st store.State) error { return s.Store.SaveSettings(st.Settings) }, nil)
}
