//go:build keenetic

package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"
)

// KeeneticOS with Entware in /opt (docs/ARCHITECTURE.md, «Кинетик»):
// iptables and ipset from Entware, the firmware's DNS proxy, the
// firmware's API (RCI) on port 79 of loopback.
const (
	ID          = "keenetic"
	Name        = "KeeneticOS"
	ConfigDir   = "/opt/etc/hyrouter"
	ShareDir    = "/opt/share/hyrouter"
	DefaultLAN  = "br0"
	StopCommand = "/opt/etc/init.d/S99hyrouter stop"
	// ZapretUser: none. The firmware's /etc/passwd, which the static
	// nfqws2 reads, is not Entware's; nfqws2 picks its own uid.
	ZapretUser   = ""
	PasswordHint = "задайте его командой passwd в SSH Entware и войдите снова"
)

// PasswordFiles: Entware keeps root's password in /opt/etc/shadow, or in
// /opt/etc/passwd itself.
var PasswordFiles = []string{"/opt/etc/shadow", "/opt/etc/passwd"}

// DefaultPasswords: what Entware's installers for Keenetic set.
var DefaultPasswords = []string{"keenetic", "12345", "zyxel"}

// certFile is Entware's CA bundle (the packages ca-bundle and
// ca-certificates): Go looks for one in /etc only.
const certFile = "/opt/etc/ssl/certs/ca-certificates.crt"

// Init points the process at Entware: its CA bundle and its programs
// (iptables, ipset) ahead of the firmware's.
func Init() {
	if os.Getenv("SSL_CERT_FILE") == "" {
		if _, err := os.Stat(certFile); err == nil {
			os.Setenv("SSL_CERT_FILE", certFile)
		}
	}
	path := os.Getenv("PATH")
	if !strings.Contains(":"+path+":", ":/opt/sbin:") {
		os.Setenv("PATH", "/opt/sbin:/opt/bin:"+path)
	}
}

// rciURL is the firmware's API: open on loopback without a login.
const rciURL = "http://127.0.0.1:79/rci/"

var rciClient = &http.Client{Transport: &http.Transport{Proxy: nil}}

// rci reads a "show" of the firmware as JSON.
func rci(ctx context.Context, path string, v any) error {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, rciURL+path, nil)
	if err != nil {
		return err
	}
	resp, err := rciClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("rci %s: %s", path, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(v)
}

// Hosts are the devices the firmware knows ("show ip hotspot"): the
// name given in its interface, else the device's own.
func Hosts(ctx context.Context) []Host {
	var r hotspot
	if err := rci(ctx, "show/ip/hotspot", &r); err != nil {
		return nil
	}
	return r.hosts()
}

type hotspot struct {
	Host []struct {
		MAC      string `json:"mac"`
		IP       string `json:"ip"`
		Hostname string `json:"hostname"`
		Name     string `json:"name"`
	} `json:"host"`
}

func (r hotspot) hosts() []Host {
	var out []Host
	for _, h := range r.Host {
		if h.MAC == "" {
			continue
		}
		name := h.Name
		if name == "" {
			name = h.Hostname
		}
		ip := h.IP
		if ip == "0.0.0.0" {
			ip = ""
		}
		out = append(out, Host{MAC: h.MAC, IP: ip, Name: name})
	}
	return out
}

// WAN are the interfaces of the default routes: the firmware's
// connection to the provider (eth3, ppp0, …).
func WAN(ctx context.Context) []string {
	var out []string
	if dev, _ := DefaultRoute(); dev != "" {
		out = append(out, dev)
	}
	if dev := defaultRoute6(); dev != "" && !slices.Contains(out, dev) {
		out = append(out, dev)
	}
	return out
}

// Offload: the firmware's network accelerator cannot be read reliably;
// the DPI page always says what to try.
func Offload(ctx context.Context) bool { return false }

// DNSUpstream is the firmware's DNS proxy where the LAN asks it: on the
// router's LAN address.
func DNSUpstream(lan []string) string {
	if a := lanAddr4(lan); a.IsValid() {
		return net.JoinHostPort(a.String(), "53")
	}
	return "127.0.0.1:53"
}

// System names the firmware and the model ("show version").
func System(ctx context.Context) (name, version, model string) {
	var v struct {
		Title   string `json:"title"`
		Release string `json:"release"`
		Model   string `json:"model"`
		Device  string `json:"device"`
		HwID    string `json:"hw_id"`
	}
	name = "KeeneticOS"
	if rci(ctx, "show/version", &v) != nil {
		return name, "", ""
	}
	version = v.Title
	if version == "" {
		version = v.Release
	}
	model = v.Model
	if model == "" {
		model = v.Device
	}
	if v.HwID != "" && !strings.Contains(model, v.HwID) {
		model = strings.TrimSpace(model + " " + v.HwID)
	}
	return name, version, model
}
