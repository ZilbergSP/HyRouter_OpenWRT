//go:build !keenetic

package platform

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"
)

// OpenWrt: procd, fw4 (nftables), dnsmasq, ubus.
const (
	// ID and Name name the platform for the web interface.
	ID   = "openwrt"
	Name = "OpenWrt"
	// ConfigDir holds the settings, ShareDir what the package brought
	// (the cores folder bin/, the DPI bypass in zapret/).
	ConfigDir = "/etc/hyrouter"
	ShareDir  = "/usr/share/hyrouter"
	// DefaultLAN is the LAN bridge of a new installation.
	DefaultLAN = "br-lan"
	// StopCommand stops HyRouter from SSH.
	StopCommand = "/etc/init.d/hyrouter stop"
	// ZapretUser is the account nfqws2 drops root for, as zapret2's own
	// service on OpenWrt.
	ZapretUser = "daemon"
	// PasswordHint says where root's password is set.
	PasswordHint = "задайте его (команда passwd или LuCI → Система → Администрирование) и войдите снова"
)

// PasswordFiles hold root's password hash, the first one with it wins.
var PasswordFiles = []string{"/etc/shadow"}

// DefaultPasswords are the passwords a fresh system comes with: the web
// interface refuses them (OpenWrt has none).
var DefaultPasswords []string

// leases is dnsmasq's DHCP leases file.
const leases = "/tmp/dhcp.leases"

// Init readies the process for the platform.
func Init() {}

// Hosts are the devices dnsmasq gave an address to.
func Hosts(ctx context.Context) []Host {
	return readLeases(leases)
}

// readLeases reads dnsmasq's leases: "expiry mac ip hostname client-id".
func readLeases(path string) []Host {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []Host
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 4 {
			continue
		}
		name := fs[3]
		if name == "*" {
			name = ""
		}
		out = append(out, Host{MAC: fs[1], IP: fs[2], Name: name})
	}
	return out
}

// WAN are the devices of OpenWrt's wan and wan6 (ubus), else the
// interface of the default route.
func WAN(ctx context.Context) []string {
	var out []string
	for _, n := range []string{"wan", "wan6"} {
		cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		b, err := exec.CommandContext(cctx, "ubus", "call", "network.interface."+n, "status").Output()
		cancel()
		if err != nil {
			continue
		}
		var s struct {
			Up       bool   `json:"up"`
			L3Device string `json:"l3_device"`
			Device   string `json:"device"`
		}
		if json.Unmarshal(b, &s) != nil {
			continue
		}
		d := s.L3Device
		if d == "" {
			d = s.Device
		}
		if d != "" && !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		if dev, _ := DefaultRoute(); dev != "" {
			out = append(out, dev)
		}
	}
	return out
}

// Offload reports fw4's flow offloading: the first packets of a
// forwarded connection may then pass the DPI bypass's queue.
func Offload(ctx context.Context) bool {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	b, err := exec.CommandContext(cctx, "uci", "-q", "get", "firewall.@defaults[0].flow_offloading").Output()
	return err == nil && strings.TrimSpace(string(b)) == "1"
}

// DNSUpstream is where HyRouter's DNS passes the queries it does not
// answer itself: dnsmasq of the router.
func DNSUpstream(lan []string) string { return "127.0.0.1:53" }

// System names the router's system and model for subscription panels.
func System(ctx context.Context) (name, version, model string) {
	name = "OpenWrt"
	if f, err := os.Open("/etc/openwrt_release"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if v, ok := strings.CutPrefix(sc.Text(), "DISTRIB_RELEASE="); ok {
				version = strings.Trim(v, `'"`)
			}
		}
		f.Close()
	}
	if b, err := os.ReadFile("/tmp/sysinfo/model"); err == nil {
		model = strings.TrimSpace(string(b))
	}
	return name, version, model
}
