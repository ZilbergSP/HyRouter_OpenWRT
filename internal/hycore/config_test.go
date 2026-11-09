package hycore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/apernet/hysteria/extras/v2/transport/udphop"

	"github.com/zilbergsp/hyrouter/internal/hysteria"
	"github.com/zilbergsp/hyrouter/internal/socks5"
)

func profile() hysteria.Profile {
	return hysteria.Profile{ID: "srv-1", Name: "NL", Host: "nl.example", Ports: "443", Auth: "pass"}
}

// The config follows the hysteria app's client config.
func TestConfig(t *testing.T) {
	p := profile()
	p.TLS = hysteria.TLS{PinSHA256: "AB:CD"}
	p.Bandwidth = hysteria.Bandwidth{Up: "20 mbps", Down: "100mbps"}
	p.QUIC = hysteria.QUIC{MaxIdleTimeout: "40s", KeepAlivePeriod: "15s", InitStreamReceiveWindow: 1 << 20}
	p.Obfs = hysteria.Obfs{Type: "Salamander", Password: "obfs"}
	p.FastOpen = true
	c, err := Config(p, "198.51.100.7")
	if err != nil {
		t.Fatal(err)
	}
	if c.Auth != "pass" || !c.FastOpen || c.ServerAddr.String() != "198.51.100.7:443" {
		t.Errorf("%+v", c)
	}
	// The host is the TLS name when the address is given; a pin skips
	// the chain and checks the leaf's hash.
	if c.TLSConfig.ServerName != "nl.example" || !c.TLSConfig.InsecureSkipVerify || c.TLSConfig.VerifyPeerCertificate == nil {
		t.Errorf("tls %+v", c.TLSConfig)
	}
	leaf := []byte("certificate")
	sum := sha256.Sum256(leaf)
	p.TLS.PinSHA256 = strings.ToUpper(hex.EncodeToString(sum[:]))
	c2, err := Config(p, "198.51.100.7")
	if err != nil {
		t.Fatal(err)
	}
	if err := c2.TLSConfig.VerifyPeerCertificate([][]byte{leaf}, nil); err != nil {
		t.Errorf("the pinned certificate was refused: %v", err)
	}
	if err := c2.TLSConfig.VerifyPeerCertificate([][]byte{[]byte("other")}, nil); err == nil {
		t.Error("another certificate passed the pin")
	}
	if c.BandwidthConfig.MaxTx != 20_000_000/8 || c.BandwidthConfig.MaxRx != 100_000_000/8 {
		t.Errorf("bandwidth %+v", c.BandwidthConfig)
	}
	if c.QUICConfig.MaxIdleTimeout != 40*time.Second || c.QUICConfig.KeepAlivePeriod != 15*time.Second || c.QUICConfig.InitialStreamReceiveWindow != 1<<20 {
		t.Errorf("quic %+v", c.QUICConfig)
	}
	// The socket is the obfuscated one.
	conn, err := c.ConnFactory.New(c.ServerAddr)
	if err != nil {
		t.Fatal(err)
	}
	if _, plain := conn.(*net.UDPConn); plain {
		t.Error("salamander did not wrap the socket")
	}
	conn.Close()
}

func TestConfigHopping(t *testing.T) {
	p := profile()
	p.Ports = "443,20000-20010"
	p.Hop = hysteria.Hop{Interval: "30s"}
	c, err := Config(p, "198.51.100.7")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.ServerAddr.(*udphop.UDPHopAddr); !ok {
		t.Fatalf("server %T", c.ServerAddr)
	}
	if h, err := hopInterval(p.Hop); err != nil || h.Min != 30*time.Second || h.Max != 30*time.Second {
		t.Errorf("%+v %v", h, err)
	}
	if _, err := hopInterval(hysteria.Hop{Interval: "30s", MinInterval: "10s"}); err == nil {
		t.Error("an interval with a range was taken")
	}
	if _, err := hopInterval(hysteria.Hop{MinInterval: "10s"}); err == nil {
		t.Error("a range without its end was taken")
	}
}

func TestConfigRefuses(t *testing.T) {
	with := func(f func(p *hysteria.Profile)) hysteria.Profile {
		p := profile()
		f(&p)
		return p
	}
	for name, p := range map[string]hysteria.Profile{
		"vless":     {ID: "v", Name: "v", Protocol: hysteria.ProtoVLESS, Host: "v.example", Ports: "443"},
		"bandwidth": with(func(p *hysteria.Profile) { p.Bandwidth.Up = "fast" }),
		"obfs":      with(func(p *hysteria.Profile) { p.Obfs = hysteria.Obfs{Type: "rot13", Password: "x"} }),
		"ech":       with(func(p *hysteria.Profile) { p.TLS.ECH = "%%%" }),
		"ca":        with(func(p *hysteria.Profile) { p.TLS.CA = "/nonexistent/ca.pem" }),
	} {
		if _, err := Config(p, "198.51.100.7"); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
}

func TestStringToBps(t *testing.T) {
	for in, want := range map[string]uint64{"8 bps": 1, "1 kbps": 125, "1m": 125000, "2 gbps": 250000000, " 1 TB ": 125000000000} {
		if got, err := stringToBps(in); err != nil || got != want {
			t.Errorf("%q: %d %v", in, got, err)
		}
	}
	for _, in := range []string{"", "mbps", "10 furlongs"} {
		if _, err := stringToBps(in); err == nil {
			t.Errorf("%q taken", in)
		}
	}
}

// A runner that cannot reach its server says so and stops cleanly.
func TestRunnerUnreachable(t *testing.T) {
	old := backoffMin
	backoffMin = 50 * time.Millisecond
	defer func() { backoffMin = old }()
	p := profile()
	var got []netip.Addr
	r := &Runner{Profile: p, Resolve: func(context.Context, string) ([]netip.Addr, error) {
		return nil, &net.DNSError{Err: "no such host", Name: p.Host, IsNotFound: true}
	}}
	r.Hooks.SetServerIPs = func(ips []netip.Addr) error { got = ips; return nil }
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for r.Status().State != hysteria.Failed && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if st := r.Status(); st.State != hysteria.Failed || !strings.Contains(st.Message, "адрес сервера не найден") {
		t.Errorf("%+v", st)
	}
	if r.Available() || got != nil {
		t.Error("an unreachable server is available")
	}
	if r.SOCKS().Server == "" {
		t.Error("no SOCKS5 server")
	}
	r.Stop()
	if st := r.Status(); st.State != hysteria.Stopped {
		t.Errorf("after Stop: %+v", st)
	}
	if _, err := r.Dial(context.Background(), socksAddr()); err == nil {
		t.Error("a stopped runner dialed")
	}
}

func socksAddr() socks5.Addr { return socks5.Addr{Host: "example.com", Port: 443} }
