// Package hycore runs a Hysteria 2 server's client inside hyrouterd
// (HyRouter Lite): the core of apernet/hysteria as a library instead of a
// hysteria process per server, which a router with 128 MB of memory and a
// small flash cannot afford. It offers the same SOCKS5 server on loopback
// as the process does, so the relay, the probes and the DNS reach it the
// same way. The config follows the client of apernet/hysteria app/v2.12.3
// (app/cmd/client.go) field by field.
package hycore

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/extras/v2/obfs"
	"github.com/apernet/hysteria/extras/v2/transport/udphop"

	"github.com/zilbergsp/hyrouter/internal/hysteria"
)

// Config is the client config of a profile. serverIP, when valid, is the
// address to connect to (the server's host stays the TLS name).
func Config(p hysteria.Profile, serverIP string) (*client.Config, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if p.IsVLESS() {
		return nil, errors.New("VLESS не запускается встроенным клиентом")
	}
	c := &client.Config{Auth: p.Auth, FastOpen: p.FastOpen}
	host := p.Host
	if serverIP != "" {
		host = serverIP
	}
	hostPort := hysteria.ServerString(host, p.Ports)
	_, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, fmt.Errorf("server: %v", err)
	}
	hop := strings.ContainsAny(port, "-,")
	if hop {
		c.ServerAddr, err = udphop.ResolveUDPHopAddr(hostPort)
	} else {
		c.ServerAddr, err = net.ResolveUDPAddr("udp", hostPort)
	}
	if err != nil {
		return nil, fmt.Errorf("server: %v", err)
	}

	// TLS: the name is the host's, unless set.
	c.TLSConfig.ServerName = p.Host
	if p.TLS.SNI != "" {
		c.TLSConfig.ServerName = p.TLS.SNI
	}
	c.TLSConfig.InsecureSkipVerify = p.TLS.Insecure || p.TLS.PinSHA256 != ""
	if pin := p.TLS.PinSHA256; pin != "" {
		want := normalizeCertHash(pin)
		c.TLSConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			if hex.EncodeToString(sum[:]) == want {
				return nil
			}
			return errors.New("no certificate matches the pinned hash")
		}
	}
	if p.TLS.CA != "" {
		ca, err := os.ReadFile(p.TLS.CA)
		if err != nil {
			return nil, fmt.Errorf("tls.ca: %v", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, errors.New("tls.ca: failed to parse CA certificate")
		}
		c.TLSConfig.RootCAs = pool
	}
	if p.TLS.ECH != "" {
		list, err := echConfigList(p.TLS.ECH)
		if err != nil {
			return nil, fmt.Errorf("tls.ech: %v", err)
		}
		c.TLSConfig.ECHConfigList = list
	}

	// QUIC.
	q := p.QUIC
	c.QUICConfig = client.QUICConfig{
		InitialStreamReceiveWindow:     q.InitStreamReceiveWindow,
		MaxStreamReceiveWindow:         q.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: q.InitConnReceiveWindow,
		MaxConnectionReceiveWindow:     q.MaxConnReceiveWindow,
		DisablePathMTUDiscovery:        q.DisablePathMTUDiscovery,
		DisableChromeParrot:            q.DisableChromeParrot,
	}
	if c.QUICConfig.MaxIdleTimeout, err = duration(q.MaxIdleTimeout); err != nil {
		return nil, fmt.Errorf("quic.maxIdleTimeout: %v", err)
	}
	if c.QUICConfig.KeepAlivePeriod, err = duration(q.KeepAlivePeriod); err != nil {
		return nil, fmt.Errorf("quic.keepAlivePeriod: %v", err)
	}

	// Bandwidth and congestion.
	if p.Bandwidth.Up != "" {
		if c.BandwidthConfig.MaxTx, err = stringToBps(p.Bandwidth.Up); err != nil {
			return nil, fmt.Errorf("bandwidth.up: %v", err)
		}
	}
	if p.Bandwidth.Down != "" {
		if c.BandwidthConfig.MaxRx, err = stringToBps(p.Bandwidth.Down); err != nil {
			return nil, fmt.Errorf("bandwidth.down: %v", err)
		}
	}
	c.CongestionConfig.Type, c.CongestionConfig.BBRProfile = p.Congestion.Type, p.Congestion.BBRProfile

	// The UDP socket: port hopping, then the obfuscation.
	hopEvery, err := hopInterval(p.Hop)
	if err != nil {
		return nil, fmt.Errorf("transport.udp: %v", err)
	}
	open := func() (net.PacketConn, error) { return net.ListenUDP("udp", nil) }
	if hop {
		addr := c.ServerAddr.(*udphop.UDPHopAddr)
		listen := open
		open = func() (net.PacketConn, error) {
			return udphop.NewUDPHopPacketConn(addr, hopEvery, listen)
		}
	}
	wrap, err := obfsWrapper(p.Obfs)
	if err != nil {
		return nil, err
	}
	c.ConnFactory = connFactory(func() (net.PacketConn, error) {
		conn, err := open()
		if err != nil {
			return nil, err
		}
		w, err := wrap(conn)
		if err != nil {
			conn.Close()
			return nil, err
		}
		return w, nil
	})
	return c, nil
}

// connFactory makes the client's UDP socket.
type connFactory func() (net.PacketConn, error)

func (f connFactory) New(net.Addr) (net.PacketConn, error) { return f() }

// obfsWrapper is the obfuscation of a profile.
func obfsWrapper(o hysteria.Obfs) (func(net.PacketConn) (net.PacketConn, error), error) {
	switch strings.ToLower(o.Type) {
	case "", "plain":
		return func(c net.PacketConn) (net.PacketConn, error) { return c, nil }, nil
	case "salamander":
		return func(c net.PacketConn) (net.PacketConn, error) {
			return obfs.WrapPacketConnSalamander(c, []byte(o.Password))
		}, nil
	case "gecko":
		return func(c net.PacketConn) (net.PacketConn, error) {
			return obfs.WrapPacketConnGecko(c, obfs.GeckoOptions{Password: []byte(o.Password), MinPacketSize: o.MinPacketSize, MaxPacketSize: o.MaxPacketSize})
		}, nil
	}
	return nil, fmt.Errorf("obfs.type: %q не поддерживается", o.Type)
}

// hopInterval is the port hopping interval (hopIntervalConfig of the app).
func hopInterval(h hysteria.Hop) (udphop.HopIntervalConfig, error) {
	every, err := duration(h.Interval)
	if err != nil {
		return udphop.HopIntervalConfig{}, err
	}
	lo, err := duration(h.MinInterval)
	if err != nil {
		return udphop.HopIntervalConfig{}, err
	}
	hi, err := duration(h.MaxInterval)
	if err != nil {
		return udphop.HopIntervalConfig{}, err
	}
	switch {
	case every != 0 && (lo != 0 || hi != 0):
		return udphop.HopIntervalConfig{}, errors.New("hopInterval cannot be used together with minHopInterval or maxHopInterval")
	case lo == 0 && hi == 0:
		if every == 0 {
			return udphop.HopIntervalConfig{}, nil
		}
		return udphop.HopIntervalConfig{Min: every, Max: every}, nil
	case lo == 0 || hi == 0:
		return udphop.HopIntervalConfig{}, errors.New("minHopInterval and maxHopInterval must both be set")
	}
	return udphop.HopIntervalConfig{Min: lo, Max: hi}, nil
}

// duration reads "30s", "" = 0.
func duration(s string) (time.Duration, error) {
	if strings.TrimSpace(s) == "" {
		return 0, nil
	}
	return time.ParseDuration(strings.TrimSpace(s))
}

// normalizeCertHash is the app's: lower case without ":" and "-".
func normalizeCertHash(hash string) string {
	return strings.NewReplacer(":", "", "-", "").Replace(strings.ToLower(hash))
}

// stringToBps is the app's utils.StringToBps: "100 mbps" in bytes a second.
func stringToBps(s string) (uint64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	spl := 0
	for i, c := range s {
		if c < '0' || c > '9' {
			spl = i
			break
		}
	}
	if spl == 0 {
		return 0, errors.New("invalid format")
	}
	v, err := strconv.ParseUint(s[:spl], 10, 64)
	if err != nil {
		return 0, err
	}
	const k = 1000
	switch strings.TrimSpace(s[spl:]) {
	case "b", "bps":
		return v / 8, nil
	case "k", "kb", "kbps":
		return v * k / 8, nil
	case "m", "mb", "mbps":
		return v * k * k / 8, nil
	case "g", "gb", "gbps":
		return v * k * k * k / 8, nil
	case "t", "tb", "tbps":
		return v * k * k * k * k / 8, nil
	}
	return 0, errors.New("unsupported unit")
}

// echConfigList decodes a base64 ECHConfigList (standard or URL alphabet,
// padded or not).
func echConfigList(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) > 2 {
			return b, nil
		}
	}
	return nil, errors.New("не base64-список ECHConfigList")
}
