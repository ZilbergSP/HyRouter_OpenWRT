// Package subs downloads subscriptions (a panel's link that lists
// servers) and merges their servers into the router's (HyRoute's
// internal/app subs.go, links.go, merge.go and subinfo.go, adapted: no
// controller, no snapshots).
package subs

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zilbergsp/hyrouter/internal/geodata"
	"github.com/zilbergsp/hyrouter/internal/socks5"
	"github.com/zilbergsp/hyrouter/internal/subfmt"
)

// maxBody bounds a subscription's answer.
const maxBody = 5 << 20

// MaxServers bounds the servers taken from one subscription: every one is
// kept in servers.json and merged on every update, and public aggregators
// list thousands. The controller lowers it for HyRouter Lite.
var MaxServers = 3000

// maxErrors bounds the parse errors a subscription keeps of its update.
const maxErrors = 5

// FetchResult is a downloaded subscription.
type FetchResult struct {
	Body []byte
	// Title is the panel's profile-title, UserInfo its
	// subscription-userinfo (canonical or ""), UpdateHours its
	// profile-update-interval (0 = not sent), Support its support-url
	// (safe or "").
	Title       string
	UserInfo    string
	UpdateHours int
	Support     string
	At          time.Time
	// ViaVPN: the direct download failed and this one went through the
	// main server.
	ViaVPN bool
}

// DeviceInfo is what panels that limit a subscription's devices
// (Remnawave's «HWID device limit» and panels copying it) want to see:
// without x-hwid such a panel answers with a placeholder server
// («Приложение не поддерживается»).
type DeviceInfo struct {
	HWID      string // x-hwid ("" sends no device headers)
	OS        string // x-device-os
	OSVersion string // x-ver-os
	Model     string // x-device-model
}

func (d DeviceInfo) setHeaders(h http.Header) {
	if d.HWID == "" {
		return
	}
	h.Set("X-Hwid", d.HWID)
	for k, v := range map[string]string{"X-Device-Os": d.OS, "X-Ver-Os": d.OSVersion, "X-Device-Model": d.Model} {
		if v != "" {
			h.Set(k, v)
		}
	}
}

// DeviceID is the router's ID for the panel at host: a hash of the
// router's own random ID and the host, so panels cannot match their users
// by it.
func DeviceID(routerID, host string) string {
	if routerID == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("HyRouter device\x00" + strings.ToLower(strings.TrimSpace(routerID)) + "\x00" + strings.ToLower(host)))
	return hex.EncodeToString(sum[:16])
}

// Dialer is a server's way out (tunnels.Endpoint).
type Dialer interface {
	Dial(ctx context.Context, dst socks5.Addr) (net.Conn, error)
}

// Fetcher downloads subscriptions.
type Fetcher struct {
	UserAgent string
	// Device gives the device headers for a panel's host (nil = none).
	Device func(host string) DeviceInfo
	// Tunnel is the main server's way out for a panel the network blocks
	// (nil = none).
	Tunnel func() Dialer
	// Transport replaces the direct transport (tests).
	Transport http.RoundTripper
}

// directTransport is the default transport without a proxy, its panel
// headers bounded.
func directTransport() *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.MaxResponseHeaderBytes = 64 << 10
	tr.DisableKeepAlives = true
	return tr
}

// redirect refuses a redirect from https to http (the token in the link
// and the servers' passwords in the body would go in clear), and a
// redirect to another host leaves the device's headers behind: its ID is
// the panel's own, and net/http copies every header but Authorization and
// Cookie to the next host.
func redirect(req *http.Request, via []*http.Request) error {
	if err := geodata.NoDowngrade(req, via); err != nil {
		return err
	}
	if len(via) > 0 && !strings.EqualFold(req.URL.Hostname(), via[0].URL.Hostname()) {
		for _, k := range []string{"X-Hwid", "X-Device-Os", "X-Ver-Os", "X-Device-Model"} {
			req.Header.Del(k)
		}
	}
	return nil
}

// tunnelClient downloads through a server's tunnel. A client per
// download: a connection kept idle would hold a tunnel stream and two
// goroutines until the server closes it.
func tunnelClient(tun Dialer) *http.Client {
	return &http.Client{Timeout: 30 * time.Second, CheckRedirect: redirect, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			pn, err := strconv.Atoi(port)
			if err != nil {
				return nil, err
			}
			return tun.Dial(ctx, socks5.Addr{Host: host, Port: uint16(pn)})
		},
		TLSHandshakeTimeout:    20 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		DisableKeepAlives:      true,
	}}
}

// Fetch downloads a subscription: directly, and when that fails, an https
// one once more through the main server (the VPN server never sees an
// http link's token).
func (f *Fetcher) Fetch(ctx context.Context, rawURL string) (FetchResult, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return FetchResult{}, errors.New("ссылка подписки должна начинаться с https:// (или http://)")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return FetchResult{}, err
	}
	req.Header.Set("User-Agent", f.UserAgent)
	req.Header.Set("Accept", "text/plain, */*")
	if f.Device != nil {
		f.Device(u.Hostname()).setHeaders(req.Header)
	}
	var tr http.RoundTripper = directTransport()
	if f.Transport != nil {
		tr = f.Transport
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second, Transport: tr, CheckRedirect: redirect}).Do(req)
	viaVPN := false
	if failed := err != nil || resp.StatusCode >= 500; failed && u.Scheme == "https" && f.Tunnel != nil {
		if tun := f.Tunnel(); tun != nil {
			if r2, err2 := tunnelClient(tun).Do(req.Clone(ctx)); err2 == nil {
				if resp != nil {
					resp.Body.Close()
				}
				resp, err, viaVPN = r2, nil, true
			} else if err != nil {
				err = err2
			}
		}
	}
	if err != nil {
		// The error text holds the URL: never show it.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return FetchResult{}, fmt.Errorf("сервер подписки недоступен: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return FetchResult{}, fmt.Errorf("сервер подписки ответил %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return FetchResult{}, fmt.Errorf("ответ подписки оборван: %v", err)
	}
	if len(body) > maxBody {
		return FetchResult{}, errors.New("ответ подписки больше 5 МБ")
	}
	res := panelHeaders(resp.Header)
	res.Body, res.ViaVPN = body, viaVPN
	res = res.clean()
	res.At = time.Now()
	return res, nil
}

// decodeTitle handles "base64:..." titles of common panels.
func decodeTitle(s string) string {
	if rest, ok := strings.CutPrefix(s, "base64:"); ok {
		if b, err := base64.StdEncoding.DecodeString(rest); err == nil {
			return string(b)
		}
	}
	return s
}

// capServers keeps the first MaxServers servers of l, with a warning.
func capServers(l Links) Links {
	if n := len(l.Profiles); n > MaxServers {
		l.Profiles = l.Profiles[:MaxServers]
		l.Warnings = append(l.Warnings, fmt.Sprintf("в подписке %d серверов: взяты первые %d", n, MaxServers))
	}
	return l
}

// Parse turns a body into servers or an error that explains what came
// instead. A list of share links (plain or base64) is the usual body;
// Clash, sing-box and Xray configs are read too (subfmt).
func Parse(body []byte) (Links, error) {
	l := ParseLinks(string(body))
	if len(l.Profiles) > 0 {
		return capServers(l), nil
	}
	if r, ok := subfmt.Convert(body); ok {
		l = ParseLinks(strings.Join(r.Links, "\n"))
		l.Format = r.Format
		l.Warnings = append(r.Warnings, l.Warnings...)
		l.Errors = append(r.Errors, l.Errors...)
		for k, v := range r.Other {
			l.Ignored[k] += v
		}
		if len(l.Profiles) > 0 {
			return capServers(l), nil
		}
	}
	t := strings.TrimSpace(string(body))
	switch {
	case len(l.Notices) > 0:
		// The panel says why it sent no servers: a device limit, an
		// expired account, an app it does not serve.
		return l, fmt.Errorf("панель прислала вместо серверов сообщение: «%s»", strings.Join(l.Notices, "», «"))
	case t == "":
		return l, errors.New("подписка пустая")
	case strings.HasPrefix(strings.ToLower(t), "<!doctype") || strings.HasPrefix(strings.ToLower(t), "<html"):
		return l, errors.New("сервер вернул веб-страницу, а не подписку: проверьте ссылку")
	case len(l.Errors) > 0:
		msg := fmt.Sprintf("ни один сервер Hysteria 2 или VLESS не разобран (%d): %s", len(l.Errors), l.Errors[0])
		if l.IgnoredTotal() > 0 {
			msg += "; других протоколов: " + ignoredText(l.Ignored)
		}
		return l, errors.New(msg)
	case l.IgnoredTotal() > 0:
		return l, fmt.Errorf("в подписке нет серверов Hysteria 2 и VLESS, только другие протоколы (%s)", ignoredText(l.Ignored))
	case l.Format != "":
		return l, fmt.Errorf("в конфиге %s нет серверов", l.Format)
	case strings.HasPrefix(t, "{") || strings.HasPrefix(t, "["):
		return l, errors.New("JSON без серверов: HyRouter читает конфиги sing-box и Xray и списки ссылок")
	case !strings.ContainsAny(t, "\r\n") && utf8.RuneCountInString(t) <= 200:
		return l, fmt.Errorf("сервер подписки ответил текстом, а не ссылками: «%s»", t)
	}
	return l, errors.New("в ответе нет ссылок hysteria2://, hy2:// или vless://")
}

// FirstErrors is at most maxErrors of a parse's errors.
func FirstErrors(l Links) []string { return l.Errors[:min(len(l.Errors), maxErrors)] }

func ignoredText(m map[string]int) string {
	var parts []string
	for k, v := range m {
		parts = append(parts, fmt.Sprintf("%s: %d", k, v))
	}
	slices.Sort(parts)
	return strings.Join(parts, ", ")
}

// MaskURL shows only the scheme and host: path and query usually carry
// the token.
func MaskURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "***"
	}
	return u.Scheme + "://" + u.Host + "/…"
}

// pathWords are path segments of panels that are words, not tokens.
var pathWords = map[string]bool{
	"subscription": true, "subscriptions": true, "subscribe": true, "download": true, "dns-query": true,
}

// Secrets are the redactor entries for a subscription URL: the URL and
// every path segment and query value long enough to be a token.
func Secrets(raw string) []string {
	out := []string{raw}
	u, err := url.Parse(raw)
	if err != nil {
		return out
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if len(seg) >= 8 && !pathWords[strings.ToLower(seg)] {
			out = append(out, seg)
		}
	}
	for _, vs := range u.Query() {
		for _, v := range vs {
			if len(v) >= 8 {
				out = append(out, v)
			}
		}
	}
	if u.User != nil {
		out = append(out, u.User.String())
	}
	return out
}

// SameURL reports two subscription links as one: the same link but for
// the scheme's and host's case.
func SameURL(a, b string) bool {
	ua, err1 := url.Parse(strings.TrimSpace(a))
	ub, err2 := url.Parse(strings.TrimSpace(b))
	if err1 != nil || err2 != nil {
		return strings.TrimSpace(a) == strings.TrimSpace(b)
	}
	return strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Host, ub.Host) && ua.RequestURI() == ub.RequestURI()
}
