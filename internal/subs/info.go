package subs

// Panel headers besides the link list (subscription-userinfo & co.): parsed
// defensively (the panel is remote and subscriptions.json user-writable) and
// shown as "осталось 86 ГБ / 12 дней". They never affect routing.

import (
	"fmt"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxInfoHeader  = 1024 // subscription-userinfo longer than this is ignored
	maxLinkLen     = 2048
	maxTitleRunes  = 100
	lowTrafficPct  = 10 // < 10 % left → low
	expireSoon     = 72 * time.Hour
	staleInfo      = 48 * time.Hour // traffic alert older than this shows its date
	maxInfoValue   = int64(1) << 62
	unlimitedTotal = int64(1) << 50 // total ≥ 1 PiB means "no limit"
	// msExpire: an expire at or above it is in milliseconds (some panels).
	// In seconds it would be after the year 5138, so an expire still at or
	// above it after the division is invalid: every date shown fits in four
	// digits in any time zone, and the canonical form reads back the same.
	msExpire = int64(1e11)
	// minMsExpire: a divided expire below it (2000-01-01) was a far-future
	// seconds value meaning "never" (such as 253402300799, 31.12.9999), not
	// milliseconds: it is skipped rather than shown as a 1970s date.
	minMsExpire = int64(946684800)
)

// userInfo is a parsed subscription-userinfo header.
type userInfo struct {
	Upload, Download, Total, Expire             int64
	HasUpload, HasDownload, HasTotal, HasExpire bool
}

// parseUserInfo reads "upload=1; download=2; total=3; expire=4". Separators
// ';' or ','; keys case-insensitive, surrounding spaces ignored; values are
// non-negative integers (a float such as "1.5e9" or "1712345678.0" is
// truncated); the first valid occurrence of a key wins; unknown keys, empty,
// negative, non-finite or > maxInfoValue values are skipped. expire ≥ 1e11
// is milliseconds; an expire still ≥ 1e11 after that, or before 2000 (a
// far-future seconds value), is skipped. ok is false
// when s is longer than maxInfoHeader or no key was recognised.
func parseUserInfo(s string) (u userInfo, ok bool) {
	if len(s) > maxInfoHeader {
		return userInfo{}, false
	}
	for part := range strings.FieldsFuncSeq(s, func(r rune) bool { return r == ';' || r == ',' }) {
		k, v, found := strings.Cut(part, "=")
		if !found {
			continue
		}
		n, valid := infoValue(strings.TrimSpace(v))
		if !valid {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "upload":
			if !u.HasUpload {
				u.Upload, u.HasUpload = n, true
			}
		case "download":
			if !u.HasDownload {
				u.Download, u.HasDownload = n, true
			}
		case "total":
			if !u.HasTotal {
				u.Total, u.HasTotal = n, true
			}
		case "expire":
			if n >= msExpire {
				n /= 1000
				if n < minMsExpire {
					continue
				}
			}
			if !u.HasExpire && n < msExpire {
				u.Expire, u.HasExpire = n, true
			}
		}
	}
	return u, u.HasUpload || u.HasDownload || u.HasTotal || u.HasExpire
}

// infoValue reads one value: an integer in [0, maxInfoValue], or a finite
// float in that range, truncated.
func infoValue(v string) (int64, bool) {
	if v == "" {
		return 0, false
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return n, n >= 0 && n <= maxInfoValue
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || math.IsNaN(f) || f < 0 || f > float64(maxInfoValue) {
		return 0, false
	}
	n := int64(f)
	return n, n >= 0 && n <= maxInfoValue
}

// String is the canonical form stored in Subscription.UserInfo (v1.0.0's
// trafficText reads it): "upload=…; download=…; total=…; expire=…", present
// keys only, in this order. The raw total is kept (≥ 1 PiB is interpreted
// as unlimited only in the view).
func (u userInfo) String() string {
	var parts []string
	add := func(has bool, k string, v int64) {
		if has {
			parts = append(parts, k+"="+strconv.FormatInt(v, 10))
		}
	}
	add(u.HasUpload, "upload", u.Upload)
	add(u.HasDownload, "download", u.Download)
	add(u.HasTotal, "total", u.Total)
	add(u.HasExpire, "expire", u.Expire)
	return strings.Join(parts, "; ")
}

// normalizeUserInfo returns the canonical form of a header, or "".
func normalizeUserInfo(raw string) string {
	u, ok := parseUserInfo(raw)
	if !ok {
		return ""
	}
	return u.String()
}

// SubInfo is a subscription's traffic and term for the UI.
type SubInfo struct {
	Upload      int64     `json:"upload"`
	Download    int64     `json:"download"`
	Used        int64     `json:"used"`
	Total       int64     `json:"total"`       // limit; 0: unlimited or not reported
	Unlimited   bool      `json:"unlimited"`   // total=0 or ≥ 1 PiB was sent
	Left        int64     `json:"left"`        // Total > 0 only
	Percent     int       `json:"percent"`     // share of Total left 0..100; -1 without a limit
	UsedPct     int       `json:"usedPct"`     // bar fill 0..100 (float64 maths, clamped); 0 without a limit
	Expire      int64     `json:"expire"`      // Unix seconds; 0: no end date
	SecondsLeft int64     `json:"secondsLeft"` // until Expire, negative once past; 0 without a date
	At          time.Time `json:"at,omitzero"` // when the panel reported it; absent when unknown
	Level       string    `json:"level"`       // worse of traffic and expiry: "" | "low" | "out"
	Summary     string    `json:"summary"`     // «Осталось 86 ГБ / 12 дней»
	Details     string    `json:"details"`     // «использовано 14 ГБ из 100 ГБ, до 10.10.2026»
	Warning     string    `json:"warning"`     // all reasons; "" when Level is ""
	UpDown      string    `json:"upDown"`      // «↑ 1.2 ГБ ↓ 12.8 ГБ» (bar tooltip); "" without upload/download

	// The two halves, for the alert policy (subAlertFor); not sent to the UI.
	// The traffic reason is trafficHead + " (" + trafficParen + ")"; an
	// alert may add the figures' date inside the parentheses.
	trafficLevel, expireLevel string
	trafficHead, trafficParen string
	expireReason              string
}

// InfoOf is the view of a stored Subscription-Userinfo at now (nil
// without one); at is when the panel reported it.
func InfoOf(raw string, at, now time.Time) *SubInfo {
	u, ok := parseUserInfo(raw)
	if !ok {
		return nil
	}
	return newSubInfo(u, at, now)
}

// worse is the worse of two levels.
func worse(a, b string) string {
	if a == "out" || b == "out" {
		return "out"
	}
	if a == "low" || b == "low" {
		return "low"
	}
	return ""
}

// newSubInfo builds the view of u at now (nil when u says nothing to show).
// It never multiplies header values: percentages via float64, the < 10 %
// test by integer division, sizes by division of remainders, used
// saturating. It never panics and keeps Percent in [0,100] or -1, UsedPct
// in [0,100], levels in {"",low,out}, whatever u holds. JS numbers lose
// precision above 2^53, so the UI uses usedPct/upDown and the Go-made
// texts, never arithmetic on the raw byte counts.
func newSubInfo(u userInfo, at, now time.Time) *SubInfo {
	// u may come from anywhere (tests, a future caller): the parser's
	// bounds again.
	bound := func(v int64, has *bool) int64 {
		if v < 0 || v > maxInfoValue {
			*has = false
		}
		if !*has {
			return 0
		}
		return v
	}
	u.Upload = bound(u.Upload, &u.HasUpload)
	u.Download = bound(u.Download, &u.HasDownload)
	u.Total = bound(u.Total, &u.HasTotal)
	if u.Expire < 0 || u.Expire >= msExpire {
		u.HasExpire = false
	}
	if !u.HasExpire {
		u.Expire = 0
	}
	upDown := u.HasUpload || u.HasDownload
	if !upDown && !u.HasTotal && u.Expire == 0 {
		return nil
	}

	info := &SubInfo{Upload: u.Upload, Download: u.Download, Percent: -1, At: at, Expire: u.Expire}
	info.Used = u.Upload + u.Download
	if u.Upload > maxInfoValue-u.Download {
		info.Used = maxInfoValue
	}
	limit := u.HasTotal && u.Total > 0 && u.Total < unlimitedTotal
	info.Unlimited = u.HasTotal && !limit
	used := fmtSize(info.Used)
	var tPart, dPart, details []string
	if limit {
		t := u.Total
		info.Total = t
		if info.Used < t {
			info.Left = t - info.Used
		}
		info.Percent = clampPct(math.Floor(float64(info.Left) / float64(t) * 100))
		info.UsedPct = clampPct(math.Round(float64(info.Used) / float64(t) * 100))
		pct := strconv.Itoa(info.Percent) + " %"
		if info.Percent == 0 && info.Left > 0 {
			pct = "<1 %"
		}
		total := fmtSize(t)
		switch {
		case info.Left == 0:
			info.trafficLevel = "out"
			tPart = append(tPart, "трафик закончился")
			info.trafficHead, info.trafficParen = "трафик закончился", "использовано "+used+" из "+total
		case info.Left < t/lowTrafficPct || info.Left == t/lowTrafficPct && t%lowTrafficPct != 0:
			info.trafficLevel = "low"
			info.trafficHead, info.trafficParen = "осталось "+fmtSize(info.Left)+" из "+total, pct
		}
		if info.Left > 0 {
			tPart = append(tPart, "осталось "+fmtSize(info.Left))
		}
		details = append(details, "использовано "+used+" из "+total)
	} else {
		if info.Unlimited {
			tPart = append(tPart, "трафик без лимита")
		}
		if upDown {
			details = append(details, "использовано "+used)
		}
	}

	if u.Expire > 0 {
		nowU := min(max(now.Unix(), -maxInfoValue), maxInfoValue)
		info.SecondsLeft = u.Expire - nowU
		end := fmtDate(u.Expire)
		if info.SecondsLeft > 0 {
			d := fmtLeft(info.SecondsLeft)
			if len(tPart) > 0 && strings.HasPrefix(tPart[0], "осталось") {
				dPart = append(dPart, d)
			} else {
				dPart = append(dPart, "осталось "+d)
			}
			details = append(details, "до "+end)
			if info.SecondsLeft < int64(expireSoon/time.Second) {
				info.expireLevel = "low"
				when := "через " + d
				if info.SecondsLeft < 3600 {
					when = "меньше чем через час"
				}
				info.expireReason = "срок заканчивается " + when + ", " + fmtDateHour(u.Expire)
			}
		} else {
			info.expireLevel = "out"
			info.expireReason = "срок истёк " + end
			dPart = append(dPart, info.expireReason)
			details = append(details, "закончилась "+end)
		}
	}

	info.Summary = capFirst(strings.Join(slices.Concat(tPart, dPart), " / "))
	if info.Summary == "" {
		info.Summary = "Использовано " + used
	}
	info.Details = strings.Join(details, ", ")
	if upDown {
		info.UpDown = "↑ " + fmtSize(u.Upload) + " ↓ " + fmtSize(u.Download)
	}
	info.Level = worse(info.trafficLevel, info.expireLevel)
	var reasons []string
	if info.trafficLevel != "" {
		reasons = append(reasons, info.trafficReason(""))
	}
	if info.expireLevel != "" {
		reasons = append(reasons, info.expireReason)
	}
	info.Warning = strings.Join(reasons, "; ")
	return info
}

// trafficReason is the traffic reason; dated (", данные сервиса на …")
// goes inside its parentheses.
func (i *SubInfo) trafficReason(dated string) string {
	return i.trafficHead + " (" + i.trafficParen + dated + ")"
}

func clampPct(f float64) int {
	if math.IsNaN(f) || f < 0 {
		return 0
	}
	if f > 100 {
		return 100
	}
	return int(f)
}

// capFirst upper-cases the first letter.
func capFirst(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	if n == 0 {
		return s
	}
	return string(unicode.ToUpper(r)) + s[n:]
}

// fmtSize prints n bytes in binary units with Russian labels, always
// truncated to the precision shown (9.96 GiB is «9.9 ГБ», never «10.0 ГБ»),
// so «осталось» never promises more than is left. No step multiplies n
// (only a remainder, below 2^40, by ten).
func fmtSize(n int64) string {
	const mib, gib, tib = int64(1) << 20, int64(1) << 30, int64(1) << 40
	if n <= 0 {
		return "0 ГБ"
	}
	switch g := n / gib; {
	case g >= 1024:
		t := n / tib
		if t < 10 {
			return fmt.Sprintf("%d.%d ТБ", t, (n%tib)*10/tib)
		}
		return fmt.Sprintf("%d ТБ", t)
	case g >= 10:
		return fmt.Sprintf("%d ГБ", g)
	case g >= 1:
		return fmt.Sprintf("%d.%d ГБ", g, (n%gib)*10/gib)
	}
	if m := n / mib; m >= 1 {
		return fmt.Sprintf("%d МБ", m)
	}
	return "<1 МБ"
}

// fmtLeft is the time left in whole days, hours or «меньше часа».
func fmtLeft(sec int64) string {
	switch {
	case sec >= 86400:
		d := sec / 86400
		return strconv.FormatInt(d, 10) + " " + ruPlural(d, "день", "дня", "дней")
	case sec >= 3600:
		return strconv.FormatInt(sec/3600, 10) + " ч"
	}
	return "меньше часа"
}

// ruPlural picks the Russian plural form for n.
func ruPlural(n int64, one, few, many string) string {
	m10, m100 := n%10, n%100
	switch {
	case m10 == 1 && m100 != 11:
		return one
	case m10 >= 2 && m10 <= 4 && (m100 < 10 || m100 >= 20):
		return few
	}
	return many
}

func fmtDate(unix int64) string { return time.Unix(unix, 0).Local().Format("02.01.2006") }

func fmtDateHour(unix int64) string {
	return time.Unix(unix, 0).Local().Format("02.01.2006 в 15:04")
}

// cleanTitle drops control characters (whitespace ones become spaces),
// format characters (bidi embeddings, overrides and isolates, marks,
// zero-width characters, BOM, soft hyphen…) and private-use characters;
// drops invalid UTF-8; collapses runs of spaces, trims and caps at
// maxTitleRunes. The title becomes the default subscription name, shown on
// Home, in the nav, diagnostics, the CLI and «Правила текстом» exports, so
// it must not reorder or hide surrounding text.
func cleanTitle(s string) string {
	var b strings.Builder
	n, space := 0, false
	for _, r := range strings.ToValidUTF8(s, "") {
		if unicode.IsSpace(r) {
			space = b.Len() > 0
			continue
		}
		if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Co) || r == utf8.RuneError {
			continue
		}
		if n >= maxTitleRunes {
			break
		}
		if space {
			b.WriteByte(' ')
			n++
			space = false
			if n >= maxTitleRunes {
				break
			}
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// parseUpdateHours reads profile-update-interval (whole hours 1..8760; 0
// otherwise).
func parseUpdateHours(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 8760 {
		return 0
	}
	return n
}

// panelHeaders reads the panel's headers of a 200 answer. Each raw value
// longer than its bound is dropped before any processing (the title is
// bounded before decoding); clean then normalises them.
func panelHeaders(h http.Header) FetchResult {
	var r FetchResult
	if t := h.Get("Profile-Title"); len(t) <= 4*maxInfoHeader {
		r.Title = decodeTitle(t)
	}
	if u := h.Get("Subscription-Userinfo"); len(u) <= maxInfoHeader {
		r.UserInfo = u
	}
	if u := h.Get("Profile-Update-Interval"); len(u) <= 16 {
		r.UpdateHours = parseUpdateHours(u)
	}
	if u := h.Get("Support-Url"); len(u) <= maxLinkLen {
		r.Support = u
	}
	return r
}

// fetchedInfo is the view of a download's figures (nil: none).
func fetchedInfo(res FetchResult) *SubInfo {
	u, ok := parseUserInfo(res.UserInfo)
	if !ok {
		return nil
	}
	return newSubInfo(u, res.At, time.Now())
}

// previewInfoErr adds what the panel reports to a check whose body did not
// parse (Marzban and Remnawave answer an expired account with 200 and an
// empty list or a web page): «подписка пустая. Сервис сообщает: срок истёк
// 25.09.2026». Wails rejects the promise with a string, so it rides in the
// text.
func previewInfoErr(err error, res FetchResult) error {
	if info := fetchedInfo(res); info != nil && info.Level != "" {
		return fmt.Errorf("%w. Сервис сообщает: %s", err, info.Warning)
	}
	return err
}

// clean normalises a download's panel data (both httpFetch and the test
// Fetch go through it, in Controller.fetch).
func (r FetchResult) clean() FetchResult {
	r.Title = cleanTitle(r.Title)
	r.UserInfo = normalizeUserInfo(r.UserInfo)
	if r.UpdateHours < 1 || r.UpdateHours > 8760 {
		r.UpdateHours = 0
	}
	r.Support = safeLink(r.Support)
	return r
}

// safeLink returns the canonical form of a panel link that may be shown and
// opened: an absolute http(s) URL with a host, no user info, at most
// maxLinkLen bytes, no whitespace, control or format characters or any of
// `"<>\^`{|}`. "" otherwise. It re-serialises through url.URL.String().
func safeLink(raw string) string {
	if raw == "" || len(raw) > maxLinkLen || !utf8.ValidString(raw) {
		return ""
	}
	for _, r := range raw {
		if unicode.IsSpace(r) || unicode.In(r, unicode.Cc, unicode.Cf, unicode.Co) || strings.ContainsRune("\"<>\\^`{|}", r) {
			return ""
		}
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Opaque != "" || u.User != nil || u.Hostname() == "" {
		return ""
	}
	out := u.String()
	if len(out) > maxLinkLen {
		return ""
	}
	return out
}

// Explain adds what the panel reports to an update whose body did not
// parse (panels answer an expired account with 200 and an empty list or a
// web page): «подписка пустая. Сервис сообщает: срок истёк 25.09.2026».
func Explain(err error, res FetchResult) error { return previewInfoErr(err, res) }
