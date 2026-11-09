package subs

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	kib = int64(1) << 10
	mib = int64(1) << 20
	gib = int64(1) << 30
	tib = int64(1) << 40
)

func TestParseUserInfo(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string // canonical form; "" = not ok
	}{
		{"upload=1; download=2; total=3; expire=4", "upload=1; download=2; total=3; expire=4"},
		{"  Upload = 1 ;DOWNLOAD=2;  Total=3 ", "upload=1; download=2; total=3"},
		{"upload=1,download=2,total=3", "upload=1; download=2; total=3"},
		{"total=100", "total=100"},
		{"upload=5; expire=", "upload=5"},
		{"expire=0", "expire=0"},
		{"upload=1.5e9; download=1712345678.0", "upload=1500000000; download=1712345678"},
		{"upload=-1; download=2", "download=2"},
		{"upload=9223372036854775807; total=5", "total=5"},
		{"upload=4611686018427387904; download=4611686018427387905", "upload=4611686018427387904"},
		{"upload=NaN; download=1e400; total=inf; expire=7", "expire=7"},
		{"upload=1; upload=2", "upload=1"},
		{"upload=x; upload=3", "upload=3"},
		{"expire=1791612000000", "expire=1791612000"},
		{"expire=253402300799; total=5", "total=5"},
		{"expire=946684799999; expire=7", "expire=7"},
		{"expire=946684800000", "expire=946684800"},
		{"garbage", ""},
		{"", ""},
		{"foo=1; bar=2", ""},
		{"upload=1;" + strings.Repeat(" ", maxInfoHeader-8), ""},
	} {
		got := normalizeUserInfo(tc.in)
		if got != tc.want {
			t.Errorf("%q: got %q, want %q", tc.in, got, tc.want)
		}
		if got != "" && normalizeUserInfo(got) != got {
			t.Errorf("%q: canonical form %q does not read back", tc.in, got)
		}
	}
	if _, ok := parseUserInfo("upload=1;" + strings.Repeat(" ", maxInfoHeader-9)); !ok {
		t.Error("a header of exactly maxInfoHeader bytes refused")
	}
}

func FuzzParseUserInfo(f *testing.F) {
	for _, s := range []string{"upload=1; download=2; total=3; expire=4", "expire=1791612000000", "total=1e400", "a=b,c=d;;=;", "upload=1.9;upload=2", "expire=199999999999999", "expire=253402300799", "expire=946684799999"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n := normalizeUserInfo(s)
		if normalizeUserInfo(n) != n {
			t.Fatalf("%q: %q is not canonical", s, n)
		}
		if u, ok := parseUserInfo(s); ok {
			newSubInfo(u, time.Unix(1_700_000_000, 0), time.Unix(1_700_000_000, 0))
		}
	})
}

var bigYear = regexp.MustCompile(`\d\d\.\d\d\.\d{5}`)

func FuzzSubInfo(f *testing.F) {
	f.Add(int64(1), int64(2), int64(3), int64(4), true, true, true, true, int64(1_700_000_000))
	f.Add(maxInfoValue, maxInfoValue, maxInfoValue, int64(253402300799), true, true, true, true, int64(0))
	f.Add(int64(0), int64(0), unlimitedTotal-1, msExpire-1, false, true, true, true, int64(-1))
	f.Add(int64(0), int64(0), int64(0), int64(253402300), false, false, false, true, int64(1_790_000_000))
	f.Add(int64(-5), int64(math.MaxInt64), int64(math.MinInt64), int64(math.MaxInt64), true, true, true, true, int64(math.MaxInt64))
	f.Fuzz(func(t *testing.T, up, down, total, expire int64, hu, hd, ht, he bool, now int64) {
		u := userInfo{Upload: up, Download: down, Total: total, Expire: expire, HasUpload: hu, HasDownload: hd, HasTotal: ht, HasExpire: he}
		if now < 0 {
			now = -(now + 1)
		}
		at := time.Unix(now%(1<<40), 0)
		info := newSubInfo(u, at, at)
		if info == nil {
			return
		}
		if info.Percent != -1 && (info.Percent < 0 || info.Percent > 100) {
			t.Fatalf("percent %d", info.Percent)
		}
		if info.UsedPct < 0 || info.UsedPct > 100 || info.Left < 0 || info.Used < 0 {
			t.Fatalf("%+v", info)
		}
		for _, l := range []string{info.Level, info.trafficLevel, info.expireLevel} {
			if l != "" && l != "low" && l != "out" {
				t.Fatalf("level %q", l)
			}
		}
		if info.Summary == "" {
			t.Fatalf("empty summary: %+v", info)
		}
		for _, s := range []string{info.Summary, info.Details, info.Warning, info.UpDown} {
			if bigYear.MatchString(s) {
				t.Fatalf("year > 9999: %q", s)
			}
		}
	})
}

func info(t *testing.T, header string, at, now time.Time) *SubInfo {
	t.Helper()
	u, ok := parseUserInfo(header)
	if !ok {
		t.Fatalf("%q does not parse", header)
	}
	return newSubInfo(u, at, now)
}

func hdr(up, down, total, expire int64) string {
	s := "upload=" + strconv.FormatInt(up, 10) + "; download=" + strconv.FormatInt(down, 10)
	if total >= 0 {
		s += "; total=" + strconv.FormatInt(total, 10)
	}
	if expire >= 0 {
		s += "; expire=" + strconv.FormatInt(expire, 10)
	}
	return s
}

func TestSubInfoBigValues(t *testing.T) {
	now := time.Unix(1_790_000_000, 0)
	i := info(t, hdr(1, 0, unlimitedTotal-1, -1), now, now)
	if i.Total != unlimitedTotal-1 || i.Unlimited || i.Percent != 99 || i.Level != "" {
		t.Fatalf("%+v", i)
	}
	for _, total := range []int64{unlimitedTotal, maxInfoValue} {
		i := info(t, hdr(5*gib, 0, total, -1), now, now)
		if !i.Unlimited || i.Total != 0 || !strings.HasPrefix(i.Summary, "Трафик без лимита") || i.trafficLevel != "" || i.Percent != -1 || i.UsedPct != 0 {
			t.Fatalf("total %d: %+v", total, i)
		}
	}
	T := int64(1) << 49
	if i := info(t, hdr(T-(T/10-1), 0, T, -1), now, now); i.Level != "low" {
		t.Fatalf("2^49: %+v", i)
	}
	if i := info(t, hdr(1001-100, 0, 1001, -1), now, now); i.Level != "low" {
		t.Fatalf("left = T/10 with a remainder: %+v", i)
	}
	if i := info(t, hdr(9, 0, 10, -1), now, now); i.Level != "" {
		t.Fatalf("10 %% left: %+v", i)
	}
	for _, e := range []int64{maxInfoValue, maxInfoValue / 1000 * 1000} {
		i := info(t, hdr(1, 1, 10*gib, e), now, now)
		if i.Expire != 0 || strings.Contains(i.Summary, "/") || strings.Contains(i.Details, "до ") {
			t.Fatalf("expire %d: %+v", e, i)
		}
	}
	// A far-future seconds value meaning "never" is not read as a 1978
	// date in milliseconds.
	if u, ok := parseUserInfo("expire=253402300799"); ok || u.HasExpire {
		t.Fatalf("%+v", u)
	}
	if i := info(t, "total=10; expire=253402300799", now, now); i == nil || i.Expire != 0 || i.Level != "" {
		t.Fatalf("%+v", i)
	}
}

func TestFmtSize(t *testing.T) {
	for n, want := range map[int64]string{
		0:                     "0 ГБ",
		500 * kib:             "<1 МБ",
		512 * mib:             "512 МБ",
		8 * gib:               "8.0 ГБ",
		frac(9.96, gib):       "9.9 ГБ",
		10*gib - 1:            "9.9 ГБ",
		frac(86.9, gib):       "86 ГБ",
		frac(1023.9, gib):     "1023 ГБ",
		tib + tib/2:           "1.5 ТБ",
		frac(12.7, tib):       "12 ТБ",
		maxInfoValue:          "4194304 ТБ",
		frac(1.25, gib):       "1.2 ГБ",
		frac(12.8, gib):       "12 ГБ",
		frac(1023.99, mib):    "1023 МБ",
		frac(9.999, tib) + 1:  "9.9 ТБ",
		frac(10.01, tib) + 1:  "10 ТБ",
		frac(0.999, mib) + 17: "<1 МБ",
	} {
		if got := fmtSize(n); got != want {
			t.Errorf("fmtSize(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestSubInfoText(t *testing.T) {
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.Local)
	day := int64(86400)
	e := func(d time.Duration) int64 { return now.Add(d).Unix() }

	i := info(t, hdr(4*gib, 10*gib, 100*gib, e(12*24*time.Hour+time.Hour)), now, now)
	if i.Summary != "Осталось 86 ГБ / 12 дней" || i.Level != "" || i.Percent != 86 || i.UsedPct != 14 || i.Warning != "" ||
		i.Details != "использовано 14 ГБ из 100 ГБ, до "+fmtDate(i.Expire) || i.UpDown != "↑ 4.0 ГБ ↓ 10 ГБ" || i.Left != 86*gib {
		t.Fatalf("%+v", i)
	}

	i = info(t, hdr(0, 92*gib, 100*gib, -1), now, now)
	if i.Level != "low" || i.Warning != "осталось 8.0 ГБ из 100 ГБ (8 %)" || i.Summary != "Осталось 8.0 ГБ" {
		t.Fatalf("%+v", i)
	}
	i = info(t, hdr(0, 100*gib-gib/2, 100*gib, -1), now, now)
	if i.Warning != "осталось 512 МБ из 100 ГБ (<1 %)" {
		t.Fatalf("%+v", i)
	}

	i = info(t, hdr(gib, 100*gib, 100*gib, e(3*24*time.Hour+time.Hour)), now, now)
	if i.Level != "out" || i.Summary != "Трафик закончился / осталось 3 дня" || i.Warning != "трафик закончился (использовано 101 ГБ из 100 ГБ)" || i.Percent != 0 || i.UsedPct != 100 {
		t.Fatalf("%+v", i)
	}

	i = info(t, hdr(0, 14*gib, 100*gib, e(2*24*time.Hour+time.Minute)), now, now)
	if i.Level != "low" || i.Warning != "срок заканчивается через 2 дня, "+fmtDateHour(i.Expire) || !strings.Contains(i.Warning, " в ") {
		t.Fatalf("%+v", i)
	}
	i = info(t, hdr(0, 14*gib, 100*gib, e(5*time.Hour+time.Minute)), now, now)
	if i.Summary != "Осталось 86 ГБ / 5 ч" || i.Warning != "срок заканчивается через 5 ч, "+fmtDateHour(i.Expire) {
		t.Fatalf("%+v", i)
	}
	i = info(t, hdr(0, 14*gib, 100*gib, e(20*time.Minute)), now, now)
	if i.Summary != "Осталось 86 ГБ / меньше часа" || i.Warning != "срок заканчивается меньше чем через час, "+fmtDateHour(i.Expire) {
		t.Fatalf("%+v", i)
	}

	i = info(t, hdr(0, 14*gib, 100*gib, e(-3*24*time.Hour)), now, now)
	end := fmtDate(i.Expire)
	if i.Level != "out" || i.Summary != "Осталось 86 ГБ / срок истёк "+end || i.Warning != "срок истёк "+end ||
		i.Details != "использовано 14 ГБ из 100 ГБ, закончилась "+end || i.SecondsLeft >= 0 {
		t.Fatalf("%+v", i)
	}

	i = info(t, hdr(0, 14*gib, 0, e(30*24*time.Hour+time.Hour)), now, now)
	if i.Summary != "Трафик без лимита / осталось 30 дней" || !i.Unlimited || i.Level != "" {
		t.Fatalf("%+v", i)
	}
	i = info(t, "expire="+strconv.FormatInt(e(12*24*time.Hour+time.Hour), 10), now, now)
	if i.Summary != "Осталось 12 дней" || i.UpDown != "" {
		t.Fatalf("%+v", i)
	}
	i = info(t, hdr(4*gib, 10*gib, -1, -1), now, now)
	if i.Summary != "Использовано 14 ГБ" || i.Details != "использовано 14 ГБ" || i.Percent != -1 {
		t.Fatalf("%+v", i)
	}
	i = info(t, hdr(4*gib, 10*gib, 100*gib, 0), now, now)
	if i.Summary != "Осталось 86 ГБ" || i.Details != "использовано 14 ГБ из 100 ГБ" || i.Expire != 0 || i.SecondsLeft != 0 {
		t.Fatalf("%+v", i)
	}
	if i := info(t, "expire=0", now, now); i != nil {
		t.Fatalf("nothing to show: %+v", i)
	}

	for n, want := range map[int64]string{1: "1 день", 2: "2 дня", 5: "5 дней", 11: "11 дней", 21: "21 день", 22: "22 дня", 112: "112 дней"} {
		if got := fmtLeft(n*day + 5); got != want {
			t.Errorf("%d days: %q", n, got)
		}
	}
}

func TestCleanTitleAndUpdateHours(t *testing.T) {
	for in, want := range map[string]string{
		"My VPN":                               "My VPN",
		"  a\r\n\tb  ":                         "a b",
		"x\x00\x07\x1by\u0085z":                "xy z", // NEL is a line break
		"ok\xff\xfe!":                          "ok!",
		"a\u202ab\u202bc\u202cd\u202de\u202ef": "abcdef",
		"a\u2066b\u2067c\u2068d\u2069e":        "abcde",
		"a\u200bb\u200cc\u200dd\u200ee\u200ff": "abcdef",
		"\ufeffBOM\u00adx":                     "BOMx",
		"p\ue000q\U000F0000r":                  "pqr",
		"a \u00a0\u3000 b":                     "a b",
	} {
		if got := cleanTitle(in); got != want {
			t.Errorf("cleanTitle(%q) = %q, want %q", in, got, want)
		}
	}
	long := strings.Repeat("я", 150)
	if got := cleanTitle(long); got != strings.Repeat("я", maxTitleRunes) {
		t.Errorf("%d runes", len([]rune(got)))
	}
	for in, want := range map[string]int{"12": 12, " 6 ": 6, "8760": 8760, "0": 0, "-1": 0, "abc": 0, "9999": 0, "1.5": 0, "": 0} {
		if got := parseUpdateHours(in); got != want {
			t.Errorf("%q: %d", in, got)
		}
	}
}

func TestSafeLink(t *testing.T) {
	for in, want := range map[string]string{
		"https://t.me/some_support":          "https://t.me/some_support",
		"http://panel.example:8080/help?x=1": "http://panel.example:8080/help?x=1",
		"HTTPS://Example.com/a b":            "",
		"https://example.com/путь":           "https://example.com/%D0%BF%D1%83%D1%82%D1%8C",
	} {
		if got := safeLink(in); got != want {
			t.Errorf("safeLink(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{
		"", "javascript:alert(1)", "file:///C:/x.exe", "tg://resolve?domain=x", "data:text/html,x", "ms-settings:network",
		`\\host\share`, `C:\x.exe`, "/relative/path", "t.me/x", "https:///path", "https://user:pw@example.com/",
		"https://example.com/a b", `https://example.com/"x"`, "https://example.com/<x>", "https://example.com/\r\nX: y",
		"https://example.com/\u202e", "https://example.com/{x}", "https://example.com/a|b", "https://example.com/a^b", "https://example.com/`",
		"https://t.me/" + strings.Repeat("a", maxLinkLen), "https://example.com/\xff",
	} {
		if got := safeLink(bad); got != "" {
			t.Errorf("safeLink(%q) = %q", bad, got)
		}
	}
}

