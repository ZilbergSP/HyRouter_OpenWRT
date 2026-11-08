package rules

import (
	"net/netip"
	"strings"
	"testing"
)

func mustMAC(t *testing.T, s string) MAC {
	t.Helper()
	m, err := ParseMAC(s)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestParseMAC(t *testing.T) {
	want := MAC{0xaa, 0xbb, 0xcc, 0x01, 0x02, 0x03}
	for _, s := range []string{"aa:bb:cc:01:02:03", "AA-BB-CC-01-02-03", "aabbcc010203", " aa:BB:cc:01:02:03 "} {
		m, err := ParseMAC(s)
		if err != nil || m != want {
			t.Errorf("ParseMAC(%q) = %v, %v", s, m, err)
		}
	}
	if got := want.String(); got != "aa:bb:cc:01:02:03" {
		t.Errorf("String = %q", got)
	}
	for _, s := range []string{"", "00:00:00:00:00:00", "aa:bb:cc:01:02", "aa:bb-cc:01:02:03", "aa:bb:cc:01:02:0g",
		"192.168.100.200", "aabb.cc01.0203", "aa:bb:cc:01:02:03:04"} {
		if m, err := ParseMAC(s); err == nil {
			t.Errorf("ParseMAC(%q) = %v, want an error", s, m)
		}
	}
}

func TestDeviceRules(t *testing.T) {
	tv := mustMAC(t, "aa:bb:cc:00:00:01")
	phone := mustMAC(t, "aa:bb:cc:00:00:02")
	set, err := Compile(Config{DefaultAction: Direct, Rules: []Rule{
		{Name: "ТВ", Devices: []string{"AA-BB-CC-00-00-01"}, Action: Tunnel, Profile: "de"},
		{Name: "Дети", Devices: []string{"192.168.1.16/28", "fd00::20"}, Domains: []string{"youtube.com"}, Action: Block},
		{Name: "YouTube", Domains: []string{"youtube.com"}, Action: Tunnel, Profile: "nl"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	dst := netip.MustParseAddrPort("203.0.113.5:443")
	cases := []struct {
		name string
		sub  Subject
		dom  string
		want Action
		prof string
	}{
		{"tv by MAC", Subject{Proto: 6, Dst: dst, MAC: tv}, "", Tunnel, "de"},
		{"tv by MAC, any site", Subject{Proto: 6, Dst: dst, MAC: tv}, "youtube.com", Tunnel, "de"},
		{"phone, other site", Subject{Proto: 6, Dst: dst, MAC: phone}, "example.com", Direct, ""},
		{"phone, youtube", Subject{Proto: 6, Dst: dst, MAC: phone}, "youtube.com", Tunnel, "nl"},
		{"child v4, youtube", Subject{Proto: 6, Dst: dst, Src: netip.MustParseAddr("192.168.1.20")}, "youtube.com", Block, ""},
		{"child v4-mapped", Subject{Proto: 6, Dst: dst, Src: netip.MustParseAddr("::ffff:192.168.1.30")}, "youtube.com", Block, ""},
		{"child v6", Subject{Proto: 6, Dst: dst, Src: netip.MustParseAddr("fd00::20")}, "youtube.com", Block, ""},
		{"outside the network", Subject{Proto: 6, Dst: dst, Src: netip.MustParseAddr("192.168.1.40")}, "youtube.com", Tunnel, "nl"},
		{"device unknown", Subject{Proto: 6, Dst: dst}, "youtube.com", Tunnel, "nl"},
	}
	for _, c := range cases {
		res := set.EvaluateDomain(c.sub, c.dom, SrcSNI)
		if res.Action != c.want || res.Profile != c.prof {
			t.Errorf("%s: got %v %q (rule %q), want %v %q", c.name, res.Action, res.Profile, res.Rule, c.want, c.prof)
		}
	}
	// A device rule decides at packet level: the TV never waits for a name.
	if res := set.Evaluate(Subject{Proto: 6, Dst: dst, MAC: tv}, nil); res.NeedsDomain || res.Action != Tunnel {
		t.Errorf("tv at packet level: %+v", res)
	}
	if res := set.Evaluate(Subject{Proto: 6, Dst: dst, MAC: phone}, nil); !res.NeedsDomain {
		t.Errorf("phone at packet level should need the name: %+v", res)
	}
}

func TestDeviceTable(t *testing.T) {
	t.Cleanup(func() { SetDevices(nil) })
	tv := mustMAC(t, "aa:bb:cc:00:00:01")
	SetDevices(DeviceTable{"tv": {MACs: []MAC{tv}, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.50/32")}}})
	cfg := Config{DefaultAction: Direct, Rules: []Rule{
		{Name: "ТВ", Devices: []string{"dev:tv"}, Action: Tunnel, Profile: "de"},
		{Name: "Пропавшее", Devices: []string{"DEV:gone"}, Action: Block},
	}}
	set, err := Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Warnings) != 1 || !strings.Contains(set.Warnings[0], "gone") {
		t.Errorf("warnings = %q, want one about the missing device", set.Warnings)
	}
	dst := netip.MustParseAddrPort("203.0.113.5:443")
	for _, sub := range []Subject{{Proto: 6, Dst: dst, MAC: tv}, {Proto: 17, Dst: dst, Src: netip.MustParseAddr("192.168.1.50")}} {
		if res := set.EvaluateNoDomain(sub); res.Action != Tunnel || res.Profile != "de" {
			t.Errorf("%+v: %+v", sub, res)
		}
	}
	// The rule of a missing device matches nothing, never every device.
	other := Subject{Proto: 6, Dst: dst, MAC: mustMAC(t, "aa:bb:cc:00:00:09"), Src: netip.MustParseAddr("192.168.1.9")}
	if res := set.EvaluateNoDomain(other); res.Action != Direct {
		t.Errorf("other device: %+v", res)
	}
	// The table is read at compile time.
	SetDevices(DeviceTable{})
	set, err = Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res := set.EvaluateNoDomain(Subject{Proto: 6, Dst: dst, MAC: tv}); res.Action != Direct {
		t.Errorf("tv after it left the table: %+v", res)
	}
}

func TestDeviceItems(t *testing.T) {
	if _, err := Compile(Config{Rules: []Rule{{Name: "x", Devices: []string{"aa:bb:cc:00:00:01"}, Action: Direct}}}); err != nil {
		t.Errorf("a device-only rule: %v", err)
	}
	for _, bad := range []string{"", "  ", "телевизор", "dev:", "aa:bb:cc", "192.168.1.300"} {
		_, err := Compile(Config{Rules: []Rule{{Name: "x", Devices: []string{bad}, Action: Direct}}})
		if err == nil {
			t.Errorf("device %q compiled", bad)
		}
	}
	if !IsDeviceRef("Dev:tv") || IsDeviceRef("aa:bb:cc:00:00:01") || IsDeviceRef("de") {
		t.Error("IsDeviceRef")
	}
}

func TestDeviceDuplicates(t *testing.T) {
	a := Rule{Name: "a", Devices: []string{"aa:bb:cc:00:00:01"}, Domains: []string{"youtube.com"}, Action: Tunnel}
	b := Rule{Name: "b", Devices: []string{"AA-BB-CC-00-00-01"}, Domains: []string{"youtube.com"}, Action: Tunnel}
	c := Rule{Name: "c", Devices: []string{"aa:bb:cc:00:00:02"}, Domains: []string{"youtube.com"}, Action: Tunnel}
	all := Rule{Name: "all", Domains: []string{"youtube.com"}, Action: Tunnel}
	if !SameMatch(a, b) || RepeatKey(a) != RepeatKey(b) {
		t.Error("the same MAC in two spellings should repeat")
	}
	for _, o := range []Rule{c, all} {
		if SameMatch(a, o) || RepeatKey(a) == RepeatKey(o) {
			t.Errorf("%s should not repeat a", o.Name)
		}
		if Duplicate(Config{Rules: []Rule{o}}, a, -1) != -1 {
			t.Errorf("Duplicate found %s for a", o.Name)
		}
	}
	if Intersects(a, c) {
		t.Error("rules of two MACs intersect")
	}
	ip := Rule{Name: "ip", Devices: []string{"192.168.1.20"}, Domains: []string{"youtube.com"}, Action: Block}
	if !Intersects(a, ip) || !Intersects(a, all) {
		t.Error("a MAC and an address may be one device; a rule without devices covers every one")
	}
}

func TestDeviceName(t *testing.T) {
	set, err := Compile(Config{DefaultAction: Direct, Rules: []Rule{
		{Name: "ТВ", Devices: []string{"aa:bb:cc:00:00:01"}, Domains: []string{"youtube.com"}, Action: Tunnel, Profile: "de"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	tv := Subject{MAC: mustMAC(t, "aa:bb:cc:00:00:01")}
	if r := set.EvaluateName(tv, "youtube.com", SrcQuery); r.Pos != 0 || r.Action != Tunnel {
		t.Errorf("tv asks: %+v", r)
	}
	if r := set.EvaluateName(Subject{MAC: mustMAC(t, "aa:bb:cc:00:00:02")}, "youtube.com", SrcQuery); r.Pos != 1 || len(r.Alt) != 0 {
		t.Errorf("another device asks: %+v", r)
	}
	if r := set.EvaluateName(Subject{}, "youtube.com", SrcQuery); r.Pos != 1 || len(r.Alt) != 1 || r.Alt[0].Cond&CondApp == 0 {
		t.Errorf("unknown device asks: %+v", r)
	}
}

func TestDeviceExplain(t *testing.T) {
	c := Config{DefaultAction: Direct, Rules: []Rule{
		{Name: "ТВ", Devices: []string{"aa:bb:cc:00:00:01"}, Action: Tunnel, Profile: "de"},
	}}
	q := Query{Domain: "example.com", IP: netip.MustParseAddr("203.0.113.5"), Proto: 6, Port: 443}
	q.Device = "AA-BB-CC-00-00-01"
	if ex := Explain(c, "", q); ex.Winner.Index != 0 || !strings.Contains(ex.Winner.Reason, "устройство") {
		t.Errorf("tv: %+v", ex.Winner)
	}
	q.Device = "192.168.1.9"
	if ex := Explain(c, "", q); ex.Winner.Index != -1 || !strings.Contains(ex.Steps[0].Reason, "не из правила") {
		t.Errorf("other device: %+v", ex.Steps[0])
	}
	q.Device = ""
	if ex := Explain(c, "", q); ex.Winner.Index != -1 || !strings.Contains(ex.Steps[0].Reason, "не указано") {
		t.Errorf("no device: %+v", ex.Steps[0])
	}
}
