package rules

import (
	"net/netip"
	"slices"
	"testing"
)

func TestPlan(t *testing.T) {
	c := Config{DefaultAction: Direct, Rules: []Rule{
		{Name: "tv", Devices: []string{"AA-BB-CC-DD-EE-01", "192.168.1.0/28"}, Action: Tunnel},
		{Name: "yt", Domains: []string{".youtube.com", "10.1.0.0/16"}, Protocol: "tcp", Ports: PortList{"443"}, Action: Tunnel, Profile: "p2"},
		{Name: "app", Apps: []AppMatch{{Pattern: "x.exe"}}, Action: Block},
		{Name: "ghost", Devices: []string{"dev:no-such-device"}, Action: Block},
	}}
	s, err := Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	s.Main = "p1"
	plan, def := s.Plan()
	if len(plan) != 4 || def.Action != Direct {
		t.Fatalf("%d rules, default %v", len(plan), def.Action)
	}
	mac, err := ParseMAC("aa:bb:cc:dd:ee:01")
	if err != nil {
		t.Fatal(err)
	}
	tv := plan[0]
	if tv.Never || !tv.Devices || !slices.Equal(tv.MACs, []MAC{mac}) || tv.Dest || tv.Route.Action != Tunnel || tv.Route.Profile != "p1" {
		t.Errorf("tv: %+v", tv)
	}
	if !slices.Equal(tv.Sources, []netip.Prefix{netip.MustParsePrefix("192.168.1.0/28")}) {
		t.Errorf("tv sources: %v", tv.Sources)
	}
	yt := plan[1]
	if yt.Pos != 1 || !yt.Dest || !yt.Sites || yt.Devices || yt.Proto != 6 || yt.Route.Profile != "p2" {
		t.Errorf("yt: %+v", yt)
	}
	if !slices.Equal(yt.Nets, []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}) || !slices.Equal(yt.Ports, []PortRange{{443, 443}}) {
		t.Errorf("yt nets %v, ports %v", yt.Nets, yt.Ports)
	}
	if !plan[2].Never || !plan[3].Never {
		t.Errorf("app never %v, ghost never %v", plan[2].Never, plan[3].Never)
	}
	if got := s.NameRules("WWW.YouTube.com."); !slices.Equal(got, []int{1}) {
		t.Errorf("NameRules(www.youtube.com) = %v", got)
	}
	if got := s.NameRules("example.com"); got != nil {
		t.Errorf("NameRules(example.com) = %v", got)
	}
}
