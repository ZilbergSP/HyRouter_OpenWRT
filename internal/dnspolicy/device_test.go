package dnspolicy

import (
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/zilbergsp/hyrouter/internal/rules"
)

// HyRouter: a rule for a device decides the names that device asks for,
// and only for it.
func TestClassifyDevice(t *testing.T) {
	set, err := rules.Compile(rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{
		{Name: "tv", Devices: []string{"192.168.1.20"}, Domains: []string{".video.example"}, Action: rules.Tunnel},
	}})
	if err != nil {
		t.Fatal(err)
	}
	set.Main = "p1"
	p, err := Compile(Config{ByRules: true}, Names{})
	if err != nil {
		t.Fatal(err)
	}
	q := Question{Name: "cdn.video.example", Type: dnsmessage.TypeA}
	env := Env{Rules: set}
	if d := p.Classify(q, Requester{Src: netip.MustParseAddr("192.168.1.20")}, env); d.Kind != Resolve || d.Via != ViaTunnel || d.Route.Profile != "p1" {
		t.Errorf("the tv's query: %+v", d)
	}
	if d := p.Classify(q, Requester{Src: netip.MustParseAddr("192.168.1.21")}, env); d.Kind != Pass {
		t.Errorf("another device's query: %+v", d)
	}
}
