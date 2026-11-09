package edition

import "testing"

func TestLimits(t *testing.T) {
	c := Current
	if c.DNSCache <= 0 || c.Relay <= 0 || c.Memory < 0 {
		t.Fatalf("%s: %+v", Name, c)
	}
	if Lite != (Package == "hyrouter-lite") || Lite == c.VLESS || Lite != (c.Memory > 0) {
		t.Fatalf("%s (%s): %+v", Name, Package, c)
	}
}
