package nft

import (
	"strings"
	"testing"
)

func TestGuardScript(t *testing.T) {
	s, err := GuardScript([]string{"br-lan", "br-guest"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"table inet hyrouter_guard {", "hook forward", `iifname { "br-lan", "br-guest" }`, "reject"} {
		if !strings.Contains(s, want) {
			t.Errorf("no %q in\n%s", want, s)
		}
	}
	if _, err := GuardScript([]string{`br-lan" accept;`}); err == nil {
		t.Error("an interface name that breaks the script was taken")
	}
	if _, err := GuardScript(nil); err == nil {
		t.Error("a guard of no interfaces")
	}
}
