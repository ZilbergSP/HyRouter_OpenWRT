//go:build keenetic

package platform

import (
	"encoding/json"
	"testing"
)

func TestHotspotHosts(t *testing.T) {
	// The shape of "show ip hotspot" (RCI), trimmed.
	raw := `{"host": [
		{"mac": "aa:bb:cc:dd:ee:01", "via": "aa:bb:cc:dd:ee:01", "ip": "192.168.1.33", "hostname": "android-1", "name": "Телефон", "registered": true, "active": true},
		{"mac": "aa:bb:cc:dd:ee:02", "ip": "0.0.0.0", "hostname": "tv", "name": ""},
		{"ip": "192.168.1.50"}
	]}`
	var r hotspot
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatal(err)
	}
	got := r.hosts()
	want := []Host{{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.1.33", Name: "Телефон"}, {MAC: "aa:bb:cc:dd:ee:02", Name: "tv"}}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("host %d: got %v, want %v", i, got[i], want[i])
		}
	}
}

func TestDNSUpstreamWithoutLAN(t *testing.T) {
	if got := DNSUpstream([]string{"no-such-if0"}); got != "127.0.0.1:53" {
		t.Errorf("got %q", got)
	}
}
