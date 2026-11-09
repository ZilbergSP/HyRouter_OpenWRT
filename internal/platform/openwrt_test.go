//go:build !keenetic

package platform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadLeases(t *testing.T) {
	p := filepath.Join(t.TempDir(), "leases")
	data := "1700000000 aa:bb:cc:dd:ee:01 192.168.1.20 phone 01:aa:bb:cc:dd:ee:01\n" +
		"1700000000 aa:bb:cc:dd:ee:02 192.168.1.21 * *\n" +
		"broken line\n"
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	got := readLeases(p)
	want := []Host{{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.1.20", Name: "phone"}, {MAC: "aa:bb:cc:dd:ee:02", IP: "192.168.1.21"}}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("host %d: got %v, want %v", i, got[i], want[i])
		}
	}
	if readLeases(filepath.Join(t.TempDir(), "none")) != nil {
		t.Error("a missing file gives hosts")
	}
}
