package zapret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNFT(t *testing.T) {
	plans := map[Target]Plan{
		YouTube: {Methods: []string{"fake", "seqovl"}, Circular: true},
		Discord: {Methods: []string{"fake"}},
	}
	out, err := NFT(NFTConfig{WAN: []string{"wan", "pppoe-wan"}, Queue: QueueFor(plans), Probes: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"type filter hook postrouting priority 101; policy accept;",
		"meta mark & 0x40000000 != 0 return",
		`oifname != { "wan", "pppoe-wan" } return`,
		"ip daddr @zapret_skip4 return",
		"ip6 daddr @zapret_skip6 return",
		"tcp sport 30000-31949 goto zapret_probe",
		"tcp dport { 80, 443, 2053, 2083, 2087, 2096, 8443 } ct original packets 1-20 meta mark set meta mark | 0x20000000 queue num 200 bypass",
		"udp dport { 443, 19294-19344, 50000-50100 } ct original packets 1-5 meta mark set meta mark | 0x20000000 queue num 200 bypass",
		"tcp sport 30150-30299 ct original packets 1-20 meta mark set meta mark | 0x20000000 queue num 201 bypass",
		"type filter hook prerouting priority -101; policy accept;",
		"tcp dport 30000-31949 goto zapret_probe_in",
		"tcp sport { 80, 443, 2053, 2083, 2087, 2096, 8443 } ct reply packets 1-10 queue num 200 bypass",
		"tcp dport 30150-30299 ct reply packets 1 queue num 201 bypass",
		"meta mark & 0x20000000 != 0 notrack",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
	// Slot 0 checks without a bypass: never queued.
	if strings.Contains(out, "port 30000-30149") {
		t.Error("slot 0 is queued")
	}
	if n := strings.Count(out, "queue num 2"); n != 3+2*(ProbeSlots-1) {
		t.Errorf("%d queue rules", n)
	}

	// A fixed method: only the SYN-ACK comes back, for autottl.
	fixed, err := NFT(NFTConfig{WAN: []string{"eth1"}, Queue: QueueFor(map[Target]Plan{YouTube: {Methods: []string{"fake-seqovl"}}})})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fixed, "tcp sport { 80, 443 } ct reply packets 1 queue num 200 bypass") ||
		!strings.Contains(fixed, "tcp dport 30000-31949 return") || strings.Contains(fixed, "zapret_probe") {
		t.Errorf("fixed:
%s", fixed)
	}

	// Bypass off, no pick: no queue at all; the probe range still skips.
	off, err := NFT(NFTConfig{WAN: []string{"eth1"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(off, "queue") || strings.Contains(off, "chain zapret_pre {") || !strings.Contains(off, "tcp sport 30000-31949 return") {
		t.Errorf("bypass off:\n%s", off)
	}

	for _, c := range []NFTConfig{
		{},
		{WAN: []string{`wan" } accept; #`}},
		{WAN: []string{"a-very-long-interface"}},
		{WAN: []string{"wan"}, Queue: Queue{TCP: []string{"443; accept"}}},
		{WAN: []string{"wan"}, Queue: Queue{UDP: []string{"0"}}},
		{WAN: []string{"wan"}, Queue: Queue{UDP: []string{"200-100"}}},
	} {
		if _, err := NFT(c); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
}

// TestNFTFiles writes the rules into whole tables for "nft -c -f": CI
// sets HYROUTER_NFT_DIR and checks every file with the kernel's nftables.
func TestNFTFiles(t *testing.T) {
	dir := os.Getenv("HYROUTER_NFT_DIR")
	if dir == "" {
		t.Skip("HYROUTER_NFT_DIR is set by CI, which checks the files with nft -c")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	all := map[Target]Plan{}
	for _, tg := range Targets {
		p, _ := Settings{Enabled: true, Targets: Targets}.PlanFor(tg, "")
		all[tg] = p
	}
	cases := map[string]NFTConfig{
		"full":  {WAN: []string{"eth1", "pppoe-wan"}, Queue: QueueFor(all), Probes: true},
		"fixed": {WAN: []string{"eth1"}, Queue: QueueFor(map[Target]Plan{YouTube: {Methods: []string{"fake"}}})},
		"off":   {WAN: []string{"eth1"}},
		"pick":  {WAN: []string{"eth1"}, Probes: true},
	}
	for name, c := range cases {
		body, err := NFT(c)
		if err != nil {
			t.Fatal(err)
		}
		table := "table inet hyrouter_test {\n" + body + "}\n"
		if err := os.WriteFile(filepath.Join(dir, name+".nft"), []byte(table), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
