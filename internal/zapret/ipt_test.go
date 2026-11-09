package zapret

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/zilbergsp/hyrouter/internal/ipt"
)

func rulesOf(p ipt.Part, fam int, table string) string {
	i := slices.IndexFunc(p.Tables, func(t ipt.Table) bool { return t.Family == fam && t.Name == table })
	if i < 0 {
		return ""
	}
	return strings.Join(p.Tables[i].Rules, "\n")
}

func TestIPT(t *testing.T) {
	plans := map[Target]Plan{
		YouTube: {Methods: []string{"fake", "seqovl"}, Circular: true},
		Discord: {Methods: []string{"fake"}},
	}
	skip := []netip.Addr{netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("2001:db8::7")}
	p, err := IPT(NFTConfig{WAN: []string{"eth3", "ppp0"}, Queue: QueueFor(plans), Probes: true, Skip: skip}, true)
	if err != nil {
		t.Fatal(err)
	}
	m4 := rulesOf(p, 4, "mangle")
	for _, want := range []string{
		"-A HYR_ZPOST -o eth3 -g HYR_ZOUT",
		"-A HYR_ZPOST -o ppp0 -g HYR_ZOUT",
		"-A HYR_ZOUT -m mark --mark 0x40000000/0x40000000 -j RETURN",
		"-A HYR_ZOUT -m set --match-set hyr_zskip4 dst -j RETURN",
		"-A HYR_ZOUT -p tcp --sport 30000:31949 -g HYR_ZPROBE",
		"-A HYR_ZOUT -p tcp -m multiport --dports 80,443,2053,2083,2087,2096,8443 -m connbytes --connbytes 1:20 --connbytes-mode packets --connbytes-dir original -j NFQUEUE --queue-num 200 --queue-bypass",
		"-A HYR_ZOUT -p udp -m multiport --dports 443,19294:19344,50000:50100 -m connbytes --connbytes 1:5 --connbytes-mode packets --connbytes-dir original -j NFQUEUE --queue-num 200 --queue-bypass",
		"-A HYR_ZPROBE -p tcp --sport 30150:30299 -m connbytes --connbytes 1:20 --connbytes-mode packets --connbytes-dir original -j NFQUEUE --queue-num 201 --queue-bypass",
		"-A HYR_ZIN -i eth3 -g HYR_ZREPLY",
		"-A HYR_ZFWD -i ppp0 -g HYR_ZREPLY",
		"-A HYR_ZREPLY -m set --match-set hyr_zskip4 src -j RETURN",
		"-A HYR_ZREPLY -p tcp --dport 30000:31949 -g HYR_ZPROBE_IN",
		"-A HYR_ZREPLY -p tcp -m multiport --sports 80,443,2053,2083,2087,2096,8443 -m connbytes --connbytes 1:10 --connbytes-mode packets --connbytes-dir reply -j NFQUEUE --queue-num 200 --queue-bypass",
		"-A HYR_ZPROBE_IN -p tcp --dport 30150:30299 -m connbytes --connbytes 1:1 --connbytes-mode packets --connbytes-dir reply -j NFQUEUE --queue-num 201 --queue-bypass",
	} {
		if !strings.Contains(m4+"\n", want+"\n") {
			t.Errorf("no %q in\n%s", want, m4)
		}
	}
	// Slot 0 checks without a bypass: never queued.
	if strings.Contains(m4, "30000:30149") {
		t.Error("slot 0 is queued")
	}
	if !strings.Contains(rulesOf(p, 6, "mangle"), "-A HYR_ZOUT -m set --match-set hyr_zskip6 dst -j RETURN") {
		t.Error("no IPv6 rules")
	}
	if got := rulesOf(p, 4, "nat"); got != "-A HYR_ZNAT -o eth3 -p udp -m mark --mark 0x40000000/0x40000000 -j MASQUERADE\n-A HYR_ZNAT -o ppp0 -p udp -m mark --mark 0x40000000/0x40000000 -j MASQUERADE" {
		t.Errorf("nat:\n%s", got)
	}
	for _, s := range p.Sets {
		switch s.Name {
		case "zskip4":
			if !slices.Equal(s.Elems, []string{"198.51.100.7"}) {
				t.Errorf("zskip4 %v", s.Elems)
			}
		case "zskip6":
			if !slices.Equal(s.Elems, []string{"2001:db8::7"}) {
				t.Errorf("zskip6 %v", s.Elems)
			}
		default:
			t.Errorf("set %s", s.Name)
		}
	}

	// A fixed method: only the SYN-ACK comes back, no probes.
	fixed, err := IPT(NFTConfig{WAN: []string{"eth3"}, Queue: QueueFor(map[Target]Plan{YouTube: {Methods: []string{"fake-seqovl"}}})}, false)
	if err != nil {
		t.Fatal(err)
	}
	f4 := rulesOf(fixed, 4, "mangle")
	if !strings.Contains(f4, "-A HYR_ZREPLY -p tcp -m multiport --sports 80,443 -m connbytes --connbytes 1:1 --connbytes-mode packets --connbytes-dir reply -j NFQUEUE --queue-num 200 --queue-bypass") ||
		!strings.Contains(f4, "-A HYR_ZOUT -p tcp --sport 30000:31949 -j RETURN") || strings.Contains(f4, "HYR_ZPROBE") {
		t.Errorf("fixed:\n%s", f4)
	}
	if rulesOf(fixed, 6, "mangle") != "" {
		t.Error("IPv6 rules without IPv6")
	}

	// Bypass off, no pick: no queue, no answers, no NAT.
	off, err := IPT(NFTConfig{WAN: []string{"eth3"}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if o := rulesOf(off, 4, "mangle"); strings.Contains(o, "NFQUEUE") || strings.Contains(o, "HYR_ZREPLY") || rulesOf(off, 4, "nat") != "" {
		t.Errorf("off:\n%s", o)
	}

	for name, c := range map[string]NFTConfig{
		"no WAN":   {},
		"bad WAN":  {WAN: []string{"eth3 -j ACCEPT"}},
		"bad port": {WAN: []string{"eth3"}, Queue: Queue{TCP: []string{"443,80"}}},
	} {
		if _, err := IPT(c, true); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// TestIPTFiles writes the bypass's rules for a check in CI
// (HYROUTER_IPT_DIR), as internal/ipt does for the routing.
func TestIPTFiles(t *testing.T) {
	dir := os.Getenv("HYROUTER_IPT_DIR")
	if dir == "" {
		t.Skip("HYROUTER_IPT_DIR is not set")
	}
	plans := map[Target]Plan{YouTube: {Methods: []string{"fake", "seqovl"}, Circular: true}, Discord: {Methods: []string{"fake"}}}
	p, err := IPT(NFTConfig{WAN: []string{"eth3", "ppp0"}, Queue: QueueFor(plans), Probes: true, Skip: []netip.Addr{netip.MustParseAddr("198.51.100.7")}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for f, data := range p.Files("zapret") {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
