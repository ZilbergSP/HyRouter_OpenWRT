package nft

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zilbergsp/hyrouter/internal/rules"
)

var testOptions = Options{LAN: []string{"br-lan"}, TunnelPort: 7701, NamePort: 7702, DNSPort: 7753}

func sample() rules.Config {
	return rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{
		{Name: "Телевизор", Devices: []string{"AA:BB:CC:DD:EE:01"}, Action: rules.Tunnel},
		{Name: "Старая программа", Apps: []rules.AppMatch{{Pattern: "x.exe"}}, Action: rules.Block},
		{Name: "YouTube", Domains: []string{".youtube.com", "2001:db8::/32"}, Protocol: "tcp", Ports: rules.PortList{"8000-8100", "443"}, Action: rules.Tunnel, Profile: "p2"},
		{Name: "Банк", Devices: []string{"192.168.1.20", "fd00::20"}, Domains: []string{"bank.example"}, Action: rules.Direct},
		{Name: "Реклама", Domains: []string{"ads.example", "203.0.113.0/24"}, Action: rules.Block},
		{Name: "SSH", Ports: rules.PortList{"22"}, Action: rules.Tunnel},
	}}
}

func compileConfig(t *testing.T, c rules.Config, main string, o Options) string {
	t.Helper()
	s, err := rules.Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	s.Main = main
	plan, def := s.Plan()
	script, err := Compile(plan, def, o)
	if err != nil {
		t.Fatal(err)
	}
	return script
}

// checkOrder fails unless every line of want is a line of script, in
// this order (leading and trailing blanks aside).
func checkOrder(t *testing.T, script string, want []string) {
	t.Helper()
	lines := strings.Split(script, "\n")
	i := 0
	for _, w := range want {
		for i < len(lines) && strings.TrimSpace(lines[i]) != w {
			i++
		}
		if i == len(lines) {
			t.Fatalf("line %q is missing or out of order in:\n%s", w, script)
		}
		i++
	}
}

func TestCompile(t *testing.T) {
	script := compileConfig(t, sample(), "p1", testOptions)
	checkOrder(t, script, []string{
		"table inet hyrouter",
		"delete table inet hyrouter",
		"table inet hyrouter {",
		"set r0_mac {",
		"elements = { aa:bb:cc:dd:ee:01 }",
		"set r2_net6 {",
		"elements = { 2001:db8::/32 }",
		"set r2_dns4 {",
		"flags timeout",
		"set r3_src4 {",
		"elements = { 192.168.1.20 }",
		"set r3_src6 {",
		"elements = { fd00::20 }",
		"set r4_net4 {",
		"elements = { 203.0.113.0/24 }",
		"chain prerouting_lan {",
		`iifname != { "br-lan" } return`,
		"ct mark & 0x07000000 == 0x01000000 return",
		"ct mark & 0x07000000 == 0x02000000 goto to_tunnel",
		"ct state != new return",
		"ip daddr @skip4 return",
		"# Телевизор",
		"ether saddr @r0_mac goto v_tunnel",
		"meta l4proto tcp th dport { 80, 443, 8080, 8443 } ip daddr @ambig4 goto v_name",
		"meta l4proto tcp th dport { 80, 443, 8080, 8443 } ip6 daddr @ambig6 goto v_name",
		"# YouTube",
		"meta l4proto tcp th dport { 443, 8000-8100 } ip6 daddr @r2_net6 goto v_tunnel",
		"meta l4proto tcp th dport { 443, 8000-8100 } ip daddr @r2_dns4 goto v_tunnel",
		"meta l4proto tcp th dport { 443, 8000-8100 } ip6 daddr @r2_dns6 goto v_tunnel",
		"# Банк",
		"ip saddr @r3_src4 ip daddr @r3_dns4 goto v_direct",
		"ip6 saddr @r3_src6 ip6 daddr @r3_dns6 goto v_direct",
		"# Реклама",
		"ip daddr @r4_net4 goto v_block",
		"ip daddr @r4_dns4 goto v_block",
		"ip6 daddr @r4_dns6 goto v_block",
		"# SSH",
		"meta l4proto { tcp, udp } th dport 22 goto v_tunnel",
		"# Всё остальное",
		"goto v_direct",
		"}",
		"chain v_tunnel {",
		"ct mark set ct mark & 0xf8ffffff | 0x02000000",
		"goto to_tunnel",
		"chain to_tunnel {",
		"meta l4proto tcp tproxy to :7701 meta mark set meta mark | 0x08000000 accept",
		"meta l4proto udp tproxy to :7701 meta mark set meta mark | 0x08000000 accept",
		"drop",
		"chain to_name {",
		"meta l4proto tcp tproxy to :7702 meta mark set meta mark | 0x08000000 accept",
		"chain forward_block {",
		"ct mark & 0x07000000 == 0x04000000 meta l4proto tcp reject with tcp reset",
		"chain dns_redirect {",
		"fib daddr type local meta l4proto { tcp, udp } th dport 53 redirect to :7753",
	})
	// The program rule matches nothing on a router: no sets, no lines.
	if strings.Contains(script, "r1_") || strings.Contains(script, "Старая программа") {
		t.Errorf("a program rule reached the script:\n%s", script)
	}
	// A source of one family is never paired with an address of the other.
	if strings.Contains(script, "ip saddr @r3_src4 ip6") || strings.Contains(script, "ip6 saddr @r3_src6 ip daddr") {
		t.Errorf("mixed families:\n%s", script)
	}
}

// A tunnel with no server is refused in the kernel: it never goes direct.
func TestTunnelWithoutServerBlocks(t *testing.T) {
	c := rules.Config{DefaultAction: rules.Tunnel, Rules: []rules.Rule{
		{Name: "tv", Devices: []string{"aa:bb:cc:dd:ee:02"}, Action: rules.Tunnel},
	}}
	script := compileConfig(t, c, "", testOptions)
	checkOrder(t, script, []string{"ether saddr @r0_mac goto v_block", "# Всё остальное", "goto v_block"})
	script = compileConfig(t, c, "p1", testOptions)
	checkOrder(t, script, []string{"ether saddr @r0_mac goto v_tunnel", "# Всё остальное", "goto v_tunnel"})
}

func TestCompileRefuses(t *testing.T) {
	s, err := rules.Compile(sample())
	if err != nil {
		t.Fatal(err)
	}
	plan, def := s.Plan()
	for name, o := range map[string]Options{
		"no LAN":        {TunnelPort: 1, NamePort: 2, DNSPort: 3},
		"bad name":      {LAN: []string{`br-lan" accept`}, TunnelPort: 1, NamePort: 2, DNSPort: 3},
		"long name":     {LAN: []string{"a-very-long-interface"}, TunnelPort: 1, NamePort: 2, DNSPort: 3},
		"no DNS port":   {LAN: []string{"br-lan"}, TunnelPort: 1, NamePort: 2},
		"no relay port": {LAN: []string{"br-lan"}, NamePort: 2, DNSPort: 3},
	} {
		if _, err := Compile(plan, def, o); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestExtraInsideTable(t *testing.T) {
	o := testOptions
	o.Extra = "\tchain zapret_post {\n\t}\n"
	script := compileConfig(t, sample(), "p1", o)
	checkOrder(t, script, []string{"chain dns_redirect {", "chain zapret_post {", "}"})
	if !strings.HasSuffix(script, "\t}\n}\n") {
		t.Errorf("the table does not end after the extra chains:\n%s", script)
	}
}

// TestNFTFiles writes scripts for `nft -c -f` in CI (HYROUTER_NFT_DIR).
func TestNFTFiles(t *testing.T) {
	dir := os.Getenv("HYROUTER_NFT_DIR")
	if dir == "" {
		t.Skip("HYROUTER_NFT_DIR is not set")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"hyrouter-sample.nft":         compileConfig(t, sample(), "p1", testOptions),
		"hyrouter-default-tunnel.nft": compileConfig(t, rules.Config{DefaultAction: rules.Tunnel}, "p1", testOptions),
		"hyrouter-no-server.nft":      compileConfig(t, sample(), "", Options{LAN: []string{"br-lan", "br-guest"}, TunnelPort: 7701, NamePort: 7702, DNSPort: 7753}),
	}
	for name, script := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
