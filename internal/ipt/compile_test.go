package ipt

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/zilbergsp/hyrouter/internal/rules"
)

var testOptions = Options{LAN: []string{"br0"}, TunnelPort: 7701, NamePort: 7702, DNSPort: 7753}

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

func compileConfig(t *testing.T, c rules.Config, main string, o Options, v6 bool) *Part {
	t.Helper()
	s, err := rules.Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	s.Main = main
	plan, def := s.Plan()
	p, err := Compile(plan, def, o, v6)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Check(OwnerRoute); err != nil {
		t.Fatal(err)
	}
	return p
}

func tableOf(t *testing.T, p *Part, fam int, name string) Table {
	t.Helper()
	i := slices.IndexFunc(p.Tables, func(x Table) bool { return x.Family == fam && x.Name == name })
	if i < 0 {
		t.Fatalf("no table %d/%s", fam, name)
	}
	return p.Tables[i]
}

// checkOrder fails unless every line of want is a rule of the table, in
// this order.
func checkOrder(t *testing.T, tb Table, want []string) {
	t.Helper()
	i := 0
	for _, w := range want {
		for i < len(tb.Rules) && tb.Rules[i] != w {
			i++
		}
		if i == len(tb.Rules) {
			t.Fatalf("rule %q is missing or out of order in:\n%s", w, strings.Join(tb.Rules, "\n"))
		}
		i++
	}
}

func TestCompile(t *testing.T) {
	p := compileConfig(t, sample(), "p1", testOptions, true)
	m4 := tableOf(t, p, 4, "mangle")
	checkOrder(t, m4, []string{
		"-A HYR_PRE -i br0 -g HYR_LAN",
		"-A HYR_LAN -m connmark --mark 0x10000000/0x70000000 -j RETURN",
		"-A HYR_LAN -m connmark --mark 0x20000000/0x70000000 -g HYR_TUNNEL",
		"-A HYR_LAN -m connmark --mark 0x30000000/0x70000000 -g HYR_NAME",
		"-A HYR_LAN -m connmark --mark 0x40000000/0x70000000 -j RETURN",
		"-A HYR_LAN -m conntrack ! --ctstate NEW -j RETURN",
		"-A HYR_LAN -m addrtype --dst-type LOCAL,BROADCAST,MULTICAST,ANYCAST -j RETURN",
		"-A HYR_LAN -m set --match-set hyr_skip4 dst -j RETURN",
		"# Телевизор",
		"-A HYR_LAN -m mac --mac-source aa:bb:cc:dd:ee:01 -g HYR_V_TUNNEL",
		"-A HYR_LAN -p tcp -m multiport --dports 80,443,8080,8443 -m set --match-set hyr_ambig4 dst -g HYR_V_NAME",
		"# YouTube",
		"-A HYR_LAN -m set --match-set hyr_r2_dns4 dst -p tcp -m multiport --dports 443,8000:8100 -g HYR_V_TUNNEL",
		"# Банк",
		"-A HYR_LAN -m set --match-set hyr_r3_src4 src -m set --match-set hyr_r3_dns4 dst -g HYR_V_DIRECT",
		"# Реклама",
		"-A HYR_LAN -m set --match-set hyr_r4_net4 dst -g HYR_V_BLOCK",
		"-A HYR_LAN -m set --match-set hyr_r4_dns4 dst -g HYR_V_BLOCK",
		"# SSH",
		"-A HYR_LAN -p tcp --dport 22 -g HYR_V_TUNNEL",
		"-A HYR_LAN -p udp --dport 22 -g HYR_V_TUNNEL",
		"# Всё остальное",
		"-A HYR_LAN -g HYR_V_DIRECT",
		"-A HYR_V_TUNNEL -j CONNMARK --set-xmark 0x20000000/0x70000000",
		"-A HYR_V_TUNNEL -g HYR_TUNNEL",
		"-A HYR_TUNNEL -p tcp -j TPROXY --on-port 7701 --tproxy-mark 0x80000000/0x80000000",
		"-A HYR_TUNNEL -p udp -j TPROXY --on-port 7701 --tproxy-mark 0x80000000/0x80000000",
		"-A HYR_TUNNEL -j DROP",
		"-A HYR_NAME -p tcp -j TPROXY --on-port 7702 --tproxy-mark 0x80000000/0x80000000",
	})
	m6 := tableOf(t, p, 6, "mangle")
	checkOrder(t, m6, []string{
		"-A HYR_LAN -m addrtype --dst-type LOCAL,MULTICAST,ANYCAST -j RETURN",
		"-A HYR_LAN -m set --match-set hyr_skip6 dst -j RETURN",
		"-A HYR_LAN -m mac --mac-source aa:bb:cc:dd:ee:01 -g HYR_V_TUNNEL",
		"-A HYR_LAN -p tcp -m multiport --dports 80,443,8080,8443 -m set --match-set hyr_ambig6 dst -g HYR_V_NAME",
		"-A HYR_LAN -m set --match-set hyr_r2_net6 dst -p tcp -m multiport --dports 443,8000:8100 -g HYR_V_TUNNEL",
		"-A HYR_LAN -m set --match-set hyr_r2_dns6 dst -p tcp -m multiport --dports 443,8000:8100 -g HYR_V_TUNNEL",
		"-A HYR_LAN -m set --match-set hyr_r3_src6 src -m set --match-set hyr_r3_dns6 dst -g HYR_V_DIRECT",
	})
	// A source of one family is never paired with an address of the other.
	for _, r := range m4.Rules {
		if strings.Contains(r, "6 ") && strings.Contains(r, "hyr_r") {
			t.Errorf("an IPv6 set in IPv4: %s", r)
		}
	}
	// The program rule matches nothing on a router.
	for _, tb := range p.Tables {
		for _, r := range tb.Rules {
			if strings.Contains(r, "hyr_r1_") || strings.Contains(r, "Старая программа") {
				t.Errorf("a program rule reached the rules: %s", r)
			}
		}
	}
	nat := tableOf(t, p, 4, "nat")
	checkOrder(t, nat, []string{
		"-A HYR_DNS -i br0 -m addrtype --dst-type LOCAL -p udp --dport 53 -j REDIRECT --to-ports 7753",
		"-A HYR_DNS -i br0 -m addrtype --dst-type LOCAL -p tcp --dport 53 -j REDIRECT --to-ports 7753",
	})
	f := tableOf(t, p, 4, "filter")
	checkOrder(t, f, []string{
		"-A HYR_FWD -m connmark --mark 0x40000000/0x70000000 -p tcp -j REJECT --reject-with tcp-reset",
		"-A HYR_FWD -m connmark --mark 0x40000000/0x70000000 -j DROP",
		"-A HYR_FWD -m connmark --mark 0x20000000/0x70000000 -j DROP",
		"-A HYR_FWD -m connmark --mark 0x30000000/0x70000000 -j DROP",
		"-A HYR_IN -m mark --mark 0x80000000/0x80000000 -j ACCEPT",
		"-A HYR_IN -i br0 -p udp --dport 7753 -j ACCEPT",
	})
	if !slices.Equal(f.Hooks, []Hook{{"FORWARD", "HYR_FWD"}, {"INPUT", "HYR_IN"}}) {
		t.Errorf("filter hooks: %v", f.Hooks)
	}
	sets := map[string]Set{}
	for _, s := range p.Sets {
		sets[s.Name] = s
	}
	for name, want := range map[string]Set{
		"skip4":    {Name: "skip4", Net: true, Family: 4, Elems: skip4},
		"r3_src4":  {Name: "r3_src4", Net: true, Family: 4, Elems: []string{"192.168.1.20"}},
		"r3_src6":  {Name: "r3_src6", Net: true, Family: 6, Elems: []string{"fd00::20"}},
		"r4_net4":  {Name: "r4_net4", Net: true, Family: 4, Elems: []string{"203.0.113.0/24"}},
		"r2_dns4":  {Name: "r2_dns4", Family: 4, Timeout: true},
		"ambig6":   {Name: "ambig6", Family: 6, Timeout: true},
		"r2_net6":  {Name: "r2_net6", Net: true, Family: 6, Elems: []string{"2001:db8::/32"}},
		"r0_dns4x": {},
	} {
		got, ok := sets[name]
		if want.Name == "" {
			if ok {
				t.Errorf("unexpected set %s", name)
			}
			continue
		}
		if !ok || got.Net != want.Net || got.Family != want.Family || got.Timeout != want.Timeout || !slices.Equal(got.Elems, want.Elems) {
			t.Errorf("set %s: got %+v, want %+v", name, got, want)
		}
	}
}

func TestCompileIPv4Only(t *testing.T) {
	p := compileConfig(t, sample(), "p1", testOptions, false)
	if fams := p.Families(); !slices.Equal(fams, []int{4}) {
		t.Errorf("families %v", fams)
	}
	for _, s := range p.Sets {
		if s.Family == 6 {
			t.Errorf("an IPv6 set without IPv6: %s", s.Name)
		}
	}
}

// A tunnel with no server is refused in the kernel: it never goes direct.
func TestTunnelWithoutServerBlocks(t *testing.T) {
	c := rules.Config{DefaultAction: rules.Tunnel, Rules: []rules.Rule{
		{Name: "tv", Devices: []string{"aa:bb:cc:dd:ee:02"}, Action: rules.Tunnel},
	}}
	p := compileConfig(t, c, "", testOptions, false)
	checkOrder(t, tableOf(t, p, 4, "mangle"), []string{"-A HYR_LAN -m mac --mac-source aa:bb:cc:dd:ee:02 -g HYR_V_BLOCK", "# Всё остальное", "-A HYR_LAN -g HYR_V_BLOCK"})
	p = compileConfig(t, c, "p1", testOptions, false)
	checkOrder(t, tableOf(t, p, 4, "mangle"), []string{"-A HYR_LAN -m mac --mac-source aa:bb:cc:dd:ee:02 -g HYR_V_TUNNEL", "# Всё остальное", "-A HYR_LAN -g HYR_V_TUNNEL"})
}

func TestCompileRefuses(t *testing.T) {
	s, err := rules.Compile(sample())
	if err != nil {
		t.Fatal(err)
	}
	plan, def := s.Plan()
	for name, o := range map[string]Options{
		"no LAN":        {TunnelPort: 1, NamePort: 2, DNSPort: 3},
		"bad name":      {LAN: []string{"br0 -j ACCEPT"}, TunnelPort: 1, NamePort: 2, DNSPort: 3},
		"long name":     {LAN: []string{"a-very-long-interface"}, TunnelPort: 1, NamePort: 2, DNSPort: 3},
		"no DNS port":   {LAN: []string{"br0"}, TunnelPort: 1, NamePort: 2},
		"no relay port": {LAN: []string{"br0"}, NamePort: 2, DNSPort: 3},
	} {
		if _, err := Compile(plan, def, o, true); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestPorts(t *testing.T) {
	var items []string
	for i := 1; i <= 16; i++ {
		items = append(items, fmt.Sprint(i))
	}
	got, err := Ports(items)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[1] != "16" || strings.Count(got[0], ",") != 14 {
		t.Errorf("16 ports: %q", got)
	}
	got, err = Ports([]string{"443", "19294-19344", "50000-50100"})
	if err != nil || !slices.Equal(got, []string{"443,19294:19344,50000:50100"}) {
		t.Errorf("ranges: %q %v", got, err)
	}
	for _, bad := range []string{"0", "70000", "10-5", "a", "1-"} {
		if _, err := Ports([]string{bad}); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

func TestAllAddresses(t *testing.T) {
	c := rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{
		{Name: "всё", Domains: []string{"0.0.0.0/0", "::/0"}, Action: rules.Block},
	}}
	p := compileConfig(t, c, "p1", testOptions, true)
	for _, s := range p.Sets {
		switch s.Name {
		case "r0_net4":
			if !slices.Equal(s.Elems, []string{"0.0.0.0/1", "128.0.0.0/1"}) {
				t.Errorf("r0_net4: %v", s.Elems)
			}
		case "r0_net6":
			if !slices.Equal(s.Elems, []string{"::/1", "8000::/1"}) {
				t.Errorf("r0_net6: %v", s.Elems)
			}
		}
	}
}

func TestPartCheck(t *testing.T) {
	ok := Part{Tables: []Table{{Family: 4, Name: "filter", Chains: []string{"HYR_X"}, Rules: []string{"-A HYR_X -j DROP"}, Hooks: []Hook{{"FORWARD", "HYR_X"}}}}}
	if err := ok.Check(OwnerRoute); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]Part{
		"foreign chain": {Tables: []Table{{Family: 4, Name: "filter", Chains: []string{"FORWARD"}}}},
		"foreign rule":  {Tables: []Table{{Family: 4, Name: "filter", Chains: []string{"HYR_X"}, Rules: []string{"-I FORWARD -j ACCEPT"}}}},
		"two lines":     {Tables: []Table{{Family: 4, Name: "filter", Chains: []string{"HYR_X"}, Rules: []string{"-A HYR_X -j DROP\n-F FORWARD"}}}},
		"bad hook":      {Tables: []Table{{Family: 4, Name: "filter", Chains: []string{"HYR_X"}, Hooks: []Hook{{"PREROUTING", "HYR_X"}}}}},
		"bad table":     {Tables: []Table{{Family: 4, Name: "raw"}}},
		"bad set":       {Sets: []Set{{Name: "a b", Family: 4}}},
		"bad element":   {Sets: []Set{{Name: "a", Family: 4, Elems: []string{"1.2.3.4 -exist"}}}},
		"guard's chain": {Tables: []Table{{Family: 4, Name: "filter", Chains: []string{"HYRG_FWD"}}}},
	} {
		if err := p.Check(OwnerRoute); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestGuard(t *testing.T) {
	p, err := Guard([]string{"br0", "br1"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Check(OwnerGuard); err != nil {
		t.Fatal(err)
	}
	checkOrder(t, tableOf(t, p, 4, "filter"), []string{
		"-A HYRG_FWD -i br0 -j REJECT --reject-with icmp-admin-prohibited",
		"-A HYRG_FWD -i br1 -j REJECT --reject-with icmp-admin-prohibited",
	})
	checkOrder(t, tableOf(t, p, 6, "filter"), []string{"-A HYRG_FWD -i br0 -j REJECT --reject-with icmp6-adm-prohibited"})
	if _, err := Guard(nil, true); err == nil {
		t.Error("a guard without LAN")
	}
}

// TestIPTFiles writes the rules for a check in CI (HYROUTER_IPT_DIR):
// <case>.ipset for "ipset restore", <case>-<family>-<table>.rules for
// "iptables-legacy-restore --test".
func TestIPTFiles(t *testing.T) {
	dir := os.Getenv("HYROUTER_IPT_DIR")
	if dir == "" {
		t.Skip("HYROUTER_IPT_DIR is not set")
	}
	WriteTestFiles(t, dir, "hyrouter-sample", compileConfig(t, sample(), "p1", testOptions, true))
	WriteTestFiles(t, dir, "hyrouter-default-tunnel", compileConfig(t, rules.Config{DefaultAction: rules.Tunnel}, "p1", testOptions, true))
	WriteTestFiles(t, dir, "hyrouter-no-server", compileConfig(t, sample(), "", Options{LAN: []string{"br0", "br1"}, TunnelPort: 7701, NamePort: 7702, DNSPort: 7753}, true))
	p := compileConfig(t, sample(), "p1", testOptions, true)
	f := tableOf(t, p, 6, "filter")
	f.Rules = append(f.Rules, DNS6Fallback(testOptions.LAN)...)
	f.Rules = append(f.Rules, Closed6(testOptions.LAN)...)
	WriteTestFiles(t, dir, "hyrouter-fallback6", &Part{Tables: []Table{f}})
	g, err := Guard([]string{"br0", "br1"}, true)
	if err != nil {
		t.Fatal(err)
	}
	WriteTestFiles(t, dir, "hyrouter-guard", g)
}

// WriteTestFiles writes a part's files (Part.Files) into dir.
func WriteTestFiles(t *testing.T, dir, name string, p *Part) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for f, data := range p.Files(name) {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
