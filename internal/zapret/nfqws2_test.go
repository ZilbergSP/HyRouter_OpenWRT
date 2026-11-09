package zapret

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

// TestNFQWS2DryRun runs the real nfqws2 with --dry-run on every command
// line HyRouter builds: each library method alone, generated strategies
// (the neighbors of every library method and a spread over the whole
// space), the circular plan with generated ones in it, for all targets and
// own sites by name and by address, as root and dropping to a user.
// nfqws2 checks its options and files and exits; a line it does not accept
// fails the test. CI downloads the zapret2 release pinned in
// build/deps.json, checks its sums and sets HYROUTER_ZAPRET_DIR to the
// unpacked zapret2-<version> folder.
func TestNFQWS2DryRun(t *testing.T) {
	src := os.Getenv("HYROUTER_ZAPRET_DIR")
	if src == "" {
		t.Skip("HYROUTER_ZAPRET_DIR is set by CI: the unpacked zapret2 release")
	}
	exe := filepath.Join(src, "binaries", "linux-x86_64", "nfqws2")
	// The layout hyrouterd installs: lua/ and blobs/ in one folder. nfqws2
	// started as root runs as another user once its queue is open and
	// rereads the lists then: the folder must be open to everyone, unlike
	// t.TempDir's.
	dir, err := os.MkdirTemp("", "hyrouter-zapret-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range LuaFiles {
		copyFile(t, filepath.Join(src, "lua", f), filepath.Join(dir, "lua", f))
	}
	for _, f := range BlobFiles {
		copyFile(t, filepath.Join(src, "files", "fake", f), filepath.Join(dir, "blobs", f))
	}
	// Own sites by name and by address (documentation networks).
	sites := []string{"example.com", "example.org", "192.0.2.0/24", "2001:db8::/32"}
	lists := filepath.Join(dir, "lists")
	if err := WriteLists(lists, sites, []netip.Addr{netip.MustParseAddr("192.0.2.1")}); err != nil {
		t.Fatal(err)
	}

	type run struct {
		name  string
		plans map[Target]Plan
		user  string
	}
	var runs []run
	alone := func(name, id string) {
		plans := map[Target]Plan{}
		for _, tg := range Targets {
			plans[tg] = Plan{Methods: []string{id}}
		}
		runs = append(runs, run{name: name, plans: plans})
	}
	for _, m := range Methods {
		alone(m.ID, m.ID)
	}
	var gen []string
	add := func(s Strategy) {
		if id := s.ID(); !slices.Contains(gen, id) {
			gen = append(gen, id)
		}
	}
	for _, m := range Methods {
		if s, ok := AsStrategy(m.ID); ok {
			for _, n := range Neighbors(s) {
				add(n)
			}
		}
	}
	for _, s := range Broad(48, 1) {
		add(s)
	}
	for _, id := range gen {
		alone(id, id)
	}
	t.Logf("%d library methods, %d generated strategies", len(Methods), len(gen))
	// A pick's result: generated strategies first, then the library.
	circular := map[Target]Plan{}
	for _, tg := range Targets {
		s := Settings{Enabled: true, Targets: Targets, Picked: map[string]Picked{"net": {
			Methods: map[Target]string{tg: gen[0]}, Working: map[Target][]string{tg: gen[:6]}}}}
		p, _ := s.PlanFor(tg, "net")
		circular[tg] = p
	}
	runs = append(runs, run{name: "circular", plans: circular})
	if os.Geteuid() == 0 {
		// Dropping root takes root (initgroups): hyrouterd runs as root.
		runs = append(runs, run{name: "circular as nobody", plans: circular, user: "nobody"})
	}

	for _, r := range runs {
		args, err := Build(BuildConfig{Dir: dir, Lists: lists, Plans: r.plans, Sites: sites, QNum: QNumBypass, User: r.user})
		if err != nil {
			t.Fatalf("%s: %v", r.name, err)
		}
		out, err := exec.Command(exe, append([]string{"--dry-run"}, args...)...).CombinedOutput()
		if err != nil {
			t.Errorf("%s: nfqws2 refused it: %v\n%s\n%s", r.name, err, CommandLine(args), out)
		}
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o644); err != nil {
		t.Fatal(err)
	}
}
