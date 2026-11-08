package zapret

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestNFQWS2DryRun runs the real nfqws2 with --dry-run on every command
// line HyRouter builds: each method alone and the circular plan, for all
// targets, as root and dropping to a user. nfqws2 checks its options and
// files and exits; a line it does not accept fails the test. CI downloads
// the zapret2 release pinned in build/deps.json, checks its sums and sets
// HYROUTER_ZAPRET_DIR to the unpacked zapret2-<version> folder.
func TestNFQWS2DryRun(t *testing.T) {
	src := os.Getenv("HYROUTER_ZAPRET_DIR")
	if src == "" {
		t.Skip("HYROUTER_ZAPRET_DIR is set by CI: the unpacked zapret2 release")
	}
	exe := filepath.Join(src, "binaries", "linux-x86_64", "nfqws2")
	// The layout hyrouterd installs: lua/ and blobs/ in one folder.
	dir := t.TempDir()
	for _, f := range LuaFiles {
		copyFile(t, filepath.Join(src, "lua", f), filepath.Join(dir, "lua", f))
	}
	for _, f := range BlobFiles {
		copyFile(t, filepath.Join(src, "files", "fake", f), filepath.Join(dir, "blobs", f))
	}
	lists := filepath.Join(dir, "lists")
	if err := WriteLists(lists, []string{"example.com", "example.org"}, []netip.Addr{netip.MustParseAddr("192.0.2.1")}); err != nil {
		t.Fatal(err)
	}

	type run struct {
		name  string
		plans map[Target]Plan
		user  string
	}
	var runs []run
	for _, m := range Methods {
		plans := map[Target]Plan{}
		for _, tg := range Targets {
			plans[tg] = Plan{Methods: []string{m.ID}}
		}
		runs = append(runs, run{name: m.ID, plans: plans})
	}
	circular := map[Target]Plan{}
	for _, tg := range Targets {
		p, _ := Settings{Enabled: true, Targets: Targets}.PlanFor(tg, "")
		circular[tg] = p
	}
	runs = append(runs, run{name: "circular", plans: circular}, run{name: "circular as nobody", plans: circular, user: "nobody"})

	for _, r := range runs {
		args, err := Build(BuildConfig{Dir: dir, Lists: lists, Plans: r.plans, QNum: QNumBypass, User: r.user})
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
