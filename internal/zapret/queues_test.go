package zapret

import (
	"errors"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseQueues(t *testing.T) {
	got := parseQueues("  200  12345     0 2 65531     0     0        0  1\n" +
		"  201  -4123     0 2 65531     0     0        0  1\n" +
		"  202 4294963173     0 2 65531     0     0        0  1\n" +
		"garbage\n\n")
	want := map[int]int64{200: 12345, 201: -4123, 202: 4294963173}
	if !maps.Equal(got, want) {
		t.Errorf("parseQueues: %v, want %v", got, want)
	}
}

func TestPickQueue(t *testing.T) {
	ours := func(q int, port int64) bool { return port != 2 } // port 2 is HyRouter's
	for _, c := range []struct {
		name  string
		bound map[int]int64
		want  int
	}{
		{"nothing bound", map[int]int64{}, 200},
		{"only ours", map[int]int64{200: 2, 201: 2}, 200},
		{"another bypass on 200", map[int]int64{200: 1}, 300},
		{"another on the last probe slot", map[int]int64{200 + ProbeSlots - 1: 1}, 300},
		{"another past the range", map[int]int64{200 + ProbeSlots: 1}, 200},
		{"200 and 305 taken", map[int]int64{200: 1, 201: 2, 305: 3}, 400},
	} {
		if got := PickQueue(c.bound, ours); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
	all := map[int]int64{}
	for q := 0; q <= 65535; q++ {
		all[q] = 1
	}
	if got := PickQueue(all, ours); got != QNumBypass {
		t.Errorf("every queue taken: %d", got)
	}
}

func TestFindHolder(t *testing.T) {
	old := procDir
	procDir = t.TempDir()
	t.Cleanup(func() { procDir = old })
	dir := filepath.Join(procDir, "4242")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte("4242 (nf (qws)) S 77 4242 4242 0 -1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/opt/usr/bin/nfqws (deleted)", filepath.Join(dir, "exe")); err != nil {
		t.Fatal(err)
	}
	h, ok := FindHolder(4242)
	if !ok || h != (Holder{PID: 4242, Name: "nf (qws)", Exe: "/opt/usr/bin/nfqws", Parent: 77}) {
		t.Errorf("FindHolder: %+v %v", h, ok)
	}
	for _, p := range []int64{0, -4123, 4294963173, 999} {
		if _, ok := FindHolder(p); ok {
			t.Errorf("FindHolder(%d) found a process", p)
		}
	}
}

func TestLeftovers(t *testing.T) {
	old := procDir
	procDir = t.TempDir()
	t.Cleanup(func() { procDir = old })
	proc := func(pid string, parent int, exe string) {
		dir := filepath.Join(procDir, pid)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		stat := pid + " (nfqws2) S " + strconv.Itoa(parent) + " 1 1 0 -1\n"
		if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(exe, filepath.Join(dir, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	const ours = "/opt/share/hyrouter/zapret/nfqws2"
	proc("100", 1, ours)              // left by an hyrouterd that is gone
	proc("101", 50, ours)             // this hyrouterd's (50)
	proc("102", 1, "/opt/bin/nfqws")  // another program's
	proc("103", 7, ours+" (deleted)") // left by an earlier package
	if err := os.MkdirAll(filepath.Join(procDir, "self"), 0o755); err != nil {
		t.Fatal(err)
	}
	var got []int
	for _, h := range Leftovers(ours, 50) {
		got = append(got, h.PID)
	}
	slices.Sort(got)
	if !slices.Equal(got, []int{100, 103}) {
		t.Errorf("Leftovers: %v, want [100 103]", got)
	}
}

func TestExitReasonQueueTaken(t *testing.T) {
	got := exitReason(errors.New("exit status 1"), []string{
		"binding this socket to queue '200'",
		"nfq_create_queue(): Operation not permitted",
		"closing nfq library handle",
	})
	if !strings.Contains(got, "занята другой программой") {
		t.Errorf("exitReason: %q", got)
	}
}

func TestQNum(t *testing.T) {
	plans := map[Target]Plan{YouTube: {Methods: []string{"fake"}, Circular: true}}
	c := NFTConfig{WAN: []string{"ppp0"}, Queue: QueueFor(plans), Probes: true, QNum: 300}
	out, err := NFT(c)
	if err != nil {
		t.Fatal(err)
	}
	p, err := IPT(c, true)
	if err != nil {
		t.Fatal(err)
	}
	rules := rulesOf(p, 4, "mangle") + "\n" + rulesOf(p, 6, "mangle")
	for _, s := range []string{out, rules} {
		if strings.Contains(s, " 200 ") || !strings.Contains(s, " 300 ") || !strings.Contains(s, " 301 ") ||
			!strings.Contains(s, " "+strconv.Itoa(300+ProbeSlots-1)+" ") || strings.Contains(s, " "+strconv.Itoa(300+ProbeSlots)+" ") {
			t.Errorf("the queues are not 300…%d:\n%s", 300+ProbeSlots-1, s)
		}
	}
	for _, q := range []int{-1, 65536 - ProbeSlots + 1} {
		c.QNum = q
		if _, err := NFT(c); err == nil {
			t.Errorf("NFT takes queue %d", q)
		}
		if _, err := IPT(c, false); err == nil {
			t.Errorf("IPT takes queue %d", q)
		}
	}
}

// TestQueueTaken: on the real kernel, another nfqws2 holds queue 200 (as
// zapret or nfqws-keenetic on a router does). BoundQueues and FindHolder
// name it, PickQueue moves to 300, and an nfqws2 started on 200 ends with
// the reason the page shows. Root and the zapret2 release of CI
// (HYROUTER_ZAPRET_DIR, as for TestNFQWS2DryRun).
func TestQueueTaken(t *testing.T) {
	src := os.Getenv("HYROUTER_ZAPRET_DIR")
	if src == "" || os.Geteuid() != 0 {
		t.Skip("root and HYROUTER_ZAPRET_DIR: CI only")
	}
	exe, err := filepath.EvalSymlinks(filepath.Join(src, "binaries", "linux-x86_64", "nfqws2"))
	if err != nil {
		t.Fatal(err)
	}
	other := exec.Command(exe, "--qnum=200")
	var out strings.Builder
	other.Stdout, other.Stderr = &out, &out
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		other.Process.Kill()
		other.Wait()
	})
	var bound map[int]int64
	for end := time.Now().Add(10 * time.Second); ; {
		if bound, err = BoundQueues(); err != nil {
			t.Fatal(err)
		}
		if _, ok := bound[200]; ok {
			break
		}
		if time.Now().After(end) {
			t.Fatalf("queue 200 not bound; nfqws2 wrote:\n%s", out.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	h, ok := FindHolder(bound[200])
	if !ok || h.PID != other.Process.Pid || h.Name != "nfqws2" || h.Exe != exe || h.Parent != os.Getpid() {
		t.Errorf("holder of 200: %+v %v (pid %d, %s)", h, ok, other.Process.Pid, exe)
	}
	if got := PickQueue(bound, func(int, int64) bool { return true }); got != 300 {
		t.Errorf("PickQueue: %d, want 300", got)
	}

	r := &Runner{Exe: exe}
	r.Start([]string{"--qnum=200"})
	defer r.Stop()
	for end := time.Now().Add(10 * time.Second); ; {
		st := r.Status()
		if st.State == Failed {
			if !strings.Contains(st.Error, "занята другой программой") {
				t.Errorf("error %q; nfqws2 wrote:\n%s", st.Error, strings.Join(st.Lines, "\n"))
			}
			break
		}
		if time.Now().After(end) {
			t.Fatalf("nfqws2 on a taken queue: %+v", st)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
