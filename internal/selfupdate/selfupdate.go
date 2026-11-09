//go:build linux

// Package selfupdate finds a newer HyRouter for this router among the
// releases of its repository and installs it with the router's package
// manager: opkg on OpenWrt 24.10 and in Entware (KeeneticOS), apk on
// OpenWrt 25.x. The package is checked against the release's SHA256SUMS
// (and GitHub's digest) before the package manager sees it. The package
// manager stops hyrouterd while it upgrades the package, so it runs in a
// process of its own (Launch) that outlives hyrouterd; the new hyrouterd
// reads how it went (Result).
package selfupdate

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/zilbergsp/hyrouter/internal/release"
)

// Repo is HyRouter's repository.
const Repo = "ZilbergSP/HyRouter_OpenWRT"

// SumsName is the checksum list of a release.
const SumsName = "SHA256SUMS"

// Dir is where a package waits for its installation, and Marker and Log
// tell the next hyrouterd how it went (RAM: gone after a reboot).
var (
	Dir    = "/tmp/hyrouter/update"
	Marker = "/tmp/hyrouter/update.json"
	Log    = "/tmp/hyrouter/update.log"
)

// root is prepended to the package databases (tests).
var root = ""

// The package databases, in the order they are read.
var dbs = []struct{ path, manager string }{
	{"/opt/lib/opkg/status", "opkg"}, // Entware (KeeneticOS)
	{"/usr/lib/opkg/status", "opkg"}, // OpenWrt 24.10
	{"/lib/apk/db/installed", "apk"}, // OpenWrt 25.x
}

// Packages are HyRouter's package names.
var Packages = []string{"hyrouter", "hyrouter-lite", "hyrouter-keenetic", "hyrouter-keenetic-lite"}

// Installed is HyRouter's package as the package manager knows it.
type Installed struct {
	Manager string `json:"manager"` // opkg | apk
	Package string `json:"package"`
	Version string `json:"version"` // as packaged: 0.5.0-1, 0.5.0-r1
	Arch    string `json:"arch"`
}

// Find reads the package databases for HyRouter's package.
func Find() (Installed, error) {
	for _, db := range dbs {
		b, err := os.ReadFile(root + db.path)
		if err != nil {
			continue
		}
		parse := parseOpkg
		if db.manager == "apk" {
			parse = parseAPK
		}
		if in, ok := parse(b); ok {
			in.Manager = db.manager
			return in, nil
		}
	}
	return Installed{}, errors.New("пакет HyRouter не найден в базе opkg или apk: обновить можно только установленный пакет")
}

// paragraphs splits a package database into its entries' fields.
func paragraphs(b []byte, sep string) []map[string]string {
	var out []map[string]string
	cur := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		l := sc.Text()
		if strings.TrimSpace(l) == "" {
			if len(cur) > 0 {
				out = append(out, cur)
				cur = map[string]string{}
			}
			continue
		}
		if k, v, ok := strings.Cut(l, sep); ok && !strings.HasPrefix(l, " ") {
			cur[k] = strings.TrimSpace(v)
		}
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// parseOpkg reads opkg's status file: "Package:", "Version:",
// "Architecture:" and "Status: install user installed".
func parseOpkg(b []byte) (Installed, bool) {
	for _, p := range paragraphs(b, ":") {
		if isOurs(p["Package"]) && strings.HasSuffix(p["Status"], " installed") {
			return Installed{Package: p["Package"], Version: p["Version"], Arch: p["Architecture"]}, true
		}
	}
	return Installed{}, false
}

// parseAPK reads apk's installed database: "P:", "V:", "A:".
func parseAPK(b []byte) (Installed, bool) {
	for _, p := range paragraphs(b, ":") {
		if isOurs(p["P"]) {
			return Installed{Package: p["P"], Version: p["V"], Arch: p["A"]}, true
		}
	}
	return Installed{}, false
}

func isOurs(name string) bool {
	for _, p := range Packages {
		if name == p {
			return true
		}
	}
	return false
}

// AssetName is the package of version ("0.6.0") for this installation,
// as build/package.sh and build/apk.sh name it.
func AssetName(in Installed, version string) string {
	version = strings.TrimPrefix(version, "v")
	if in.Manager == "apk" {
		return fmt.Sprintf("%s-%s-r1_%s.apk", in.Package, version, in.Arch)
	}
	return fmt.Sprintf("%s_%s-1_%s.ipk", in.Package, version, in.Arch)
}

// Available is a newer HyRouter for this router.
type Available struct {
	Version   string    `json:"version"` // 0.6.0
	Notes     string    `json:"notes"`
	Published time.Time `json:"published"`
	Page      string    `json:"page"`
	Asset     string    `json:"asset"`
	Size      int64     `json:"size"`
	url       string
	sums      []string
}

// Check finds the newest release newer than current (hyrouterd's version)
// with a package for this installation. Betas count while the version in
// use is one (before 1.0 every release is).
func Check(ctx context.Context, c *release.Client, in Installed, current string) (Available, bool, error) {
	cur, err := release.Parse(current)
	if err != nil {
		return Available{}, false, fmt.Errorf("версия этой сборки (%s) не из выпуска: обновления не проверяются", current)
	}
	list, err := c.Releases(ctx, Repo)
	if err != nil {
		return Available{}, false, err
	}
	pre := cur.Major == 0 || cur.Pre != ""
	r, found := release.Latest(list, pre, func(tag string) bool { return strings.HasPrefix(tag, "v") })
	if !found || release.Compare(r.Tag, current) <= 0 {
		return Available{}, false, nil
	}
	name := AssetName(in, r.Tag)
	a, ok := r.Asset(name)
	if !ok {
		return Available{}, false, fmt.Errorf("в выпуске %s нет пакета %s", r.Tag, name)
	}
	var sums []string
	if s, ok := r.Asset(SumsName); ok {
		if b, err := c.Fetch(ctx, s.URL); err == nil {
			if v := release.SumFor(b, name); v != "" {
				sums = append(sums, v)
			}
		}
	}
	if d := a.SHA256(); d != "" {
		sums = append(sums, d)
	}
	if len(sums) == 0 {
		return Available{}, false, fmt.Errorf("у выпуска %s нет контрольной суммы пакета: обновление небезопасно", r.Tag)
	}
	return Available{Version: strings.TrimPrefix(r.Tag, "v"), Notes: r.Body, Published: r.Published, Page: r.Page,
		Asset: name, Size: a.Size, url: a.URL, sums: sums}, true, nil
}

// freeSpace is the room on the file system of dir (tests replace it).
var freeSpace = func(dir string) int64 {
	var st unix.Statfs_t
	for d := dir; ; d = filepath.Dir(d) {
		if err := unix.Statfs(d, &st); err == nil {
			return int64(st.Bavail) * int64(st.Bsize)
		}
		if d == filepath.Dir(d) {
			return 0
		}
	}
}

// Download fetches a's package into Dir and checks its SHA-256; the file.
func Download(ctx context.Context, c *release.Client, a Available, progress func(done, total int64)) (string, error) {
	if a.url == "" || len(a.sums) == 0 {
		return "", errors.New("обновление не проверено: нажмите «Проверить» ещё раз")
	}
	os.RemoveAll(Dir)
	if err := os.MkdirAll(Dir, 0o700); err != nil {
		return "", err
	}
	if need := a.Size + 4<<20; a.Size > 0 && freeSpace(Dir) < need {
		return "", fmt.Errorf("в памяти роутера (/tmp) нет %d МБ для пакета", need>>20)
	}
	path := filepath.Join(Dir, a.Asset)
	if _, err := c.Download(ctx, a.url, path, 64<<20, progress, a.sums...); err != nil {
		return "", err
	}
	return path, nil
}

// script upgrades the package from FILE with MANAGER, writing to LOG. It
// leaves the service's control group first (procd may stop a whole
// group with its service) and updates the package lists before (a new
// version may need a new dependency). Whatever happened, the service is
// started at the end: an upgrade that failed after the package's prerm
// stopped hyrouterd would leave the LAN without it (closed, with the
// kill switch at boot).
const script = `echo $$ >/sys/fs/cgroup/cgroup.procs 2>/dev/null
sleep 1
{
	echo "== $(date): $MANAGER: $FILE"
	if [ "$MANAGER" = apk ]; then
		apk update
		apk add --allow-untrusted "$FILE"
	else
		opkg update
		opkg install "$FILE"
	fi
	echo "== exit $?"
	for s in /opt/etc/init.d/S99hyrouter /etc/init.d/hyrouter; do
		if [ -x "$s" ]; then
			"$s" start
			break
		fi
	done
} >>"$LOG" 2>&1
rm -f "$FILE"
`

// marker is what Launch leaves for the next hyrouterd.
type marker struct {
	From string    `json:"from"`
	To   string    `json:"to"`
	At   time.Time `json:"at"`
}

// Launch starts the upgrade from file (a package Download checked) in a
// session of its own, which the package manager's stop of hyrouterd does
// not end, and leaves Marker for the next hyrouterd.
func Launch(in Installed, file, from, to string) error {
	b, _ := json.Marshal(marker{From: from, To: to, At: time.Now()})
	if err := os.WriteFile(Marker, b, 0o600); err != nil {
		return err
	}
	os.Remove(Log)
	cmd := exec.Command("/bin/sh", "-c", script)
	cmd.Env = append(os.Environ(), "MANAGER="+in.Manager, "FILE="+file, "LOG="+Log)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		os.Remove(Marker)
		return err
	}
	go cmd.Wait() // reaped while this hyrouterd still runs
	return nil
}

// Result is how the last upgrade went, for the page.
type Result struct {
	From  string    `json:"from"`
	To    string    `json:"to"`
	At    time.Time `json:"at"`
	OK    bool      `json:"ok"`
	Done  bool      `json:"done"`  // false: the package manager still works
	Lines []string  `json:"lines"` // the end of its output when it failed
}

// pending is how long an upgrade may take before it counts as failed.
const pending = 10 * time.Minute

// ReadResult tells how the upgrade Launch started went, seen from
// hyrouterd of version current (nil: none was started). A finished one's
// Marker is removed: it is told once.
func ReadResult(current string) *Result {
	b, err := os.ReadFile(Marker)
	if err != nil {
		return nil
	}
	var m marker
	if json.Unmarshal(b, &m) != nil {
		os.Remove(Marker)
		return nil
	}
	r := &Result{From: m.From, To: m.To, At: m.At}
	log, _ := os.ReadFile(Log)
	exit, ended := lastExit(log)
	switch {
	case release.Compare(current, m.To) >= 0 && current != m.From:
		r.OK, r.Done = true, true
	case ended && exit != "0", time.Since(m.At) > pending:
		r.Done, r.Lines = true, tail(log, 15)
	default:
		return r // the package manager still works
	}
	os.Remove(Marker)
	return r
}

// lastExit is the status the script logged last ("== exit N").
func lastExit(log []byte) (string, bool) {
	lines := strings.Split(strings.TrimSpace(string(log)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if s, ok := strings.CutPrefix(lines[i], "== exit "); ok {
			return strings.TrimSpace(s), true
		}
	}
	return "", false
}

func tail(b []byte, n int) []string {
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	if len(lines) == 1 && lines[0] == "" {
		return nil
	}
	return lines
}
