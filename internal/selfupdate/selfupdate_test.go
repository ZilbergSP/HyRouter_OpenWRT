//go:build linux

package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zilbergsp/hyrouter/internal/release"
)

const opkgStatus = `Package: ca-bundle
Version: 20240203-1
Status: install user installed
Architecture: all

Package: hyrouter-keenetic-lite
Version: 0.5.0-1
Depends: iptables, ipset, ca-bundle
Conflicts: hyrouter-keenetic
Status: install user installed
Architecture: mipsel-3.4
Conffiles:
 /opt/etc/init.d/S99hyrouter 1234
Installed-Time: 1794240000
`

const apkInstalled = `C:Q1abc=
P:busybox
V:1.37.0-r1
A:aarch64_cortex-a53

C:Q1def=
P:hyrouter
V:0.5.0-r1
A:aarch64_cortex-a53
S:4567
`

func TestFind(t *testing.T) {
	for _, c := range []struct {
		name, path, db string
		want           Installed
	}{
		{"Entware", "/opt/lib/opkg/status", opkgStatus, Installed{"opkg", "hyrouter-keenetic-lite", "0.5.0-1", "mipsel-3.4"}},
		{"OpenWrt 24.10", "/usr/lib/opkg/status", strings.ReplaceAll(strings.ReplaceAll(opkgStatus, "hyrouter-keenetic-lite", "hyrouter"), "mipsel-3.4", "x86_64"),
			Installed{"opkg", "hyrouter", "0.5.0-1", "x86_64"}},
		{"OpenWrt 25.x", "/lib/apk/db/installed", apkInstalled, Installed{"apk", "hyrouter", "0.5.0-r1", "aarch64_cortex-a53"}},
	} {
		root = t.TempDir()
		p := filepath.Join(root, c.path)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(c.db), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := Find()
		if err != nil || got != c.want {
			t.Errorf("%s: %+v %v, want %+v", c.name, got, err, c.want)
		}
	}
	root = t.TempDir()
	os.MkdirAll(filepath.Join(root, "usr/lib/opkg"), 0o755)
	os.WriteFile(filepath.Join(root, "usr/lib/opkg/status"), []byte("Package: hyrouter\nStatus: deinstall ok not-installed\n"), 0o644)
	if _, err := Find(); err == nil {
		t.Error("a removed package found")
	}
	root = ""
}

func TestAssetName(t *testing.T) {
	for _, c := range []struct {
		in   Installed
		want string
	}{
		{Installed{"opkg", "hyrouter", "0.5.0-1", "aarch64_cortex-a53"}, "hyrouter_0.6.0-1_aarch64_cortex-a53.ipk"},
		{Installed{"apk", "hyrouter-lite", "0.5.0-r1", "mipsel_24kc"}, "hyrouter-lite-0.6.0-r1_mipsel_24kc.apk"},
		{Installed{"opkg", "hyrouter-keenetic-lite", "0.5.0-1", "mipsel-3.4"}, "hyrouter-keenetic-lite_0.6.0-1_mipsel-3.4.ipk"},
	} {
		if got := AssetName(c.in, "v0.6.0"); got != c.want {
			t.Errorf("%+v: %s, want %s", c.in, got, c.want)
		}
	}
}

// fakeGitHub serves the releases of Repo with a package of each listed
// version and its SHA256SUMS.
func fakeGitHub(t *testing.T, pkg []byte, sumOf func(name string) string, releases ...string) *release.Client {
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/"+Repo+"/releases", func(w http.ResponseWriter, r *http.Request) {
		var list []map[string]any
		for _, v := range releases {
			name := "hyrouter_" + strings.TrimPrefix(v, "v") + "-1_x86_64.ipk"
			list = append(list, map[string]any{
				"tag_name": v, "prerelease": true, "body": "что нового в " + v, "html_url": srv.URL + "/page/" + v,
				"assets": []map[string]any{
					{"name": name, "browser_download_url": srv.URL + "/dl/" + name, "size": len(pkg)},
					{"name": SumsName, "browser_download_url": srv.URL + "/sums/" + v},
				},
			})
		}
		json.NewEncoder(w).Encode(list)
	})
	mux.HandleFunc("/sums/{v}", func(w http.ResponseWriter, r *http.Request) {
		name := "hyrouter_" + strings.TrimPrefix(r.PathValue("v"), "v") + "-1_x86_64.ipk"
		w.Write([]byte(sumOf(name) + "  " + name + "\n"))
	})
	mux.HandleFunc("/dl/{name}", func(w http.ResponseWriter, r *http.Request) { w.Write(pkg) })
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &release.Client{API: srv.URL}
}

func TestCheckAndDownload(t *testing.T) {
	pkg := []byte("the package")
	h := sha256.Sum256(pkg)
	good := hex.EncodeToString(h[:])
	in := Installed{"opkg", "hyrouter", "0.5.0-1", "x86_64"}
	c := fakeGitHub(t, pkg, func(string) string { return good }, "v0.4.0", "v0.6.0", "v0.5.1")
	ctx := context.Background()

	a, ok, err := Check(ctx, c, in, "0.5.0")
	if err != nil || !ok || a.Version != "0.6.0" || a.Asset != "hyrouter_0.6.0-1_x86_64.ipk" || a.Notes != "что нового в v0.6.0" {
		t.Fatalf("Check: %+v %v %v", a, ok, err)
	}
	if _, ok, err := Check(ctx, c, in, "0.6.0"); ok || err != nil {
		t.Errorf("up to date: %v %v", ok, err)
	}
	if _, _, err := Check(ctx, c, in, "dev"); err == nil {
		t.Error("a development build checks for updates")
	}

	Dir = t.TempDir()
	path, err := Download(ctx, c, a, nil)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != string(pkg) || filepath.Base(path) != a.Asset {
		t.Errorf("downloaded %s: %q", path, b)
	}

	// A package that does not match its sum never reaches the disk.
	bad := fakeGitHub(t, pkg, func(string) string { return strings.Repeat("0", 64) }, "v0.6.0")
	a, ok, err = Check(ctx, bad, in, "0.5.0")
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	if _, err := Download(ctx, bad, a, nil); err == nil {
		t.Error("a package with a wrong sum was taken")
	}
	if ents, _ := os.ReadDir(Dir); len(ents) != 0 {
		t.Errorf("left in %s: %v", Dir, ents)
	}

	// No sum: no update.
	none := fakeGitHub(t, pkg, func(string) string { return "" }, "v0.6.0")
	if _, ok, err := Check(ctx, none, in, "0.5.0"); ok || err == nil {
		t.Errorf("an update without a sum: %v %v", ok, err)
	}
	// No package for this router.
	if _, ok, err := Check(ctx, c, Installed{"opkg", "hyrouter", "0.5.0-1", "mips_24kc"}, "0.5.0"); ok || err == nil {
		t.Errorf("an update without a package: %v %v", ok, err)
	}
}

func TestReadResult(t *testing.T) {
	dir := t.TempDir()
	Marker, Log = filepath.Join(dir, "update.json"), filepath.Join(dir, "update.log")
	put := func(at time.Time, log string) {
		b, _ := json.Marshal(marker{From: "0.5.0", To: "0.6.0", At: at})
		os.WriteFile(Marker, b, 0o600)
		os.WriteFile(Log, []byte(log), 0o600)
	}
	if r := ReadResult("0.5.0"); r != nil {
		t.Errorf("no marker: %+v", r)
	}

	put(time.Now(), "== now: opkg: x\nUpgrading hyrouter\n")
	if r := ReadResult("0.5.0"); r == nil || r.Done {
		t.Errorf("still installing: %+v", r)
	}
	if _, err := os.Stat(Marker); err != nil {
		t.Error("the marker of an upgrade under way is gone")
	}

	if r := ReadResult("0.6.0"); r == nil || !r.OK || !r.Done {
		t.Errorf("upgraded: %+v", r)
	}
	if _, err := os.Stat(Marker); err == nil {
		t.Error("the marker of a finished upgrade stays")
	}

	put(time.Now(), "== now: opkg: x\nCollected errors:\n * no space left\n== exit 255\nHyRouter is running\n")
	r := ReadResult("0.5.0")
	if r == nil || r.OK || !r.Done || !strings.Contains(strings.Join(r.Lines, "\n"), "no space left") {
		t.Errorf("failed: %+v", r)
	}

	put(time.Now().Add(-time.Hour), "")
	if r := ReadResult("0.5.0"); r == nil || r.OK || !r.Done {
		t.Errorf("never finished: %+v", r)
	}
}
