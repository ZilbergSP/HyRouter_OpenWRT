//go:build linux

package cores

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zilbergsp/hyrouter/internal/release"
)

// releases serves a core's releases (repo) at /repos/<repo>/releases: one
// release per tag with asset and its checksum file, and the files.
func releases(t *testing.T, repo, asset string, files map[string][]byte, sums func(tag string, b []byte) (name string, body []byte), tags ...string) *release.Client {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/"+repo+"/releases", func(w http.ResponseWriter, r *http.Request) {
		var list []map[string]any
		for _, tag := range tags {
			sumName, _ := sums(tag, files[tag])
			list = append(list, map[string]any{
				"tag_name": tag, "body": "notes " + tag, "html_url": srv.URL + "/page",
				"assets": []map[string]any{
					{"name": asset, "browser_download_url": srv.URL + "/dl/" + strings.ReplaceAll(tag, "/", "_")},
					{"name": sumName, "browser_download_url": srv.URL + "/sum/" + strings.ReplaceAll(tag, "/", "_")},
				},
			})
		}
		json.NewEncoder(w).Encode(list)
	})
	mux.HandleFunc("/dl/{tag}", func(w http.ResponseWriter, r *http.Request) {
		w.Write(files[strings.ReplaceAll(r.PathValue("tag"), "_", "/")])
	})
	mux.HandleFunc("/sum/{tag}", func(w http.ResponseWriter, r *http.Request) {
		tag := strings.ReplaceAll(r.PathValue("tag"), "_", "/")
		_, body := sums(tag, files[tag])
		w.Write(body)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &release.Client{API: srv.URL}
}

// fakeVersion: a test core is a text file that names its version.
func fakeVersion(_, path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(string(b), "core ") {
		return "", errors.New("does not start")
	}
	return strings.TrimPrefix(strings.TrimSpace(string(b)), "core "), nil
}

func TestCoreUpdate(t *testing.T) {
	old := freeSpace
	freeSpace = func(string) int64 { return 1 << 30 }
	t.Cleanup(func() { freeSpace = old })
	ctx := context.Background()
	dir := t.TempDir()
	in := &Installer{Dir: dir, Arch: "test", Version: fakeVersion}
	pinnedBody := []byte("core app/v2.12.3\n")
	pinned := Core{Version: "app/v2.12.3", Assets: map[string]Asset{"test": {
		URL: "https://example.invalid/releases/download/app%2Fv2.12.3/hysteria-linux-test", SHA256: sum(pinnedBody)}}}
	files := map[string][]byte{
		"app/v2.13.0": []byte("core app/v2.13.0\n"),
		"app/v2.14.0": []byte("core app/v2.14.0\n"),
		"app/v3.0.0":  []byte("core app/v3.0.0\n"), // another major: never offered
		"app/v2.15.0": []byte("core app/v2.9.9\n"), // names another version
	}
	hashes := func(tag string, b []byte) (string, []byte) {
		return "hashes.txt", []byte(sum(b) + "  build/hysteria-linux-test\n")
	}
	c := releases(t, "apernet/hysteria", "hysteria-linux-test", files, hashes, "app/v2.13.0", "app/v3.0.0")
	pinnedPath := filepath.Join(dir, fileName(Hysteria, pinned.Version))
	os.WriteFile(pinnedPath, pinnedBody, 0o755)

	u, ok, err := in.check(ctx, c, Hysteria, pinned)
	if err != nil || !ok || u.Version != "app/v2.13.0" || u.Notes != "notes app/v2.13.0" {
		t.Fatalf("check: %+v %v %v", u, ok, err)
	}
	if err := in.install1(ctx, c, u, pinned.Version, nil); err != nil {
		t.Fatal(err)
	}
	in.mu.Lock()
	p := in.updated(Hysteria, pinned.Version)
	in.mu.Unlock()
	if p != filepath.Join(dir, "hysteria-app-v2.13.0") {
		t.Errorf("in use: %q", p)
	}
	inf := in.info(Hysteria, pinned)
	if !inf.Updated || inf.Version != "app/v2.13.0" || inf.Previous != "закреплённое app/v2.12.3" {
		t.Errorf("info: %+v", inf)
	}
	if _, ok, err := in.check(ctx, c, Hysteria, pinned); ok || err != nil {
		t.Errorf("up to date: %v %v", ok, err)
	}

	// The next one: the previous update is the rollback target.
	c = releases(t, "apernet/hysteria", "hysteria-linux-test", files, hashes, "app/v2.14.0")
	if u, _, err = in.check(ctx, c, Hysteria, pinned); err != nil {
		t.Fatal(err)
	}
	if err := in.install1(ctx, c, u, pinned.Version, nil); err != nil {
		t.Fatal(err)
	}
	if inf := in.info(Hysteria, pinned); inf.Version != "app/v2.14.0" || inf.Previous != "app/v2.13.0" {
		t.Errorf("after the second: %+v", inf)
	}
	if err := in.Rollback(Hysteria); err != nil {
		t.Fatal(err)
	}
	if inf := in.info(Hysteria, pinned); inf.Version != "app/v2.13.0" {
		t.Errorf("after the rollback: %+v", inf)
	}
	if _, err := os.Stat(pinnedPath); err != nil {
		t.Error("the pinned core was pruned")
	}

	// A core that names another version is refused and leaves nothing.
	c = releases(t, "apernet/hysteria", "hysteria-linux-test", files, hashes, "app/v2.15.0")
	if u, _, err = in.check(ctx, c, Hysteria, pinned); err != nil {
		t.Fatal(err)
	}
	if err := in.install1(ctx, c, u, pinned.Version, nil); err == nil {
		t.Error("a core that names another version was installed")
	}
	if _, err := os.Stat(filepath.Join(dir, "hysteria-app-v2.15.0")); err == nil {
		t.Error("the refused core stays")
	}

	// A wrong checksum: no update.
	bad := func(tag string, b []byte) (string, []byte) {
		return "hashes.txt", []byte(strings.Repeat("0", 64) + "  hysteria-linux-test\n")
	}
	c = releases(t, "apernet/hysteria", "hysteria-linux-test", files, bad, "app/v2.14.0")
	if u, _, err = in.check(ctx, c, Hysteria, pinned); err != nil {
		t.Fatal(err)
	}
	if err := in.install1(ctx, c, u, pinned.Version, nil); err == nil {
		t.Error("a core with a wrong sum was installed")
	}

	// A changed file is not run: the pinned core is.
	os.WriteFile(filepath.Join(dir, "hysteria-app-v2.13.0"), []byte("core evil\n"), 0o755)
	in.hashOK = nil
	if inf := in.info(Hysteria, pinned); inf.Updated || inf.Error == "" {
		t.Errorf("a changed core: %+v", inf)
	}

	// A HyRouter update pinning a newer core retires the downloads.
	os.WriteFile(filepath.Join(dir, "hysteria-app-v2.13.0"), files["app/v2.13.0"], 0o755)
	in.hashOK = nil
	in.mu.Lock()
	p = in.updated(Hysteria, "app/v2.13.0")
	in.mu.Unlock()
	if p != "" {
		t.Errorf("not retired: %q", p)
	}
	if err := in.Rollback(Hysteria); err == nil {
		t.Error("a rollback after the retirement")
	}
}

func TestXrayUpdate(t *testing.T) {
	old := freeSpace
	freeSpace = func(string) int64 { return 1 << 30 }
	t.Cleanup(func() { freeSpace = old })
	dir := t.TempDir()
	in := &Installer{Dir: dir, Arch: "test", Version: fakeVersion}
	pinned := Core{Version: "v26.10.31", Assets: map[string]Asset{"test": {
		URL: "https://example.invalid/releases/download/v26.10.31/Xray-linux-test.zip", SHA256: "x", Member: "xray"}}}
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	for name, body := range map[string]string{"xray": "core v26.11.20\n", "geoip.dat": "x", "LICENSE": "x"} {
		w, _ := zw.Create(name)
		w.Write([]byte(body))
	}
	zw.Close()
	files := map[string][]byte{"v26.11.20": zbuf.Bytes()}
	dgst := func(tag string, b []byte) (string, []byte) {
		return "Xray-linux-test.zip.dgst", []byte("MD5= 00\nSHA2-256= " + sum(b) + "\n")
	}
	c := releases(t, "XTLS/Xray-core", "Xray-linux-test.zip", files, dgst, "v26.11.20")
	u, ok, err := in.check(context.Background(), c, Xray, pinned)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	if err := in.install1(context.Background(), c, u, pinned.Version, nil); err != nil {
		t.Fatal(err)
	}
	if inf := in.info(Xray, pinned); !inf.Updated || inf.Version != "v26.11.20" {
		t.Errorf("info: %+v", inf)
	}
	ents, _ := os.ReadDir(dir)
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if strings.Join(names, " ") != "updates.json xray-v26.11.20" {
		t.Errorf("in the folder: %v", names)
	}
}
