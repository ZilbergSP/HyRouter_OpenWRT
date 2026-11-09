//go:build linux

package cores

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func TestPinned(t *testing.T) {
	for name, archs := range map[string][]string{Hysteria: {"amd64", "arm64", "mipsle", "arm"}, Xray: {"amd64", "arm64"}} {
		c, err := Pinned(name)
		if err != nil {
			t.Fatal(err)
		}
		if c.Version == "" {
			t.Errorf("%s: no version", name)
		}
		for _, arch := range archs {
			a, ok := c.Assets[arch]
			if !ok || !strings.HasPrefix(a.URL, "https://github.com/") || len(a.SHA256) != 64 {
				t.Errorf("%s for %s: %+v", name, arch, a)
			}
		}
	}
	if _, err := Pinned("no-such-core"); err == nil {
		t.Error("an unknown core was found")
	}
}

// server serves the files of files by path and counts the requests.
func server(t *testing.T, files map[string][]byte) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		b, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestInstall(t *testing.T) {
	ctx := context.Background()
	core := []byte("#!/bin/sh\necho core\n")
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	w, err := zw.Create("xray")
	if err != nil {
		t.Fatal(err)
	}
	w.Write(core)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	srv, hits := server(t, map[string][]byte{"/core": core, "/core.zip": zbuf.Bytes()})
	dir := t.TempDir()
	in := &Installer{Dir: dir, Arch: "test", Client: srv.Client()}

	plain := Core{Version: "app/v1", Assets: map[string]Asset{"test": {URL: srv.URL + "/core", SHA256: sum(core)}}}
	p, err := in.install(ctx, Hysteria, plain)
	if err != nil {
		t.Fatal(err)
	}
	if p != filepath.Join(dir, "hysteria-app-v1") {
		t.Errorf("path %s", p)
	}
	if st, err := os.Stat(p); err != nil || st.Mode()&0o111 == 0 {
		t.Fatalf("installed core: %v, %v", st, err)
	}
	if _, err := in.install(ctx, Hysteria, plain); err != nil || hits.Load() != 1 {
		t.Errorf("installed again: %v, %d downloads", err, hits.Load())
	}

	// A newer version replaces the older one.
	newer := Core{Version: "app/v2", Assets: plain.Assets}
	if _, err := in.install(ctx, Hysteria, newer); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Error("the older version was kept")
	}

	// The core inside a zip.
	zipped := Core{Version: "v9", Assets: map[string]Asset{"test": {URL: srv.URL + "/core.zip", SHA256: sum(zbuf.Bytes()), Member: "xray"}}}
	p, err = in.install(ctx, Xray, zipped)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(p); err != nil || !bytes.Equal(b, core) {
		t.Errorf("core from the zip: %q, %v", b, err)
	}

	// A wrong sum installs nothing and leaves nothing behind.
	bad := Core{Version: "v10", Assets: map[string]Asset{"test": {URL: srv.URL + "/core", SHA256: strings.Repeat("0", 64)}}}
	if _, err := in.install(ctx, "other", bad); err == nil {
		t.Error("a file with a wrong sum was installed")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "other") || strings.HasPrefix(e.Name(), ".") {
			t.Errorf("left behind: %s", e.Name())
		}
	}

	if _, err := (&Installer{Dir: dir, Arch: "sparc"}).install(ctx, Hysteria, plain); err == nil {
		t.Error("a core for another processor was installed")
	}
}

// With too little room in Dir the core goes to Spare.
func TestSpare(t *testing.T) {
	old := freeSpace
	freeSpace = func(string) int64 { return 1 << 20 }
	defer func() { freeSpace = old }()
	core := []byte("core")
	srv, _ := server(t, map[string][]byte{"/core": core})
	dir, spare := t.TempDir(), t.TempDir()
	in := &Installer{Dir: dir, Spare: spare, Arch: "test", Client: srv.Client()}
	p, err := in.install(context.Background(), Hysteria, Core{Version: "v1", Assets: map[string]Asset{"test": {URL: srv.URL + "/core", SHA256: sum(core)}}})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(p) != spare {
		t.Errorf("installed in %s, not in the spare %s", filepath.Dir(p), spare)
	}
}
