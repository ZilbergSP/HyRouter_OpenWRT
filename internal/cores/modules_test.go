//go:build linux

package cores

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// The VLESS module: never downloaded before it is installed; installed by
// a button through RAM, to the flash when it has room, else kept in RAM;
// removed with its files. A core an earlier version downloaded counts as
// installed.
func TestModules(t *testing.T) {
	old := freeSpace
	flash := int64(0)
	dir, ram := t.TempDir(), t.TempDir()
	freeSpace = func(d string) int64 {
		if d == dir {
			return flash
		}
		return 1 << 30
	}
	t.Cleanup(func() { freeSpace = old })
	core := []byte("#!/bin/sh\necho xray\n")
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	w, _ := zw.Create("xray")
	w.Write(core)
	zw.Close()
	srv, _ := server(t, map[string][]byte{"/x.zip": zbuf.Bytes()})
	pinned, err := Pinned(Xray)
	if err != nil {
		t.Fatal(err)
	}
	c := Core{Version: pinned.Version, Assets: map[string]Asset{"test": {URL: srv.URL + "/x.zip", SHA256: sum(zbuf.Bytes()), Member: "xray"}}}
	in := &Installer{Dir: dir, Staging: ram, Arch: "test", Client: srv.Client()}
	ctx := context.Background()

	if in.Installed(Xray) {
		t.Fatal("installed before the button")
	}
	if _, err := in.Path(ctx, Xray); err != ErrNotInstalled {
		t.Fatalf("Path of a module not installed: %v", err)
	}
	if !in.Installed(Hysteria) {
		t.Error("a core that is no module counts as not installed")
	}

	// No room on the flash: it stays in RAM.
	if err := in.installModule(ctx, Xray, c); err != nil {
		t.Fatal(err)
	}
	if m := in.Module(Xray); !m.Installed || !m.RAM || m.Size != int64(len(core)) || m.Version != pinned.Version {
		t.Errorf("in RAM: %+v", m)
	}
	// Removed: nothing left, Path refuses again.
	if err := in.RemoveModule(Xray); err != nil {
		t.Fatal(err)
	}
	if m := in.Module(Xray); m.Installed || m.Size != 0 {
		t.Errorf("removed: %+v", m)
	}
	// Room on the flash: it goes there.
	flash = 1 << 30
	if err := in.installModule(ctx, Xray, c); err != nil {
		t.Fatal(err)
	}
	if m := in.Module(Xray); !m.Installed || m.RAM {
		t.Errorf("on the flash: %+v", m)
	}
	if _, err := os.Stat(filepath.Join(dir, fileName(Xray, pinned.Version))); err != nil {
		t.Error("not on the flash:", err)
	}

	// An earlier version's Xray (no modules.json) counts as installed; an
	// earlier version's Hysteria goes.
	old2 := t.TempDir()
	os.WriteFile(filepath.Join(old2, "xray-v26.1.1"), core, 0o755)
	os.WriteFile(filepath.Join(old2, "hysteria-app-v2.12.3"), core, 0o755)
	in2 := &Installer{Dir: old2}
	if !in2.Installed(Xray) {
		t.Error("an earlier Xray is not installed")
	}
	in2.Drop(Hysteria)
	if _, err := os.Stat(filepath.Join(old2, "hysteria-app-v2.12.3")); err == nil {
		t.Error("an earlier Hysteria stays")
	}
}
