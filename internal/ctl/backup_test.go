//go:build linux

package ctl

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zilbergsp/hyrouter/internal/hysteria"
	"github.com/zilbergsp/hyrouter/internal/rules"
	"github.com/zilbergsp/hyrouter/internal/store"
)

func newTestController(t *testing.T) (*Controller, *store.Store) {
	t.Helper()
	st := &store.Store{Dir: t.TempDir()}
	c := New(Options{Store: st})
	if err := c.Load(); err != nil {
		t.Fatal(err)
	}
	return c, st
}

// A backup restores what it holds; the files of before come back with
// «Вернуть как было».
func TestBackupRestoreUndo(t *testing.T) {
	ctx := context.Background()
	src, srcStore := newTestController(t)
	no := false
	if err := srcStore.SaveServers([]hysteria.Profile{{ID: "srv-a", Name: "NL", Host: "nl.example", Ports: "443", Auth: "pass", TLS: hysteria.TLS{CA: "/nonexistent/ca.pem"}}}); err != nil {
		t.Fatal(err)
	}
	if err := srcStore.SaveRules(rules.Config{DefaultAction: rules.Tunnel, Rules: []rules.Rule{
		{Name: "всё напрямую", Ports: rules.PortList{"1-65535"}, Action: rules.Direct},
		{Name: "выключено", Ports: rules.PortList{"443"}, Action: rules.Direct, Enabled: &no},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := src.Load(); err != nil {
		t.Fatal(err)
	}
	b, err := src.Backup()
	if err != nil {
		t.Fatal(err)
	}
	var bk Backup
	if err := json.Unmarshal(b, &bk); err != nil || bk.Format != BackupFormat || len(bk.Files) == 0 {
		t.Fatalf("backup %s: %v", b, err)
	}

	dst, dstStore := newTestController(t)
	if err := dstStore.SaveDevices([]store.Device{{ID: "tv", Name: "Телевизор"}}); err != nil {
		t.Fatal(err)
	}
	if err := dst.Load(); err != nil {
		t.Fatal(err)
	}
	plan, err := dst.PlanRestore(b)
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(plan.Warnings, "\n")
	if plan.Servers != 1 || plan.Rules != 2 || !strings.Contains(all, "«всё напрямую»") || strings.Contains(all, "«выключено»") || !strings.Contains(all, "/nonexistent/ca.pem") {
		t.Fatalf("plan %+v", plan)
	}
	if err := dst.Restore(ctx, plan.Token); err != nil {
		t.Fatal(err)
	}
	if err := dst.Restore(ctx, plan.Token); err == nil {
		t.Error("a plan was taken twice")
	}
	got := dst.State()
	if len(got.Servers) != 1 || got.Servers[0].Auth != "pass" || got.Servers[0].TLS.CA != "" || len(got.Devices) != 0 {
		t.Fatalf("restored %+v", got)
	}
	if got.Settings.DeviceID == src.State().Settings.DeviceID {
		t.Error("the router's ID came from the backup")
	}
	if u := dst.Undo(); u == nil || u.Partial {
		t.Fatalf("undo %+v", u)
	}
	if err := dst.UndoRestore(ctx); err != nil {
		t.Fatal(err)
	}
	got = dst.State()
	if len(got.Servers) != 0 || len(got.Devices) != 1 || dst.Undo() != nil {
		t.Fatalf("after undo %+v", got)
	}
	if _, err := os.Stat(filepath.Join(dstStore.Dir, store.ServersFile)); !os.IsNotExist(err) {
		t.Errorf("servers.json of the restore stayed: %v", err)
	}
}

func TestPlanRestoreRefuses(t *testing.T) {
	c, _ := newTestController(t)
	for _, b := range []string{`{}`, `{"format":"hyroute"}`, `not json`, `{"format":"hyrouter-backup","version":99}`,
		`{"format":"hyrouter-backup","version":1,"files":{"servers.json":"broken"}}`} {
		if _, err := c.PlanRestore([]byte(b)); err == nil {
			t.Errorf("%s was taken", b)
		}
	}
}
