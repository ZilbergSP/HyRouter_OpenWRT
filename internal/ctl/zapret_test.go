//go:build linux

package ctl

import (
	"slices"
	"strings"
	"testing"

	"github.com/zilbergsp/hyrouter/internal/rules"
	"github.com/zilbergsp/hyrouter/internal/store"
	"github.com/zilbergsp/hyrouter/internal/tgws"
	"github.com/zilbergsp/hyrouter/internal/zapret"
)

func TestCheckHosts(t *testing.T) {
	got := checkHosts(zapret.Checks(zapret.YouTube, nil))
	if !slices.Equal(got, []string{"www.youtube.com", "redirector.googlevideo.com", "i.ytimg.com"}) {
		t.Errorf("YouTube: %v", got)
	}
	got = checkHosts([]string{"https://a.example/x", "https://a.example/y", "::bad", "https://b.example:8443/"})
	if !slices.Equal(got, []string{"a.example", "b.example"}) {
		t.Errorf("checkHosts: %v", got)
	}
}

func TestQueueNote(t *testing.T) {
	if n := queueNote(zapret.QNumBypass, 0, ""); n != "" {
		t.Errorf("no holder: %q", n)
	}
	n := queueNote(300, 200, "nfqws (PID 1234)")
	for _, want := range []string{"Очередь NFQUEUE 200", "nfqws (PID 1234)", "очереди 300–312"} {
		if !strings.Contains(n, want) {
			t.Errorf("no %q in %q", want, n)
		}
	}
	if n := queueNote(zapret.QNumBypass, 205, "неизвестная программа"); strings.Contains(n, "взял очереди") {
		t.Errorf("every range taken, yet: %q", n)
	}
}

// «Telegram без VPN»: its rule comes with the switch, whether the DPI
// bypass is on or not, and names the bridge, which is no server to run.
func TestTelegramRule(t *testing.T) {
	if rs := zapretRules(zapret.Settings{Telegram: zapret.TelegramSettings{Enabled: true}}); len(rs) != 1 || rs[0].Profile != tgws.ProfileID {
		t.Fatalf("%+v", rs)
	}
	if rs := zapretRules(zapret.Settings{}); len(rs) != 0 {
		t.Fatalf("off: %+v", rs)
	}
	st := store.Defaults()
	st.Servers = append(st.Servers, server("srv-main"))
	st.Settings.Main = "srv-main"
	st.Rules = rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{telegramRule()}}
	cp, err := compile(st, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, is := range cp.issues {
		if strings.Contains(is, tgws.ProfileID) {
			t.Errorf("issue: %s", is)
		}
	}
	// The fallback (the main server) runs; the bridge is not a core.
	if len(cp.profiles) != 1 || cp.profiles[0].ID != "srv-main" {
		t.Errorf("profiles: %+v", cp.profiles)
	}
}
