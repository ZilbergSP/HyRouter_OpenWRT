//go:build linux

package ctl

import (
	"slices"
	"strings"
	"testing"

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
