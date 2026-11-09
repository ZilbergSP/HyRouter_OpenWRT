//go:build linux

package ctl

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/zilbergsp/hyrouter/internal/edition"
	"github.com/zilbergsp/hyrouter/internal/hysteria"
	"github.com/zilbergsp/hyrouter/internal/platform"
	"github.com/zilbergsp/hyrouter/internal/store"
	"github.com/zilbergsp/hyrouter/internal/subs"
)

// Subscriptions (docs/ARCHITECTURE.md, «Подписки»): a panel's link that
// lists servers. An update downloads it (directly, or through the main
// server when the panel does not answer), and merges its servers into
// servers.json keeping their IDs, so rules and groups keep pointing at the
// same servers. A server a subscription no longer lists stays while a
// rule, the main target or a group names it (marked «нет в подписке»).

var (
	subCheckEvery = time.Minute
	subRetry      = 30 * time.Minute // after a failed update
	subTimeout    = 45 * time.Second
)

// SubInput is a subscription as the web interface edits it. URL "" in an
// edit keeps the link.
type SubInput struct {
	URL       string `json:"url"`
	Name      string `json:"name"`
	IntervalH int    `json:"intervalH"`
	Enabled   bool   `json:"enabled"`
}

func (in *SubInput) check() error {
	in.URL = strings.TrimSpace(in.URL)
	in.Name = strings.TrimSpace(in.Name)
	if in.IntervalH < 0 || in.IntervalH > 24*7 {
		return errors.New("интервал обновления — от 1 часа до 7 дней или «вручную»")
	}
	if len([]rune(in.Name)) > 64 {
		return errors.New("название подписки — не длиннее 64 символов")
	}
	return nil
}

// fetcher downloads subscriptions as the router.
func (c *Controller) fetcher() *subs.Fetcher {
	return &subs.Fetcher{
		UserAgent: "HyRouter/" + c.version,
		Device: func(host string) subs.DeviceInfo {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			name, version, model := platform.System(ctx)
			return subs.DeviceInfo{HWID: subs.DeviceID(c.State().Settings.DeviceID, host), OS: name, OSVersion: version, Model: model}
		},
		Tunnel: func() subs.Dialer {
			id := c.memberFor(c.State().Settings.Main)
			if id == "" {
				return nil
			}
			ep := c.tunnels.Get(id)
			if ep == nil || !ep.Available() {
				return nil
			}
			return ep
		},
	}
}

func randomID(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func newServerID() string { return "srv-" + randomID(6) }

// usedIDs are the servers and groups the settings name: rules, the
// default route, the main target and the groups' members. A subscription
// keeps such a server when it no longer lists it.
func usedIDs(st *store.State) map[string]bool {
	m := map[string]bool{st.Settings.Main: true, st.Rules.DefaultProfile: true}
	for _, id := range st.Rules.DefaultFallback {
		m[id] = true
	}
	for _, r := range st.Rules.Rules {
		m[r.Profile] = true
		for _, id := range r.Fallback {
			m[id] = true
		}
	}
	for _, g := range st.Groups.Groups {
		for _, id := range g.Members {
			m[id] = true
		}
	}
	delete(m, "")
	return m
}

// saveSubs writes what a subscription edit changes.
func (c *Controller) saveSubs(st store.State) error {
	for _, f := range []func() error{
		func() error { return c.store.SaveServers(st.Servers) },
		func() error { return c.store.SaveGroups(st.Groups) },
		func() error { return c.store.SaveSubs(st.Subs) },
		func() error { return c.store.SaveSettings(st.Settings) },
	} {
		if err := f(); err != nil {
			return err
		}
	}
	return nil
}

// download fetches and parses a subscription. A body that does not parse
// is an error that says what the panel sent instead.
func (c *Controller) download(ctx context.Context, url string) (subs.FetchResult, subs.Links, error) {
	ctx, cancel := context.WithTimeout(ctx, subTimeout)
	defer cancel()
	res, err := c.fetcher().Fetch(ctx, url)
	if err != nil {
		return res, subs.Links{}, err
	}
	l, err := subs.Parse(res.Body)
	if err != nil {
		return res, l, subs.Explain(err, res)
	}
	if !edition.Current.VLESS {
		n := len(l.Profiles)
		l.Profiles = slices.DeleteFunc(l.Profiles, func(p hysteria.Profile) bool { return p.IsVLESS() })
		if skipped := n - len(l.Profiles); skipped > 0 {
			l.Warnings = append(l.Warnings, fmt.Sprintf("серверов VLESS пропущено: %d (в %s только Hysteria 2)", skipped, edition.Name))
		}
		if len(l.Profiles) == 0 {
			return res, l, fmt.Errorf("в подписке только серверы VLESS, а %s поддерживает только Hysteria 2", edition.Name)
		}
	}
	return res, l, nil
}

// applyDownload merges a downloaded subscription into st.
func applyDownload(st *store.State, i int, res subs.FetchResult, l subs.Links) subs.MergeStats {
	s := &st.Subs[i]
	used := usedIDs(st)
	var stats subs.MergeStats
	st.Servers, stats = subs.Merge(st.Servers, "sub:"+s.ID, l.Profiles, func(id string) bool { return used[id] }, newServerID)
	now := time.Now()
	s.LastUpdate, s.LastAttempt, s.LastError = now, now, ""
	s.Count, s.Ignored, s.Warnings = len(l.Profiles), l.Ignored, l.Warnings
	if errs := subs.FirstErrors(l); len(errs) > 0 {
		s.Warnings = append(s.Warnings, errs...)
	}
	s.UserInfo, s.InfoAt, s.Support, s.ViaVPN = res.UserInfo, res.At, res.Support, res.ViaVPN
	if res.UserInfo == "" {
		s.InfoAt = time.Time{}
	}
	return stats
}

// AddSub downloads a new subscription and adds it with its servers;
// nothing is added when the download fails or brings no server.
func (c *Controller) AddSub(ctx context.Context, in SubInput) (string, subs.MergeStats, error) {
	if err := in.check(); err != nil {
		return "", subs.MergeStats{}, &EditError{Refused, err}
	}
	for _, s := range c.State().Subs {
		if subs.SameURL(s.URL, in.URL) {
			return "", subs.MergeStats{}, &EditError{Refused, fmt.Errorf("эта подписка уже добавлена: «%s»", s.Name)}
		}
	}
	c.subMu.Lock()
	defer c.subMu.Unlock()
	res, l, err := c.download(ctx, in.URL)
	if err != nil {
		return "", subs.MergeStats{}, &EditError{Refused, err}
	}
	sub := store.Sub{ID: randomID(6), Name: in.Name, URL: in.URL, Enabled: in.Enabled, IntervalH: in.IntervalH}
	if sub.Name == "" {
		sub.Name = res.Title
	}
	if sub.Name == "" {
		sub.Name = strings.TrimSuffix(strings.TrimPrefix(subs.MaskURL(in.URL), "https://"), "/…")
	}
	c.redactor.SetGroup("sub:"+sub.ID, subs.Secrets(sub.URL)...)
	var stats subs.MergeStats
	err = c.Edit(ctx, func(st *store.State) error {
		st.Subs = append(st.Subs, sub)
		stats = applyDownload(st, len(st.Subs)-1, res, l)
		if st.Settings.Main == "" {
			for _, p := range st.Servers {
				if p.Source == "sub:"+sub.ID {
					st.Settings.Main = p.ID
					break
				}
			}
		}
		return nil
	}, c.saveSubs)
	if err != nil {
		c.redactor.SetGroup("sub:" + sub.ID)
		return "", stats, err
	}
	c.log.Info("subscription added", "subscription", sub.Name, "servers", len(l.Profiles))
	return sub.ID, stats, nil
}

// EditSub changes a subscription's name, link and schedule.
func (c *Controller) EditSub(ctx context.Context, id string, in SubInput) error {
	if err := in.check(); err != nil {
		return &EditError{Refused, err}
	}
	err := c.Edit(ctx, func(st *store.State) error {
		i := slices.IndexFunc(st.Subs, func(s store.Sub) bool { return s.ID == id })
		if i < 0 {
			return errors.New("подписка не найдена")
		}
		s := &st.Subs[i]
		if in.URL != "" {
			for _, o := range st.Subs {
				if o.ID != id && subs.SameURL(o.URL, in.URL) {
					return fmt.Errorf("эта ссылка уже в подписке «%s»", o.Name)
				}
			}
			s.URL = in.URL
		}
		if in.Name != "" {
			s.Name = in.Name
		}
		s.IntervalH, s.Enabled = in.IntervalH, in.Enabled
		return nil
	}, func(st store.State) error { return c.store.SaveSubs(st.Subs) })
	if err == nil && in.URL != "" {
		c.redactor.SetGroup("sub:"+id, subs.Secrets(in.URL)...)
	}
	return err
}

// UpdateSub downloads a subscription again and merges its servers. A
// failure is kept as the subscription's last error.
func (c *Controller) UpdateSub(ctx context.Context, id string) (subs.MergeStats, error) {
	c.subMu.Lock()
	defer c.subMu.Unlock()
	i := slices.IndexFunc(c.State().Subs, func(s store.Sub) bool { return s.ID == id })
	if i < 0 {
		return subs.MergeStats{}, &EditError{Refused, errors.New("подписка не найдена")}
	}
	sub := c.State().Subs[i]
	res, l, err := c.download(ctx, sub.URL)
	if err != nil {
		c.log.Warn("subscription not updated", "subscription", sub.Name, "err", err)
		c.Edit(ctx, func(st *store.State) error {
			if j := slices.IndexFunc(st.Subs, func(s store.Sub) bool { return s.ID == id }); j >= 0 {
				st.Subs[j].LastAttempt, st.Subs[j].LastError = time.Now(), err.Error()
				if res.UserInfo != "" {
					st.Subs[j].UserInfo, st.Subs[j].InfoAt = res.UserInfo, res.At
				}
			}
			return nil
		}, func(st store.State) error { return c.store.SaveSubs(st.Subs) })
		return subs.MergeStats{}, &EditError{Refused, err}
	}
	var stats subs.MergeStats
	err = c.Edit(ctx, func(st *store.State) error {
		j := slices.IndexFunc(st.Subs, func(s store.Sub) bool { return s.ID == id })
		if j < 0 {
			return errors.New("подписка удалена во время обновления")
		}
		stats = applyDownload(st, j, res, l)
		return nil
	}, c.saveSubs)
	if err == nil {
		c.log.Info("subscription updated", "subscription", sub.Name, "servers", len(l.Profiles), "added", stats.Added,
			"updated", stats.Updated, "removed", stats.Removed, "missingKept", stats.MissingKept)
	}
	return stats, err
}

// DeleteSub removes a subscription and its servers. A server the settings
// name stays, as one added by hand.
func (c *Controller) DeleteSub(ctx context.Context, id string) error {
	c.subMu.Lock()
	defer c.subMu.Unlock()
	err := c.Edit(ctx, func(st *store.State) error {
		i := slices.IndexFunc(st.Subs, func(s store.Sub) bool { return s.ID == id })
		if i < 0 {
			return errors.New("подписка не найдена")
		}
		st.Subs = slices.Delete(st.Subs, i, i+1)
		used := usedIDs(st)
		st.Servers = slices.DeleteFunc(st.Servers, func(p hysteria.Profile) bool {
			return p.Source == "sub:"+id && !used[p.ID]
		})
		for k := range st.Servers {
			if st.Servers[k].Source == "sub:"+id {
				st.Servers[k].Source, st.Servers[k].Missing = "", false
			}
		}
		for k := range st.Groups.Groups {
			g := &st.Groups.Groups[k]
			g.Subs = slices.DeleteFunc(g.Subs, func(s string) bool { return s == id })
		}
		return nil
	}, c.saveSubs)
	if err == nil {
		c.redactor.SetGroup("sub:" + id)
	}
	return err
}

// due reports a subscription whose automatic update is due.
func due(s store.Sub, now time.Time) bool {
	if !s.Enabled || s.IntervalH <= 0 {
		return false
	}
	every := time.Duration(s.IntervalH) * time.Hour
	if now.Sub(s.LastUpdate) < every {
		return false
	}
	return s.LastAttempt.IsZero() || now.Sub(s.LastAttempt) >= min(every, subRetry)
}

// runSubs updates the subscriptions that are due until ctx ends.
func (c *Controller) runSubs(ctx context.Context) {
	t := time.NewTicker(subCheckEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := time.Now()
		for _, s := range c.State().Subs {
			if ctx.Err() != nil {
				return
			}
			if due(s, now) {
				c.UpdateSub(ctx, s.ID)
			}
		}
	}
}

// subSecrets hides the links of every subscription in the log.
func (c *Controller) subSecrets(list []store.Sub) {
	for _, s := range list {
		c.redactor.SetGroup("sub:"+s.ID, subs.Secrets(s.URL)...)
	}
}
