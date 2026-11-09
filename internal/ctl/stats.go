//go:build linux

package ctl

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zilbergsp/hyrouter/internal/groups"
	"github.com/zilbergsp/hyrouter/internal/stats"
	"github.com/zilbergsp/hyrouter/internal/store"
)

// Statistics (docs/ARCHITECTURE.md, «Статистика»): the traffic and
// connections of every day by device, server and group, never by site.
// The collector of HyRoute samples the connection records every few
// seconds; the days go to /etc/hyrouter/stats every half hour, so the
// flash is written little.

var (
	statsSample = 5 * time.Second
	statsFlush  = 30 * time.Minute
)

// statsMaxFile bounds a statistics file read.
const statsMaxFile = 4 << 20

// statFiles is the statistics folder (stats.Files).
type statFiles struct{ dir string }

func (f statFiles) path(name string) string { return filepath.Join(f.dir, name+".json") }

func (f statFiles) List() ([]string, error) {
	entries, err := os.ReadDir(f.dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if n, ok := strings.CutSuffix(e.Name(), ".json"); ok && stats.ValidName(n) {
			out = append(out, n)
		}
	}
	return out, nil
}

func (f statFiles) Read(name string) ([]byte, error) {
	fi, err := os.Lstat(f.path(name))
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > statsMaxFile {
		return nil, stats.ErrCorrupt
	}
	file, err := os.Open(f.path(name))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, statsMaxFile))
}

func (f statFiles) Write(name string, b []byte) error { return store.WriteFile(f.path(name), b) }

func (f statFiles) Remove(name string) error {
	err := os.Remove(f.path(name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// SweepTemp removes the temporary files of interrupted writes.
func (f statFiles) SweepTemp(before time.Time) (int, error) {
	entries, err := os.ReadDir(f.dir)
	if err != nil {
		return 0, nil
	}
	n := 0
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".") {
			continue
		}
		if fi, err := e.Info(); err == nil && fi.ModTime().Before(before) && os.Remove(filepath.Join(f.dir, e.Name())) == nil {
			n++
		}
	}
	return n, nil
}

// statsName is a server's or group's name for the statistics.
func (c *Controller) statsName(id string) string {
	st := c.State()
	if groups.IsGroupID(id) {
		if g := st.Groups.Find(id); g != nil {
			return g.Name
		}
		return ""
	}
	for _, p := range st.Servers {
		if p.ID == id {
			return p.Name
		}
	}
	return ""
}

// statsMode is the collection mode of the settings.
func statsMode(s store.Settings) stats.Mode {
	if s.Stats {
		return stats.ModeOn
	}
	return stats.ModeOff
}

// runStats samples the connections and writes the days until ctx ends;
// then it writes what is left.
func (c *Controller) runStats(ctx context.Context) {
	src := c.stats.NewSource()
	c.flows.OnClose = src.Closed
	sample := time.NewTicker(statsSample)
	defer sample.Stop()
	flush := time.NewTicker(statsFlush)
	defer flush.Stop()
	for {
		select {
		case <-ctx.Done():
			src.Sample(time.Now(), c.flows)
			c.stats.Flush(time.Now())
			return
		case now := <-sample.C:
			src.Sample(now, c.flows)
			if c.stats.DayChanged(now) {
				c.stats.Flush(now)
			}
		case now := <-flush.C:
			if err := c.stats.Flush(now); err != nil {
				c.log.Warn("statistics not written", "err", err)
			}
			if c.stats.CompactDue(now) {
				c.stats.Compact(now)
			}
		}
	}
}

// Stats is the statistics of a period: today, yesterday, 7d, 30d or a
// month YYYY-MM.
func (c *Controller) Stats(period string) (stats.Report, error) {
	return c.stats.Report(time.Now(), period)
}

// SetStats turns the collection on or off.
func (c *Controller) SetStats(ctx context.Context, on bool) error {
	err := c.Edit(ctx, func(st *store.State) error {
		st.Settings.Stats = on
		return nil
	}, func(st store.State) error { return c.store.SaveSettings(st.Settings) })
	if err != nil {
		return err
	}
	return c.stats.SetMode(time.Now(), statsMode(c.State().Settings))
}

// ResetStats removes every statistics file.
func (c *Controller) ResetStats() error { return c.stats.Reset(time.Now()) }
