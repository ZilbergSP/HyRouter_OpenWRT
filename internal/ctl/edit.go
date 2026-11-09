//go:build linux

package ctl

import (
	"context"
	"fmt"

	"github.com/zilbergsp/hyrouter/internal/store"
)

// EditKind says which step of an edit failed.
type EditKind int

const (
	// Refused: the change is wrong; nothing was saved.
	Refused EditKind = iota
	// NotSaved: the files could not be written.
	NotSaved
	// NotApplied: saved, but routing did not take it.
	NotApplied
)

// EditError is a failed edit.
type EditError struct {
	Kind EditKind
	Err  error
}

func (e *EditError) Error() string { return e.Err.Error() }
func (e *EditError) Unwrap() error { return e.Err }

// Edit changes the settings, one edit at a time (the web interface, the
// subscription updates, a restore): change works on a copy, which is
// checked, saved by save and applied.
func (c *Controller) Edit(ctx context.Context, change func(*store.State) error, save func(store.State) error) error {
	c.editMu.Lock()
	defer c.editMu.Unlock()
	return c.editLocked(ctx, change, save)
}

func (c *Controller) editLocked(ctx context.Context, change func(*store.State) error, save func(store.State) error) error {
	st := c.State().Clone()
	if err := change(&st); err != nil {
		return &EditError{Refused, err}
	}
	if err := Check(st); err != nil {
		return &EditError{Refused, err}
	}
	if err := save(st); err != nil {
		c.log.Error("settings not saved", "err", err)
		return &EditError{NotSaved, err}
	}
	if err := c.Apply(ctx, st); err != nil {
		return &EditError{NotApplied, err}
	}
	c.syncGuard(st.Settings)
	c.kickGeo()
	go c.zapretApply()
	return nil
}

// SetRouting turns routing on or off; the choice is kept for the next
// boot.
func (c *Controller) SetRouting(ctx context.Context, on bool) error {
	c.editMu.Lock()
	defer c.editMu.Unlock()
	if on {
		if err := c.Start(ctx); err != nil {
			return &EditError{NotApplied, fmt.Errorf("маршрутизация не запустилась: %w", err)}
		}
	} else if err := c.Stop(); err != nil {
		c.log.Warn("routing stopped with errors", "err", err)
	}
	st := c.State().Clone()
	st.Settings.Enabled = on
	if err := c.store.SaveSettings(st.Settings); err != nil {
		return &EditError{NotSaved, err}
	}
	if err := c.Apply(ctx, st); err != nil {
		return &EditError{NotApplied, err}
	}
	c.syncGuard(st.Settings)
	return nil
}
