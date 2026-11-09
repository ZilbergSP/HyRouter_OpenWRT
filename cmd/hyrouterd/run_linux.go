package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zilbergsp/hyrouter/internal/ctl"
	"github.com/zilbergsp/hyrouter/internal/edition"
	"github.com/zilbergsp/hyrouter/internal/logx"
	"github.com/zilbergsp/hyrouter/internal/release"
	"github.com/zilbergsp/hyrouter/internal/selfupdate"
	"github.com/zilbergsp/hyrouter/internal/store"
	"github.com/zilbergsp/hyrouter/internal/web"
	webui "github.com/zilbergsp/hyrouter/web"
)

// selfUpdate installs the newest HyRouter release for this router
// (hyrouterd -update, over SSH): the check and the checked download of
// «Обновить» in the interface. The package manager runs on after this
// process ends and restarts the service. HYROUTER_RELEASES_API replaces
// GitHub's API in CI's test of the upgrade.
func selfUpdate() int {
	in, err := selfupdate.Find()
	if err != nil {
		fmt.Fprintln(os.Stderr, "hyrouterd:", err)
		return 1
	}
	cl := &release.Client{UserAgent: "HyRouter/" + version, API: os.Getenv("HYROUTER_RELEASES_API")}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	a, ok, err := selfupdate.Check(ctx, cl, in, version)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hyrouterd:", err)
		return 1
	}
	if !ok {
		fmt.Printf("HyRouter %s — последняя версия.\n", version)
		return 0
	}
	fmt.Printf("Скачиваю HyRouter %s (%s)…\n", a.Version, a.Asset)
	file, err := selfupdate.Download(ctx, cl, a, nil)
	if err == nil {
		err = selfupdate.Launch(in, file, version, a.Version)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "hyrouterd:", err)
		return 1
	}
	fmt.Printf("Ставлю HyRouter %s: служба перезапустится. Журнал: %s\n", a.Version, selfupdate.Log)
	return 0
}

// cleanup removes what HyRouter put in the kernel; the exit code.
func cleanup() int {
	if err := ctl.Cleanup(); err != nil {
		fmt.Fprintln(os.Stderr, "hyrouterd:", err)
		return 1
	}
	return 0
}

// run is hyrouterd until SIGTERM or SIGINT; the exit code.
func run(dir string) int {
	edition.SetMemoryLimit()
	journal := logx.NewJournal(2000)
	redactor := &logx.Redactor{}
	// stderr goes to the system log (procd); the journal to the interface.
	log := slog.New(logx.NewHandler(journal, redactor, slog.LevelInfo, os.Stderr))
	slog.SetDefault(log)
	log.Info("hyrouterd started", "version", version, "edition", edition.Name)

	st := &store.Store{Dir: dir}
	c := ctl.New(ctl.Options{Store: st, Log: log, Redactor: redactor, Version: version})
	port := uint16(store.DefaultWebPort)
	if err := c.Load(); err != nil {
		// The table of a run that crashed stays: VPN traffic keeps being
		// refused rather than going direct until the settings are fixed.
		log.Error("the settings could not be read: routing is not started", "err", err)
	} else {
		s := c.State().Settings
		port = s.WebPort
		if s.Enabled {
			// With the kill switch, nothing goes direct until the rules
			// are loaded (KeeneticOS has no earlier boot service).
			c.CloseAtStart()
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
				defer cancel()
				if err := c.Start(ctx); err != nil {
					log.Error("routing did not start", "err", err)
				} else {
					log.Info("routing started")
				}
			}()
		} else if err := c.Stop(); err != nil {
			log.Warn("leftovers of an earlier run", "err", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	srv := &web.Server{Ctl: c, Store: st, Journal: journal, Log: log, Version: version, UI: webui.Dist()}
	go func() {
		if err := srv.Serve(port); err != nil {
			log.Error("the web interface did not start", "port", port, "err", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	log.Info("hyrouterd stopping")
	cancel()
	srv.Close()
	if err := c.Shutdown(); err != nil {
		log.Warn("stopped with errors", "err", err)
		return 1
	}
	return 0
}
