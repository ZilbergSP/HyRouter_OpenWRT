package zapret

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/zilbergsp/hyrouter/internal/hysteria"
)

// Runner keeps one nfqws2 running with the arguments it was last given
// and starts it again when it exits on its own (after 2, 4… at most 60 s).
type Runner struct {
	Exe string
	Log *slog.Logger
	// OnChange is called when the state changes (no lock held).
	OnChange func()
	// Spawn starts the process (nil: hysteria.StartChild; tests replace it).
	Spawn func(exe string, args, env []string, out io.Writer) (hysteria.Child, error)

	mu       sync.Mutex
	gen      uint64 // the run the supervisor works for; Stop and Start bump it
	child    hysteria.Child
	exited   chan struct{} // closed once child's Wait returned
	state    string        // off | running | error
	lastErr  string
	restarts int
	lines    []string // the last lines nfqws2 wrote
}

// Runner states.
const (
	Off     = "off"
	Running = "running"
	Failed  = "error"
)

// keepLines: how many of nfqws2's last lines the runner keeps.
const keepLines = 40

// steady: a run this long resets the backoff.
const steady = time.Minute

// exitWait bounds the wait for a killed nfqws2 to be gone. A new one
// cannot bind the queue while the old one holds it, and two would process
// the same packets.
var exitWait = 5 * time.Second

// Status is the runner for the UI.
type Status struct {
	State    string   `json:"state"`
	Error    string   `json:"error,omitempty"`
	Restarts int      `json:"restarts"`
	Lines    []string `json:"lines"`
}

func (r *Runner) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.state
	if st == "" {
		st = Off
	}
	return Status{State: st, Error: r.lastErr, Restarts: r.restarts, Lines: append([]string{}, r.lines...)}
}

// Start (re)starts nfqws2 with args.
func (r *Runner) Start(args []string) {
	r.mu.Lock()
	r.gen++
	gen := r.gen
	old, done := r.child, r.exited
	r.child, r.exited = nil, nil
	r.restarts, r.lastErr, r.lines = 0, "", nil
	r.mu.Unlock()
	kill(old, done)
	go r.supervise(gen, args)
}

// Stop stops nfqws2.
func (r *Runner) Stop() {
	r.mu.Lock()
	r.gen++
	old, done := r.child, r.exited
	r.child, r.exited = nil, nil
	r.state, r.lastErr = Off, ""
	r.mu.Unlock()
	kill(old, done)
	r.changed()
}

// kill ends a child and waits until it is gone (at most exitWait).
func kill(c hysteria.Child, done chan struct{}) {
	if c == nil {
		return
	}
	c.Kill()
	if done != nil {
		select {
		case <-done:
		case <-time.After(exitWait):
		}
	}
}

func (r *Runner) changed() {
	if r.OnChange != nil {
		r.OnChange()
	}
}

func (r *Runner) current(gen uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.gen == gen
}

func (r *Runner) supervise(gen uint64, args []string) {
	backoff := 2 * time.Second
	for r.current(gen) {
		out := &lineWriter{add: func(l string) { r.line(gen, l) }}
		start := r.Spawn
		if start == nil {
			start = hysteria.StartChild
		}
		began := time.Now()
		child, err := start(r.Exe, args, nil, out)
		r.mu.Lock()
		if r.gen != gen {
			r.mu.Unlock()
			if child != nil {
				child.Kill()
			}
			return
		}
		if err != nil {
			r.state, r.lastErr = Failed, "nfqws2 не запустился: "+err.Error()
			r.mu.Unlock()
			r.log().Error("zapret: nfqws2 not started", "err", err)
			r.changed()
		} else {
			done := make(chan struct{})
			r.child, r.exited, r.state = child, done, Running
			r.mu.Unlock()
			r.log().Info("zapret: nfqws2 started", "args", len(args))
			r.changed()
			werr := child.Wait()
			close(done)
			out.Flush()
			r.mu.Lock()
			if r.gen != gen {
				r.mu.Unlock()
				return // stopped or restarted on purpose
			}
			r.child, r.exited, r.state = nil, nil, Failed
			r.lastErr = exitReason(werr, r.lines)
			r.restarts++
			r.mu.Unlock()
			r.log().Warn("zapret: nfqws2 exited", "err", werr)
			r.changed()
			if time.Since(began) > steady {
				backoff = 2 * time.Second
			}
		}
		time.Sleep(backoff)
		backoff = min(2*backoff, time.Minute)
	}
}

// exitReason: nfqws2's last error line says best why it ended.
func exitReason(err error, lines []string) string {
	for i := len(lines) - 1; i >= 0 && i >= len(lines)-5; i-- {
		l := strings.ToLower(lines[i])
		if strings.Contains(l, "error") || strings.Contains(l, "fail") || strings.Contains(l, "cannot") || strings.Contains(l, "invalid") {
			return "nfqws2 остановился: " + lines[i]
		}
	}
	if err == nil {
		err = errors.New("завершился")
	}
	return fmt.Sprintf("nfqws2 остановился (%v)", err)
}

func (r *Runner) line(gen uint64, l string) {
	r.mu.Lock()
	if r.gen == gen {
		r.lines = append(r.lines, l)
		if len(r.lines) > keepLines {
			r.lines = r.lines[len(r.lines)-keepLines:]
		}
	}
	r.mu.Unlock()
	r.log().Debug("nfqws2", "line", l)
}

func (r *Runner) log() *slog.Logger {
	if r.Log == nil {
		return slog.Default()
	}
	return r.Log
}

// lineWriter splits output into lines.
type lineWriter struct {
	mu  sync.Mutex
	buf []byte
	add func(string)
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		if l := strings.TrimSpace(string(w.buf[:i])); l != "" {
			w.add(l)
		}
		w.buf = w.buf[i+1:]
	}
	if len(w.buf) > 4096 {
		w.add(string(w.buf))
		w.buf = nil
	}
	return len(p), nil
}

// Flush passes on a last line without a newline.
func (w *lineWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if l := strings.TrimSpace(string(w.buf)); l != "" {
		w.add(l)
	}
	w.buf = nil
}
