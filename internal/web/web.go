//go:build linux

// Package web is HyRouter's web interface (docs/ARCHITECTURE.md,
// «Веб-интерфейс»): the API under /api and the built page (web/dist) for
// the rest. Only the router's LAN addresses and loopback are served. Every
// API call but the login needs a session from root's password, and every
// change also the session's CSRF token.
package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/zilbergsp/hyrouter/internal/auth"
	"github.com/zilbergsp/hyrouter/internal/ctl"
	"github.com/zilbergsp/hyrouter/internal/logx"
	"github.com/zilbergsp/hyrouter/internal/store"
)

const (
	cookieName  = "hyrouter"
	sessionLife = 24 * time.Hour
	maxBody     = 4 << 20
	// A client that gets the password wrong maxFails times waits lockout,
	// doubled each time up to maxLockout.
	maxFails   = 5
	lockout    = time.Minute
	maxLockout = 15 * time.Minute
)

// Server serves the interface.
type Server struct {
	Ctl     *ctl.Controller
	Store   *store.Store
	Journal *logx.Journal
	Log     *slog.Logger
	Version string
	// UI is the built page.
	UI fs.FS
	// Shadow is the password file (auth.Shadow; tests set their own).
	Shadow string
	// Leases is dnsmasq's DHCP leases file (/tmp/dhcp.leases).
	Leases string

	smu      sync.Mutex
	sessions map[string]session
	fails    map[netip.Addr]*failures
	srv      *http.Server
}

type session struct {
	csrf    string
	expires time.Time
}

type failures struct {
	n     int
	until time.Time
	wait  time.Duration
}

func (s *Server) log() *slog.Logger {
	if s.Log == nil {
		return slog.Default()
	}
	return s.Log
}

// Handler is the whole interface.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/session", s.handleSession)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.authed(s.handleLogout))
	mux.HandleFunc("GET /api/status", s.authed(s.handleStatus))
	mux.HandleFunc("GET /api/state", s.authed(s.handleState))
	mux.HandleFunc("POST /api/routing", s.authed(s.handleRouting))
	mux.HandleFunc("POST /api/servers", s.authed(s.handleAddServer))
	mux.HandleFunc("PATCH /api/servers/{id}", s.authed(s.handleRenameServer))
	mux.HandleFunc("DELETE /api/servers/{id}", s.authed(s.handleDeleteServer))
	mux.HandleFunc("PUT /api/main", s.authed(s.handleMain))
	mux.HandleFunc("POST /api/groups", s.authed(s.handleAddGroup))
	mux.HandleFunc("PUT /api/groups/{id}", s.authed(s.handleEditGroup))
	mux.HandleFunc("DELETE /api/groups/{id}", s.authed(s.handleDeleteGroup))
	mux.HandleFunc("PUT /api/group-probe", s.authed(s.handleGroupProbe))
	mux.HandleFunc("GET /api/connections", s.authed(s.handleConnections))
	mux.HandleFunc("GET /api/stats", s.authed(s.handleStats))
	mux.HandleFunc("PUT /api/stats", s.authed(s.handleStatsMode))
	mux.HandleFunc("POST /api/stats/reset", s.authed(s.handleStatsReset))
	mux.HandleFunc("GET /api/geo", s.authed(s.handleGeo))
	mux.HandleFunc("PUT /api/geo", s.authed(s.handleGeoSettings))
	mux.HandleFunc("POST /api/geo/update", s.authed(s.handleGeoUpdate))
	mux.HandleFunc("POST /api/subs", s.authed(s.handleAddSub))
	mux.HandleFunc("PUT /api/subs/{id}", s.authed(s.handleEditSub))
	mux.HandleFunc("POST /api/subs/{id}/update", s.authed(s.handleUpdateSub))
	mux.HandleFunc("DELETE /api/subs/{id}", s.authed(s.handleDeleteSub))
	mux.HandleFunc("PUT /api/rules", s.authed(s.handleRules))
	mux.HandleFunc("PUT /api/devices", s.authed(s.handleDevices))
	mux.HandleFunc("GET /api/neighbours", s.authed(s.handleNeighbours))
	mux.HandleFunc("PUT /api/settings", s.authed(s.handleSettings))
	mux.HandleFunc("GET /api/log", s.authed(s.handleLog))
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "нет такого запроса")
	})
	if s.UI != nil {
		files := http.FileServerFS(s.UI)
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" || r.URL.Path == "/index.html" {
				w.Header().Set("Cache-Control", "no-cache")
			}
			files.ServeHTTP(w, r)
		})
	}
	return s.guard(mux)
}

// guard serves only requests that came to a LAN address or loopback and
// sets the security headers.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.localAllowed(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// localAllowed: the connection came to loopback or to an address of a
// LAN interface.
func (s *Server) localAllowed(r *http.Request) bool {
	la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok {
		return false
	}
	ta, ok := la.(*net.TCPAddr)
	if !ok {
		return false
	}
	ip, ok := netip.AddrFromSlice(ta.IP)
	if !ok {
		return false
	}
	ip = ip.Unmap()
	if ip.IsLoopback() {
		return true
	}
	if s.Ctl == nil {
		return false
	}
	for _, name := range s.Ctl.State().Settings.LAN {
		ifc, err := net.InterfaceByName(name)
		if err != nil {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if b, ok := netip.AddrFromSlice(n.IP); ok && b.Unmap() == ip {
					return true
				}
			}
		}
	}
	return false
}

// Serve listens on port until Close.
func (s *Server) Serve(port uint16) error {
	s.srv = &http.Server{
		Addr:              net.JoinHostPort("", strconv.Itoa(int(port))),
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	err := s.srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Close stops serving.
func (s *Server) Close() {
	if s.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.srv.Shutdown(ctx)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	if err := dec.Decode(v); err != nil {
		return errors.New("неверный запрос: " + err.Error())
	}
	return nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func clientAddr(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// sessionOf returns the request's live session.
func (s *Server) sessionOf(r *http.Request) (string, session, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return "", session{}, false
	}
	s.smu.Lock()
	defer s.smu.Unlock()
	se, ok := s.sessions[c.Value]
	if !ok || time.Now().After(se.expires) {
		delete(s.sessions, c.Value)
		return "", session{}, false
	}
	return c.Value, se, true
}

// authed lets through a request with a live session; a change (anything
// but GET) also needs the session's CSRF token in X-CSRF-Token.
func (s *Server) authed(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, se, ok := s.sessionOf(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "войдите паролем root")
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("X-CSRF-Token") != se.csrf {
			writeError(w, http.StatusForbidden, "устаревшая страница: обновите её")
			return
		}
		h(w, r)
	}
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	_, se, ok := s.sessionOf(r)
	out := map[string]any{"loggedIn": ok, "version": s.Version}
	if ok {
		out["csrf"] = se.csrf
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientAddr(r)
	s.smu.Lock()
	if s.fails == nil {
		s.fails = map[netip.Addr]*failures{}
	}
	f := s.fails[ip]
	if f != nil && time.Now().Before(f.until) {
		wait := time.Until(f.until).Round(time.Second)
		s.smu.Unlock()
		writeError(w, http.StatusTooManyRequests, "слишком много попыток: подождите "+wait.String())
		return
	}
	s.smu.Unlock()
	var req struct {
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	shadow := s.Shadow
	if shadow == "" {
		shadow = auth.Shadow
	}
	ok, err := auth.Root(shadow, req.Password)
	if errors.Is(err, auth.ErrNoPassword) || errors.Is(err, auth.ErrLocked) {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	if err != nil {
		s.log().Error("web: the password could not be checked", "err", err)
		writeError(w, http.StatusInternalServerError, "не удалось проверить пароль")
		return
	}
	if !ok {
		s.smu.Lock()
		if f == nil {
			f = &failures{wait: lockout}
			s.fails[ip] = f
		}
		f.n++
		if f.n >= maxFails {
			f.n = 0
			f.until = time.Now().Add(f.wait)
			f.wait = min(f.wait*2, maxLockout)
		}
		s.smu.Unlock()
		s.log().Warn("web: a wrong password")
		writeError(w, http.StatusUnauthorized, "неверный пароль")
		return
	}
	id, csrf := randomHex(32), randomHex(16)
	s.smu.Lock()
	delete(s.fails, ip)
	if s.sessions == nil {
		s.sessions = map[string]session{}
	}
	now := time.Now()
	for k, se := range s.sessions {
		if now.After(se.expires) {
			delete(s.sessions, k)
		}
	}
	s.sessions[id] = session{csrf: csrf, expires: now.Add(sessionLife)}
	s.smu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionLife.Seconds())})
	writeJSON(w, http.StatusOK, map[string]string{"csrf": csrf})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if id, _, ok := s.sessionOf(r); ok {
		s.smu.Lock()
		delete(s.sessions, id)
		s.smu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	st := s.Ctl.Status()
	writeJSON(w, http.StatusOK, map[string]any{"version": s.Version, "status": st})
}

func (s *Server) handleLog(w http.ResponseWriter, r *http.Request) {
	after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
	writeJSON(w, http.StatusOK, s.Journal.Since(after, 1000))
}

// edit applies a change to the settings: the result is checked, saved
// and put in force, and the new state is the answer. save writes the
// parts that changed. extra, when set, is added to the answer.
func (s *Server) edit(w http.ResponseWriter, r *http.Request, change func(*store.State) error, save func(store.State) error, extra map[string]any) {
	if err := s.Ctl.Edit(r.Context(), change, save); err != nil {
		s.editError(w, err)
		return
	}
	out := map[string]any{"state": s.view(s.Ctl.State())}
	for k, v := range extra {
		out[k] = v
	}
	writeJSON(w, http.StatusOK, out)
}

// editError answers a failed edit: a refused change is the client's, the
// rest the router's.
func (s *Server) editError(w http.ResponseWriter, err error) {
	var e *ctl.EditError
	switch {
	case errors.As(err, &e) && e.Kind == ctl.NotSaved:
		writeError(w, http.StatusInternalServerError, "не удалось сохранить настройки: "+err.Error())
	case errors.As(err, &e) && e.Kind == ctl.NotApplied:
		writeError(w, http.StatusInternalServerError, "сохранено, но не применено: "+err.Error())
	default:
		writeError(w, http.StatusBadRequest, err.Error())
	}
}
