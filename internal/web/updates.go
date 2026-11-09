//go:build linux

package web

import (
	"context"
	"net/http"
	"time"
)

// handleUpdates is «Настройки → Обновления».
func (s *Server) handleUpdates(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Ctl.Updates())
}

// handleUpdatesCheck looks for a newer HyRouter and newer cores now.
func (s *Server) handleUpdatesCheck(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	s.Ctl.CheckUpdates(ctx)
	writeJSON(w, http.StatusOK, s.Ctl.Updates())
}

// handleUpdateInstall installs the HyRouter on offer: hyrouterd restarts.
func (s *Server) handleUpdateInstall(w http.ResponseWriter, r *http.Request) {
	if err := s.Ctl.InstallUpdate(); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, s.Ctl.Updates())
}

// handleCoreInstall installs the newer release of a core on offer.
func (s *Server) handleCoreInstall(w http.ResponseWriter, r *http.Request) {
	if err := s.Ctl.InstallCore(r.PathValue("name")); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, s.Ctl.Updates())
}

// handleCoreRollback returns a core to the one it replaced.
func (s *Server) handleCoreRollback(w http.ResponseWriter, r *http.Request) {
	if err := s.Ctl.RollbackCore(r.PathValue("name")); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.Ctl.Updates())
}
