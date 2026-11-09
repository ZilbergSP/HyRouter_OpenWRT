//go:build linux

package web

import (
	"io"
	"net/http"

	"github.com/zilbergsp/hyrouter/internal/ctl"
)

// handleBackup sends the backup as a file to save.
func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	b, err := s.Ctl.Backup()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+ctl.BackupName()+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
}

// handleRestorePlan reads a backup (the body) and answers what restoring
// it brings.
func (s *Server) handleRestorePlan(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	plan, err := s.Ctl.PlanRestore(b)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Ctl.Restore(r.Context(), req.Token); err != nil {
		s.editError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": s.view(s.Ctl.State())})
}

func (s *Server) handleUndo(w http.ResponseWriter, r *http.Request) {
	if err := s.Ctl.UndoRestore(r.Context()); err != nil {
		s.editError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": s.view(s.Ctl.State())})
}
