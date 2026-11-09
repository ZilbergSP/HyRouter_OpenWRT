//go:build linux

package web

import (
	"net/http"
)

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Ctl.Connections())
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	period := r.URL.Query().Get("period")
	if period == "" {
		period = "today"
	}
	rep, err := s.Ctl.Stats(period)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) handleStatsMode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Ctl.SetStats(r.Context(), req.Enabled); err != nil {
		s.editError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": s.view(s.Ctl.State())})
}

func (s *Server) handleStatsReset(w http.ResponseWriter, r *http.Request) {
	if err := s.Ctl.ResetStats(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}
