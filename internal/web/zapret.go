//go:build linux

package web

import (
	"net/http"

	"github.com/zilbergsp/hyrouter/internal/ctl"
)

func (s *Server) handleZapret(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Ctl.ZapretInfo())
}

func (s *Server) handleSaveZapret(w http.ResponseWriter, r *http.Request) {
	var in ctl.ZapretInput
	if err := readJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Ctl.SaveZapret(r.Context(), in); err != nil {
		s.editError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": s.view(s.Ctl.State()), "zapret": s.Ctl.ZapretInfo()})
}

func (s *Server) handleZapretPick(w http.ResponseWriter, r *http.Request) {
	if err := s.Ctl.ZapretPick(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, s.Ctl.ZapretInfo())
}

func (s *Server) handleZapretCancel(w http.ResponseWriter, r *http.Request) {
	s.Ctl.ZapretPickCancel()
	writeJSON(w, http.StatusOK, s.Ctl.ZapretInfo())
}
