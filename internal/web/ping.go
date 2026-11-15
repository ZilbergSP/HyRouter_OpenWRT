//go:build linux

package web

import "net/http"

// handlePings is the measurement of the servers (the servers page polls
// it while a run is under way).
func (s *Server) handlePings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Ctl.Pings())
}

// handlePing measures the servers named (all with none).
func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, s.Ctl.PingServers(req.IDs))
}

// handlePingStop ends the run under way.
func (s *Server) handlePingStop(w http.ResponseWriter, r *http.Request) {
	s.Ctl.PingStop()
	writeJSON(w, http.StatusOK, s.Ctl.Pings())
}
