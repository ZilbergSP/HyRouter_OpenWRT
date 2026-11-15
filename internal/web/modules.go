//go:build linux

package web

import "net/http"

// handleModules is «Настройки → Модули».
func (s *Server) handleModules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Ctl.Modules())
}

// handleInstallModule downloads a module (the page follows by
// handleModules).
func (s *Server) handleInstallModule(w http.ResponseWriter, r *http.Request) {
	if err := s.Ctl.InstallModule(r.PathValue("id")); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, s.Ctl.Modules())
}

// handleRemoveModule deletes a module.
func (s *Server) handleRemoveModule(w http.ResponseWriter, r *http.Request) {
	if err := s.Ctl.RemoveModule(r.PathValue("id")); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.Ctl.Modules())
}
