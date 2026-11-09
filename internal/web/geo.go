//go:build linux

package web

import (
	"context"
	"errors"
	"net/http"

	"github.com/zilbergsp/hyrouter/internal/geodata"
	"github.com/zilbergsp/hyrouter/internal/store"
)

func (s *Server) handleGeo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Ctl.GeoStatus())
}

// handleGeoSettings chooses the source of the rule database and its
// daily update; another source is downloaded at once.
func (s *Server) handleGeoSettings(w http.ResponseWriter, r *http.Request) {
	var req store.GeoSettings
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, ok := geodata.FindSource(req.Source); !ok {
		writeError(w, http.StatusBadRequest, "неизвестный источник базы правил")
		return
	}
	changed := s.Ctl.GeoStatus().Source != req.Source
	err := s.Ctl.Edit(r.Context(), func(st *store.State) error {
		st.Settings.Geo = req
		return nil
	}, func(st store.State) error { return s.Store.SaveSettings(st.Settings) })
	if err != nil {
		s.editError(w, err)
		return
	}
	if changed {
		go s.Ctl.UpdateGeo(context.Background())
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": s.view(s.Ctl.State()), "geo": s.Ctl.GeoStatus()})
}

// handleGeoUpdate starts a download of the rule database; the interface
// follows it by GET /api/geo.
func (s *Server) handleGeoUpdate(w http.ResponseWriter, r *http.Request) {
	if s.Ctl.GeoStatus().Busy {
		writeError(w, http.StatusConflict, "база правил уже обновляется")
		return
	}
	go func() {
		if err := s.Ctl.UpdateGeo(context.Background()); err != nil && !errors.Is(err, context.Canceled) {
			s.log().Warn("web: rule database not updated", "err", err)
		}
	}()
	writeJSON(w, http.StatusAccepted, s.Ctl.GeoStatus())
}
