//go:build linux

package web

import (
	"net/http"
	"time"

	"github.com/zilbergsp/hyrouter/internal/ctl"
	"github.com/zilbergsp/hyrouter/internal/store"
	"github.com/zilbergsp/hyrouter/internal/subs"
)

// subView is a subscription for the interface: its link is masked (the
// path carries the token), its panel's figures worked out.
type subView struct {
	store.Sub
	Info    *subs.SubInfo `json:"info"`
	Servers int           `json:"servers"`
	Missing int           `json:"missing"`
}

func subViews(st store.State) []subView {
	out := make([]subView, 0, len(st.Subs))
	now := time.Now()
	for _, s := range st.Subs {
		v := subView{Sub: s, Info: subs.InfoOf(s.UserInfo, s.InfoAt, now)}
		v.URL = subs.MaskURL(s.URL)
		for _, p := range st.Servers {
			if p.Source == "sub:"+s.ID {
				v.Servers++
				if p.Missing {
					v.Missing++
				}
			}
		}
		out = append(out, v)
	}
	return out
}

func (s *Server) handleAddSub(w http.ResponseWriter, r *http.Request) {
	var in ctl.SubInput
	if err := readJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	id, stats, err := s.Ctl.AddSub(r.Context(), in)
	if err != nil {
		s.editError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": s.view(s.Ctl.State()), "id": id, "stats": stats})
}

func (s *Server) handleEditSub(w http.ResponseWriter, r *http.Request) {
	var in ctl.SubInput
	if err := readJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Ctl.EditSub(r.Context(), r.PathValue("id"), in); err != nil {
		s.editError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": s.view(s.Ctl.State())})
}

func (s *Server) handleUpdateSub(w http.ResponseWriter, r *http.Request) {
	stats, err := s.Ctl.UpdateSub(r.Context(), r.PathValue("id"))
	if err != nil {
		s.editError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": s.view(s.Ctl.State()), "stats": stats})
}

func (s *Server) handleDeleteSub(w http.ResponseWriter, r *http.Request) {
	if err := s.Ctl.DeleteSub(r.Context(), r.PathValue("id")); err != nil {
		s.editError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": s.view(s.Ctl.State())})
}
