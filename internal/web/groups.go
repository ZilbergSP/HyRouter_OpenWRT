//go:build linux

package web

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/zilbergsp/hyrouter/internal/groups"
	"github.com/zilbergsp/hyrouter/internal/hysteria"
	"github.com/zilbergsp/hyrouter/internal/store"
)

// groupInput is a group as the interface edits it.
type groupInput struct {
	Name              string          `json:"name"`
	Strategy          groups.Strategy `json:"strategy"`
	Members           []string        `json:"members"`
	Subs              []string        `json:"subs"`
	Revert            bool            `json:"revert"`
	ToleranceMs       int             `json:"toleranceMs"`
	SwitchAfterErrors int             `json:"switchAfterErrors"`
}

func (in groupInput) group(id string) groups.Group {
	g := groups.Group{
		ID:                id,
		Name:              strings.TrimSpace(in.Name),
		Strategy:          in.Strategy,
		Members:           slices.Clone(in.Members),
		Subs:              slices.Clone(in.Subs),
		Revert:            in.Revert && in.Strategy == groups.Failover,
		SwitchAfterErrors: in.SwitchAfterErrors,
	}
	if g.Members == nil {
		g.Members = []string{}
	}
	if in.Strategy == groups.Latency {
		g.ToleranceMs = in.ToleranceMs
	}
	return g
}

// checkGroup is the save rule of one group: existing servers and
// subscriptions.
func checkGroup(st *store.State, g groups.Group) error {
	server := func(id string) bool {
		return slices.ContainsFunc(st.Servers, func(p hysteria.Profile) bool { return p.ID == id })
	}
	if err := groups.ValidateEdited(g, server); err != nil {
		return err
	}
	for _, sub := range g.Subs {
		if !slices.ContainsFunc(st.Subs, func(s store.Sub) bool { return s.ID == sub }) {
			return errors.New("подписка не найдена")
		}
	}
	return nil
}

func (s *Server) saveGroups(st store.State) error {
	if err := s.Store.SaveGroups(st.Groups); err != nil {
		return err
	}
	return s.Store.SaveSettings(st.Settings)
}

func (s *Server) handleAddGroup(w http.ResponseWriter, r *http.Request) {
	var in groupInput
	if err := readJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	g := in.group(groups.NewID(randomHex(6)))
	s.edit(w, r, func(st *store.State) error {
		if err := checkGroup(st, g); err != nil {
			return err
		}
		st.Groups.Groups = append(st.Groups.Groups, g)
		if err := st.Groups.Validate(); err != nil {
			return err
		}
		if st.Settings.Main == "" {
			st.Settings.Main = g.ID
		}
		return nil
	}, s.saveGroups, map[string]any{"id": g.ID})
}

func (s *Server) handleEditGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in groupInput
	if err := readJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	g := in.group(id)
	s.edit(w, r, func(st *store.State) error {
		cur := st.Groups.Find(id)
		if cur == nil {
			return errors.New("нет такой группы")
		}
		if err := checkGroup(st, g); err != nil {
			return err
		}
		*cur = g
		return st.Groups.Validate()
	}, s.saveGroups, nil)
}

// handleDeleteGroup removes a group. Rules that name it are kept: their
// traffic is refused until another server is chosen.
func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.edit(w, r, func(st *store.State) error {
		i := slices.IndexFunc(st.Groups.Groups, func(g groups.Group) bool { return g.ID == id })
		if i < 0 {
			return errors.New("нет такой группы")
		}
		st.Groups.Groups = slices.Delete(st.Groups.Groups, i, i+1)
		if st.Groups.Main == id {
			st.Groups.Main = ""
		}
		if st.Settings.Main == id {
			st.Settings.Main = firstTarget(st)
		}
		return nil
	}, s.saveGroups, nil)
}

// handleGroupProbe sets the latency probe of the groups.
func (s *Server) handleGroupProbe(w http.ResponseWriter, r *http.Request) {
	var p groups.Probe
	if err := readJSON(r, &p); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	p.URL = strings.TrimSpace(p.URL)
	if err := groups.ValidateProbe(p); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.edit(w, r, func(st *store.State) error {
		if p == (groups.Probe{}) {
			st.Groups.Probe = nil
		} else {
			st.Groups.Probe = &p
		}
		return nil
	}, func(st store.State) error { return s.Store.SaveGroups(st.Groups) }, nil)
}

// firstTarget is the main target after the main one went: the first
// server, else "".
func firstTarget(st *store.State) string {
	if len(st.Servers) > 0 {
		return st.Servers[0].ID
	}
	return ""
}

// isTarget: id is a server or a group.
func isTarget(st *store.State, id string) bool {
	return slices.ContainsFunc(st.Servers, func(p hysteria.Profile) bool { return p.ID == id }) ||
		st.Groups.Find(id) != nil
}
