package httpapi

import (
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/beekamai/network-scheme/internal/inventory"
	"github.com/beekamai/network-scheme/internal/rbac"
)

/* Bounds of the search query, in characters: a longer q is rejected, a shorter (trimmed) one finds nothing. */
const (
	minSearchLen = 2
	maxSearchLen = 100
)

/*
search is the global search (FR-UI-1): devices, ARP addresses, MACs from FDB
and ARP, and ports, among the devices in the caller's devices.read scope, at
most inventory.SearchLimit of each type (see inventory.Store.Search for the
matching rules). An absent, empty or too short query
answers an empty result; one that is too long, not UTF-8 or carries control
characters answers 400. Panel sections are matched by the web client itself.
*/
func (s *server) search(w http.ResponseWriter, r *http.Request) {
	raw, ok := single(r.URL.Query(), "q")
	if !ok || !utf8.ValidString(raw) || utf8.RuneCountInString(raw) > maxSearchLen || strings.ContainsFunc(raw, unicode.IsControl) {
		writeError(w, errBadRequest)
		return
	}
	q := strings.TrimSpace(raw)
	if utf8.RuneCountInString(q) < minSearchLen {
		writeJSON(w, http.StatusOK, inventory.EmptySearch())
		return
	}
	sc, err := s.scope(r, rbac.PermDevicesRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.inventory.Search(r.Context(), sc.filter(), q)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
