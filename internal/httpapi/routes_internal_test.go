package httpapi

import (
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestRoutesPanicsOnBypassedRegistration(t *testing.T) {
	for name, register := range map[string]func(chi.Router){
		"direct": func(r chi.Router) { r.Get("/api/rogue", func(http.ResponseWriter, *http.Request) {}) },
		"with middleware": func(r chi.Router) {
			r.With(securityHeaders).Get("/api/rogue", func(http.ResponseWriter, *http.Request) {})
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newServer(Deps{}).handler().(chi.Router)
			register(r)
			defer func() {
				if recover() == nil {
					t.Fatal("routesOf accepted a route registered without route()")
				}
			}()
			routesOf(r)
		})
	}
}
