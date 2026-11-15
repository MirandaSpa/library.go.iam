// Package chimw adapts the manifest check to chi, which part of the services use.
package chimw

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	iam "github.com/MirandaSpa/library.go.iam"
)

// Routes lists the routes the chi router serves, to compare with the manifest in a CI
// test (iam.CheckRoutes). Mounted sub-routers are walked too.
func Routes(router chi.Routes) []iam.RouteKey {
	var out []iam.RouteKey
	// chi.Walk only fails when the walk function does, and ours never does.
	_ = chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		out = append(out, iam.RouteKey{Method: method, Path: route})
		return nil
	})
	return out
}
