package chimw_test

import (
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"

	iam "github.com/MirandaSpa/library.go.iam"
	"github.com/MirandaSpa/library.go.iam/chimw"
)

func TestRoutes(t *testing.T) {
	ok := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	r := chi.NewRouter()
	r.Get("/status", ok)
	r.Route("/api/v2/storage/product-alert", func(sub chi.Router) {
		sub.Get("/trace", ok)
		sub.Patch("/state", ok)
		sub.Get("/items/{id}", ok)
	})
	r.Mount("/api/v2/docs", func() http.Handler {
		m := chi.NewRouter()
		m.Delete("/{id}", ok)
		return m
	}())

	got := chimw.Routes(r)

	assert.ElementsMatch(t, []iam.RouteKey{
		{Method: "GET", Path: "/status"},
		{Method: "GET", Path: "/api/v2/storage/product-alert/trace"},
		{Method: "PATCH", Path: "/api/v2/storage/product-alert/state"},
		{Method: "GET", Path: "/api/v2/storage/product-alert/items/{id}"},
		{Method: "DELETE", Path: "/api/v2/docs/{id}"},
	}, got)
}

func TestRoutesMatchTheManifest(t *testing.T) {
	ok := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	r := chi.NewRouter()
	r.Get("/a/{id}", ok)
	m := iam.Manifest{
		Service:     "svc",
		Permissions: []iam.ManifestPermission{{ID: "area:thing:view", Label: "Ver"}},
		Routes:      []iam.ManifestRoute{{Method: "GET", Path: "/a/{id}", Permission: "area:thing:view"}},
	}
	assert.Empty(t, iam.CheckRoutes(m, chimw.Routes(r)))
}
