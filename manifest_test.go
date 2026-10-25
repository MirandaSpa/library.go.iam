package iam_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	iam "github.com/MirandaSpa/library.go.iam"
)

func validManifest() iam.Manifest {
	return iam.Manifest{
		Service: "products",
		Permissions: []iam.ManifestPermission{
			{ID: "products:product:list", Label: "Ver catalogo", Scope: "global"},
			{ID: "products:country:list", Label: "Ver paises"},
		},
		Routes: []iam.ManifestRoute{
			{Method: "GET", Path: "/api/v2/internal_product/products", Permission: "products:product:list"},
			{Method: "GET", Path: "/api/v2/internal_product/products/country", Permission: "products:country:list"},
			{Method: "GET", Path: "/api/v2/internal_product/products/{id}/test", Public: true},
		},
	}
}

func TestManifestValidate(t *testing.T) {
	require.NoError(t, validManifest().Validate())

	tests := []struct {
		name   string
		change func(m *iam.Manifest)
		expect string
	}{
		{"service with uppercase", func(m *iam.Manifest) { m.Service = "Products" }, "service"},
		{"empty service", func(m *iam.Manifest) { m.Service = "" }, "service"},
		{"permission with two segments", func(m *iam.Manifest) { m.Permissions[0].ID = "products:list" }, "service:resource:action"},
		{"permission with uppercase", func(m *iam.Manifest) { m.Permissions[0].ID = "products:Product:list" }, "lowercase"},
		{"permission of another service", func(m *iam.Manifest) { m.Permissions[0].ID = "sales:product:list" }, "must start with the service"},
		{"permission declared twice", func(m *iam.Manifest) { m.Permissions[1].ID = "products:product:list" }, "declared twice"},
		{"permission without label", func(m *iam.Manifest) { m.Permissions[0].Label = " " }, "needs a label"},
		{"bad scope", func(m *iam.Manifest) { m.Permissions[0].Scope = "region" }, "scope"},
		{"bad audit", func(m *iam.Manifest) { m.Permissions[0].Audit = "never" }, "audit"},
		{"bad kind", func(m *iam.Manifest) { m.Permissions[0].Kind = "other" }, "kind"},
		{"bad method", func(m *iam.Manifest) { m.Routes[0].Method = "get" }, "method"},
		{"path without slash", func(m *iam.Manifest) { m.Routes[0].Path = "api/v2/x" }, "start with /"},
		{"same route twice, even with another param name", func(m *iam.Manifest) {
			m.Routes = append(m.Routes, iam.ManifestRoute{Method: "GET", Path: "/api/v2/internal_product/products/{pid}/test", Public: true})
		}, "declared twice"},
		{"route with neither permission nor public", func(m *iam.Manifest) { m.Routes[0].Permission = "" }, "declare its permission"},
		{"route that is both", func(m *iam.Manifest) { m.Routes[0].Public = true }, "not both"},
		{"route with a permission the manifest does not declare", func(m *iam.Manifest) { m.Routes[0].Permission = "products:x:y" }, "does not declare"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := validManifest()
			tt.change(&m)
			require.ErrorContains(t, m.Validate(), tt.expect)
		})
	}

	t.Run("reports every problem at once", func(t *testing.T) {
		m := validManifest()
		m.Permissions[0].Label = ""
		m.Routes[0].Method = "get"
		err := m.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "needs a label")
		assert.Contains(t, err.Error(), "method")
	})
}

func TestRegisterManifest(t *testing.T) {
	t.Run("puts the manifest of the service", func(t *testing.T) {
		var method, path string
		var body struct {
			Permissions []map[string]any `json:"permissions"`
			Routes      []map[string]any `json:"routes"`
			Service     string           `json:"service"`
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			method, path = r.Method, r.URL.Path
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			_, _ = w.Write([]byte(`{"permissions":2,"routes":3}`))
		}))
		defer srv.Close()
		c, err := iam.New(srv.URL + "/api/v2/iam")
		require.NoError(t, err)

		require.NoError(t, c.RegisterManifest(context.Background(), validManifest()))

		assert.Equal(t, http.MethodPut, method)
		assert.Equal(t, "/api/v2/iam/internal/manifests/products", path)
		assert.Len(t, body.Permissions, 2)
		assert.Len(t, body.Routes, 3)
		assert.Equal(t, "products:product:list", body.Permissions[0]["id"])
		assert.Empty(t, body.Service, "the service goes in the path, not in the body")
	})

	t.Run("an invalid manifest never reaches iam", func(t *testing.T) {
		calls := atomic.Int32{}
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
		defer srv.Close()
		c, _ := iam.New(srv.URL)
		m := validManifest()
		m.Routes[0].Permission = "products:x:y"

		require.Error(t, c.RegisterManifest(context.Background(), m))
		assert.Zero(t, calls.Load())
	})

	t.Run("a rejection is a status error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadRequest) }))
		defer srv.Close()
		c, _ := iam.New(srv.URL)

		err := c.RegisterManifest(context.Background(), validManifest())

		var se *iam.StatusError
		require.ErrorAs(t, err, &se)
		assert.Equal(t, http.StatusBadRequest, se.Code)
	})
}

func TestRegisterInBackground(t *testing.T) {
	t.Run("retries until iam answers", func(t *testing.T) {
		calls := atomic.Int32{}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if calls.Add(1) < 3 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte(`{"permissions":2,"routes":3}`))
		}))
		defer srv.Close()
		c, _ := iam.New(srv.URL, iam.WithRetryWait(time.Millisecond))
		logs := make(chan string, 20)

		done, err := c.RegisterInBackground(context.Background(), validManifest(), func(format string, _ ...any) { logs <- format })
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("registration did not finish")
		}
		assert.Equal(t, int32(3), calls.Load())
		assert.Len(t, logs, 3, "two retries and the success")
	})

	t.Run("stops when the context ends", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
		defer srv.Close()
		c, _ := iam.New(srv.URL, iam.WithRetryWait(time.Millisecond))
		ctx, cancel := context.WithCancel(context.Background())

		done, err := c.RegisterInBackground(ctx, validManifest(), nil)
		require.NoError(t, err)
		time.Sleep(10 * time.Millisecond)
		cancel()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("the goroutine did not stop with the context")
		}
	})

	t.Run("an invalid manifest is returned at once", func(t *testing.T) {
		c, _ := iam.New("http://iam.invalid")
		m := validManifest()
		m.Service = ""
		done, err := c.RegisterInBackground(context.Background(), m, nil)
		require.Error(t, err)
		assert.Nil(t, done)
	})
}

func TestCheckRoutes(t *testing.T) {
	m := validManifest()

	t.Run("the manifest and the served routes agree", func(t *testing.T) {
		served := []iam.RouteKey{
			{Method: "GET", Path: "/api/v2/internal_product/products"},
			{Method: "GET", Path: "/api/v2/internal_product/products/country"},
			{Method: "GET", Path: "/api/v2/internal_product/products/:productId/test"},
		}
		assert.Empty(t, iam.CheckRoutes(m, served))
	})

	t.Run("a served route that the manifest does not declare", func(t *testing.T) {
		served := []iam.RouteKey{
			{Method: "GET", Path: "/api/v2/internal_product/products"},
			{Method: "GET", Path: "/api/v2/internal_product/products/country"},
			{Method: "GET", Path: "/api/v2/internal_product/products/{id}/test"},
			{Method: "DELETE", Path: "/api/v2/internal_product/products/{id}"},
		}
		problems := iam.CheckRoutes(m, served)
		require.Len(t, problems, 1)
		assert.Contains(t, problems[0], "DELETE /api/v2/internal_product/products/{id}")
	})

	t.Run("a declared route that is not served", func(t *testing.T) {
		served := []iam.RouteKey{
			{Method: "GET", Path: "/api/v2/internal_product/products"},
			{Method: "GET", Path: "/api/v2/internal_product/products/{id}/test"},
		}
		problems := iam.CheckRoutes(m, served)
		require.Len(t, problems, 1)
		assert.Contains(t, problems[0], "declares GET /api/v2/internal_product/products/country")
	})

	t.Run("ignored routes need no declaration", func(t *testing.T) {
		served := []iam.RouteKey{
			{Method: "GET", Path: "/api/v2/internal_product/products"},
			{Method: "GET", Path: "/api/v2/internal_product/products/country"},
			{Method: "GET", Path: "/api/v2/internal_product/products/{id}/test"},
			{Method: "GET", Path: "/healthz/"},
		}
		assert.Empty(t, iam.CheckRoutes(m, served, iam.RouteKey{Method: "GET", Path: "/healthz"}))
	})
}
