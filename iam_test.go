package iam_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	iam "github.com/MirandaSpa/library.go.iam"
)

func TestNew(t *testing.T) {
	for _, bad := range []string{"", "iam:8080", "ftp://iam", "http://", "::"} {
		_, err := iam.New(bad)
		require.Error(t, err, bad)
	}
	_, err := iam.New("http://iam.dev.svc.cluster.local:8080/api/v2/iam/")
	require.NoError(t, err)
}

func TestCan(t *testing.T) {
	t.Run("sends the check and returns the answer", func(t *testing.T) {
		var got map[string]string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/api/v2/iam/internal/check", r.URL.Path)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			require.NoError(t, json.NewDecoder(r.Body).Decode(&got))
			_, _ = w.Write([]byte(`{"allowed":true}`))
		}))
		defer srv.Close()
		c, err := iam.New(srv.URL + "/api/v2/iam/")
		require.NoError(t, err)

		allowed, err := c.Can(context.Background(), "u1", "sales:discount:authorize", "serena")
		require.NoError(t, err)
		assert.True(t, allowed)
		assert.Equal(t, map[string]string{"user_id": "u1", "permission": "sales:discount:authorize", "branch_id": "serena"}, got)
	})

	t.Run("a denial is false without error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"allowed":false}`)) }))
		defer srv.Close()
		c, _ := iam.New(srv.URL)
		allowed, err := c.Can(context.Background(), "u1", "a:b:c", "")
		require.NoError(t, err)
		assert.False(t, allowed)
	})

	t.Run("requires user and permission", func(t *testing.T) {
		c, _ := iam.New("http://iam")
		_, err := c.Can(context.Background(), "", "a:b:c", "")
		require.Error(t, err)
		_, err = c.Can(context.Background(), "u1", "", "")
		require.Error(t, err)
	})

	t.Run("a non-2xx answer is a StatusError without the body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "secret internal detail", http.StatusInternalServerError)
		}))
		defer srv.Close()
		c, _ := iam.New(srv.URL)
		_, err := c.Can(context.Background(), "u1", "a:b:c", "")
		var se *iam.StatusError
		require.ErrorAs(t, err, &se)
		assert.Equal(t, 500, se.Code)
		assert.NotContains(t, err.Error(), "secret")
	})

	t.Run("a malformed answer is an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`nope`)) }))
		defer srv.Close()
		c, _ := iam.New(srv.URL)
		_, err := c.Can(context.Background(), "u1", "a:b:c", "")
		require.Error(t, err)
	})

	t.Run("an unreachable service is an error, never false", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		url := srv.URL
		srv.Close()
		c, _ := iam.New(url)
		allowed, err := c.Can(context.Background(), "u1", "a:b:c", "")
		require.Error(t, err)
		assert.False(t, allowed)
	})
}

func TestHolders(t *testing.T) {
	t.Run("asks by permission and branch", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "/api/v2/iam/internal/permissions/sales:discount:authorize/holders", r.URL.Path)
			assert.Equal(t, "serena", r.URL.Query().Get("branch"))
			_, _ = w.Write([]byte(`{"user_ids":["u1","u2"]}`))
		}))
		defer srv.Close()
		c, _ := iam.New(srv.URL + "/api/v2/iam")
		got, err := c.Holders(context.Background(), "sales:discount:authorize", "serena")
		require.NoError(t, err)
		assert.Equal(t, []string{"u1", "u2"}, got)
	})

	t.Run("a global permission sends no branch", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Empty(t, r.URL.RawQuery)
			_, _ = w.Write([]byte(`{"user_ids":[]}`))
		}))
		defer srv.Close()
		c, _ := iam.New(srv.URL)
		got, err := c.Holders(context.Background(), "sales:report:view", "")
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("errors", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadRequest) }))
		defer srv.Close()
		c, _ := iam.New(srv.URL)
		_, err := c.Holders(context.Background(), "sales:discount:authorize", "")
		var se *iam.StatusError
		require.ErrorAs(t, err, &se)
		assert.Equal(t, 400, se.Code)
		_, err = c.Holders(context.Background(), "", "serena")
		require.Error(t, err)
	})
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]iam.Mode{"": iam.Strict, "strict": iam.Strict, "shadow": iam.Shadow} {
		got, err := iam.ParseMode(in)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}
	_, err := iam.ParseMode("maybe")
	require.Error(t, err)
}

type checkerStub struct {
	allowed bool
	err     error
	calls   [][3]string
}

func (c *checkerStub) Can(_ context.Context, user, permission, branch string) (bool, error) {
	c.calls = append(c.calls, [3]string{user, permission, branch})
	return c.allowed, c.err
}

func TestGuard(t *testing.T) {
	newRequest := func(user, branch string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/log", nil)
		if user != "" {
			r.Header.Set(iam.HeaderUserID, user)
		}
		if branch != "" {
			r.Header.Set(iam.HeaderBranchID, branch)
		}
		return r
	}
	tests := []struct {
		name       string
		checker    *checkerStub
		user       string
		strict     int
		wantCalled bool
	}{
		{"allowed", &checkerStub{allowed: true}, "u1", 0, true},
		{"denied", &checkerStub{}, "u1", http.StatusForbidden, true},
		{"no user", &checkerStub{allowed: true}, "", http.StatusUnauthorized, false},
		{"service unreachable", &checkerStub{err: errors.New("down")}, "u1", http.StatusServiceUnavailable, true},
	}
	for _, tt := range tests {
		t.Run(tt.name+" in strict mode", func(t *testing.T) {
			g := iam.NewGuard(tt.checker, iam.Strict)
			g.Logf = func(string, ...any) {}
			assert.Equal(t, tt.strict, g.Check(newRequest(tt.user, "serena"), "a:b:c"))
			assert.Equal(t, tt.wantCalled, len(tt.checker.calls) == 1)
			if tt.wantCalled {
				assert.Equal(t, [3]string{"u1", "a:b:c", "serena"}, tt.checker.calls[0])
			}
		})
		t.Run(tt.name+" in shadow mode always proceeds and logs the denial", func(t *testing.T) {
			var lines []string
			g := iam.NewGuard(tt.checker, iam.Shadow)
			g.Logf = func(format string, _ ...any) { lines = append(lines, format) }
			assert.Equal(t, 0, g.Check(newRequest(tt.user, ""), "a:b:c"))
			assert.Equal(t, tt.strict != 0, len(lines) == 1, "a line is logged exactly when strict mode would reject")
		})
	}

	t.Run("a nil logger is safe", func(t *testing.T) {
		g := &iam.Guard{Checker: &checkerStub{}, Mode: iam.Strict}
		assert.Equal(t, http.StatusForbidden, g.Check(newRequest("u1", ""), "a:b:c"))
	})
}

func TestRequirePermissionMiddleware(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	run := func(checker iam.Checker, mode iam.Mode, user string) *httptest.ResponseRecorder {
		g := iam.NewGuard(checker, mode)
		g.Logf = func(string, ...any) {}
		req := httptest.NewRequest(http.MethodPost, "/log", nil)
		if user != "" {
			req.Header.Set(iam.HeaderUserID, user)
		}
		rec := httptest.NewRecorder()
		g.RequirePermission("a:b:c")(next).ServeHTTP(rec, req)
		return rec
	}

	t.Run("allowed reaches the handler", func(t *testing.T) {
		assert.Equal(t, http.StatusNoContent, run(&checkerStub{allowed: true}, iam.Strict, "u1").Code)
	})
	t.Run("denied is a JSON 403 that never reaches the handler", func(t *testing.T) {
		rec := run(&checkerStub{}, iam.Strict, "u1")
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
		assert.JSONEq(t, `{"error":"Forbidden"}`, rec.Body.String())
	})
	t.Run("denied passes in shadow mode", func(t *testing.T) {
		assert.Equal(t, http.StatusNoContent, run(&checkerStub{}, iam.Shadow, "u1").Code)
	})
}
