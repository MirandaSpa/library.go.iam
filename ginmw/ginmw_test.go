package ginmw_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	iam "github.com/MirandaSpa/library.go.iam"
	"github.com/MirandaSpa/library.go.iam/ginmw"
)

type checkerStub struct {
	allowed bool
	err     error
}

func (c checkerStub) Can(context.Context, string, string, string) (bool, error) {
	return c.allowed, c.err
}

func TestRequirePermission(t *testing.T) {
	gin.SetMode(gin.TestMode)
	run := func(checker checkerStub, mode iam.Mode, user string) *httptest.ResponseRecorder {
		g := iam.NewGuard(checker, mode)
		g.Logf = func(string, ...any) {}
		r := gin.New()
		reached := false
		r.POST("/log", ginmw.RequirePermission(g, "a:b:c"), func(c *gin.Context) { reached = true; c.Status(http.StatusNoContent) })
		req := httptest.NewRequest(http.MethodPost, "/log", nil)
		if user != "" {
			req.Header.Set(iam.HeaderUserID, user)
		}
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			assert.False(t, reached, "a rejected request never reaches the handler")
		}
		return rec
	}

	assert.Equal(t, http.StatusNoContent, run(checkerStub{allowed: true}, iam.Strict, "u1").Code)

	rec := run(checkerStub{}, iam.Strict, "u1")
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.JSONEq(t, `{"error":"Forbidden"}`, rec.Body.String())

	assert.Equal(t, http.StatusUnauthorized, run(checkerStub{allowed: true}, iam.Strict, "").Code)
	assert.Equal(t, http.StatusServiceUnavailable, run(checkerStub{err: errors.New("down")}, iam.Strict, "u1").Code)
	assert.Equal(t, http.StatusNoContent, run(checkerStub{}, iam.Shadow, "u1").Code, "shadow lets a denial through")
}
