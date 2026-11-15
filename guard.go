package iam

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
)

// Identity headers. X-Usuario-Id is only trustworthy when the Ingress forwards the
// value taken from the token (auth-url + auth-response-headers); otherwise the
// client can forge it, so roll the guard out in shadow mode first.
const (
	HeaderUserID   = "X-Usuario-Id"
	HeaderBranchID = "X-Sucursal-Id"
)

// Mode tells what a denial does.
type Mode string

// Guard modes: Strict rejects the request; Shadow only logs "would deny" and lets
// it through, to adopt the guard without anyone losing access.
const (
	Strict Mode = "strict"
	Shadow Mode = "shadow"
)

// ParseMode reads a configuration value; empty means Strict.
func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case "", Strict:
		return Strict, nil
	case Shadow:
		return Shadow, nil
	default:
		return "", errors.New("iam: mode must be strict or shadow")
	}
}

// Checker is what the guard needs from the client (so tests can fake it).
type Checker interface {
	Can(ctx context.Context, userID, permission, branchID string) (bool, error)
}

// Guard protects routes with a permission.
type Guard struct {
	Checker Checker
	Mode    Mode
	// Logf receives the "would deny" and error lines of shadow mode and the errors
	// of strict mode. It defaults to log.Printf. Only internal ids are logged.
	Logf func(format string, args ...any)
}

// NewGuard builds a guard around the client.
func NewGuard(c Checker, mode Mode) *Guard {
	return &Guard{Checker: c, Mode: mode, Logf: log.Printf}
}

// Check decides one request. It returns 0 when the request may proceed, or the
// HTTP status to answer with: 401 without user, 403 when denied, 503 when the
// permissions service could not answer. In shadow mode it always returns 0.
func (g *Guard) Check(r *http.Request, permission string) int {
	user, branch := r.Header.Get(HeaderUserID), r.Header.Get(HeaderBranchID)
	status := 0
	switch user {
	case "":
		status = http.StatusUnauthorized
		g.logf("iam guard: no user permission=%s mode=%s", permission, g.Mode)
	default:
		allowed, err := g.Checker.Can(r.Context(), user, permission, branch)
		switch {
		case err != nil:
			status = http.StatusServiceUnavailable
			g.logf("iam guard: check failed permission=%s user=%s branch=%s mode=%s err=%v", permission, user, branch, g.Mode, err)
		case !allowed:
			status = http.StatusForbidden
			g.logf("iam guard: denied permission=%s user=%s branch=%s mode=%s", permission, user, branch, g.Mode)
		}
	}
	if g.Mode == Shadow {
		return 0
	}
	return status
}

func (g *Guard) logf(format string, args ...any) {
	if g.Logf != nil {
		g.Logf(format, args...)
	}
}

// RequirePermission returns a net/http middleware that guards the route.
func (g *Guard) RequirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if status := g.Check(r, permission); status != 0 {
				WriteError(w, status)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// WriteError answers with a JSON error that never carries internal details.
func WriteError(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": http.StatusText(status)})
}
