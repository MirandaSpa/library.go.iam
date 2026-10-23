// Package ginmw adapts the permissions guard to gin, which the older services use.
package ginmw

import (
	"github.com/gin-gonic/gin"

	iam "github.com/MirandaSpa/library.go.iam"
)

// RequirePermission aborts the request unless the guard lets it through.
func RequirePermission(g *iam.Guard, permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if status := g.Check(c.Request, permission); status != 0 {
			c.AbortWithStatusJSON(status, gin.H{"error": statusText(status)})
			return
		}
		c.Next()
	}
}

func statusText(status int) string {
	switch status {
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	default:
		return "Service Unavailable"
	}
}
