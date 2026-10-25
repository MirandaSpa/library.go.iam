package ginmw

import (
	"github.com/gin-gonic/gin"

	iam "github.com/MirandaSpa/library.go.iam"
)

// Routes lists the routes the gin engine serves, to compare with the manifest in
// a CI test (iam.CheckRoutes).
func Routes(engine *gin.Engine) []iam.RouteKey {
	info := engine.Routes()
	out := make([]iam.RouteKey, 0, len(info))
	for _, r := range info {
		out = append(out, iam.RouteKey{Method: r.Method, Path: r.Path})
	}
	return out
}
