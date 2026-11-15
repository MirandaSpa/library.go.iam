package iam

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Manifest is what a service declares to iam: the permissions it defines and the
// routes that need them. Each service keeps it in a permissions.yaml at the root of
// its repo and registers it when it starts (RegisterManifest); iam then knows which
// permission each route requires, for the Ingress auth-url and for the legacy.
//
// Registering a manifest does not give permissions to anybody: it only adds to the
// catalog. The routes a service registers replace the ones it had.
type Manifest struct {
	Service     string               `yaml:"service" json:"-"`
	Permissions []ManifestPermission `yaml:"permissions" json:"permissions"`
	Routes      []ManifestRoute      `yaml:"routes" json:"routes,omitempty"`
}

// ManifestPermission is one permission of the catalog. The id is
// area:resource:action, in English; the label is what administrators read.
type ManifestPermission struct {
	ID          string `yaml:"id" json:"id"`
	Label       string `yaml:"label" json:"label"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	Scope       string `yaml:"scope,omitempty" json:"scope,omitempty"` // branch (default) or global
	Audit       string `yaml:"audit,omitempty" json:"audit,omitempty"` // denied (default) or always
	Kind        string `yaml:"kind,omitempty" json:"kind,omitempty"`   // entry (default) or internal
}

// ManifestRoute links a route to the permission it requires, or marks it public
// (any valid token may call it, no permission needed). Path is the full path with
// {name} for the segments that vary, e.g. /api/v2/storage/reception/{id}.
type ManifestRoute struct {
	Method     string `yaml:"method" json:"method"`
	Path       string `yaml:"path" json:"path"`
	Permission string `yaml:"permission,omitempty" json:"permission,omitempty"`
	Public     bool   `yaml:"public,omitempty" json:"public,omitempty"`
}

var (
	serviceName = regexp.MustCompile(`^[a-z0-9_-]{1,60}$`)
	segmentName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	httpMethods = map[string]bool{http.MethodGet: true, http.MethodPost: true, http.MethodPut: true, http.MethodPatch: true, http.MethodDelete: true}
)

// Validate reports everything wrong with the manifest at once, so that a CI test
// shows all the problems in one run. It applies the same rules iam applies when it
// receives the manifest.
func (m Manifest) Validate() error {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	if !serviceName.MatchString(m.Service) {
		add("service %q must be lowercase letters, digits, - or _ (up to 60)", m.Service)
	}
	declared := map[string]bool{}
	for _, p := range m.Permissions {
		parts := strings.Split(p.ID, ":")
		if len(parts) != 3 || !allSegments(parts) {
			add("permission %q must be area:resource:action, in lowercase", p.ID)
		}
		if declared[p.ID] {
			add("permission %q is declared twice", p.ID)
		}
		declared[p.ID] = true
		if strings.TrimSpace(p.Label) == "" {
			add("permission %q needs a label", p.ID)
		}
		if !oneOf(p.Scope, "", "branch", "global") {
			add("permission %q: scope must be branch or global", p.ID)
		}
		if !oneOf(p.Audit, "", "denied", "always") {
			add("permission %q: audit must be denied or always", p.ID)
		}
		if !oneOf(p.Kind, "", "entry", "internal") {
			add("permission %q: kind must be entry or internal", p.ID)
		}
	}
	seen := map[string]bool{}
	for _, r := range m.Routes {
		where := r.Method + " " + r.Path
		if !httpMethods[r.Method] {
			add("route %s: method must be GET, POST, PUT, PATCH or DELETE", where)
		}
		if !strings.HasPrefix(r.Path, "/") {
			add("route %s: path must start with /", where)
		}
		key := r.Method + " " + normalizePath(r.Path)
		if seen[key] {
			add("route %s is declared twice", where)
		}
		seen[key] = true
		switch {
		case r.Public && r.Permission != "":
			add("route %s: it is either public or needs a permission, not both", where)
		case !r.Public && r.Permission == "":
			add("route %s: declare its permission, or mark it public", where)
		case !r.Public && !declared[r.Permission]:
			add("route %s uses %q, which the manifest does not declare", where, r.Permission)
		}
	}
	if len(problems) > 0 {
		return errors.New("iam: invalid manifest: " + strings.Join(problems, "; "))
	}
	return nil
}

func allSegments(parts []string) bool {
	for _, p := range parts {
		if !segmentName.MatchString(p) {
			return false
		}
	}
	return true
}

func oneOf(s string, options ...string) bool {
	for _, o := range options {
		if s == o {
			return true
		}
	}
	return false
}

// RegisterManifest sends the manifest to iam (idempotent: the permissions are
// added or updated and the routes of the service are replaced). It validates the
// manifest first, so a mistake never reaches iam.
func (c *Client) RegisterManifest(ctx context.Context, m Manifest) error {
	if err := m.Validate(); err != nil {
		return err
	}
	body, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("iam: encode manifest: %w", err)
	}
	var out struct {
		Permissions int `json:"permissions"`
		Routes      int `json:"routes"`
	}
	return c.do(ctx, http.MethodPut, c.baseURL+"/internal/manifests/"+url.PathEscape(m.Service), bytes.NewReader(body), &out)
}

// Backoff of RegisterInBackground between attempts.
const (
	firstRetry = time.Second
	maxRetry   = 30 * time.Second
)

// RegisterInBackground registers the manifest without blocking the start of the
// service and without failing it when iam is not up yet: it retries with a growing
// wait until it succeeds or ctx ends. logf receives the progress (defaults to
// nothing). An invalid manifest is returned at once, it is a programming error.
// The goroutine ends with ctx; done is closed when it does.
func (c *Client) RegisterInBackground(ctx context.Context, m Manifest, logf func(format string, args ...any)) (done <-chan struct{}, err error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	wait := c.retryWait
	if wait == 0 {
		wait = firstRetry
	}
	ch := make(chan struct{})
	go func() {
		defer close(ch)
		for {
			err := c.RegisterManifest(ctx, m)
			if err == nil {
				logf("iam: manifest of %s registered (%d permissions, %d routes)", m.Service, len(m.Permissions), len(m.Routes))
				return
			}
			logf("iam: could not register the manifest of %s, retrying in %s: %v", m.Service, wait, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			wait = min(wait*2, maxRetry)
		}
	}()
	return ch, nil
}

// RouteKey is a route a service serves: its method and full path.
type RouteKey struct {
	Method string
	Path   string // {name} or :name for the segments that vary
}

// CheckRoutes compares the routes a service really serves with its manifest, for
// a CI test: every served route must be declared (as protected or public) and
// every declared route must exist, so the manifest cannot drift from the code.
// Path parameters are compared by position, not by name. ignore lists the served
// routes that do not need to be declared (health probes, docs).
func CheckRoutes(m Manifest, served []RouteKey, ignore ...RouteKey) []string {
	skip := map[string]bool{}
	for _, r := range ignore {
		skip[r.Method+" "+normalizePath(r.Path)] = true
	}
	declared := map[string]bool{}
	for _, r := range m.Routes {
		declared[r.Method+" "+normalizePath(r.Path)] = true
	}
	actual := map[string]RouteKey{}
	for _, r := range served {
		actual[r.Method+" "+normalizePath(r.Path)] = r
	}

	var problems []string
	for key, r := range actual {
		if !declared[key] && !skip[key] {
			problems = append(problems, fmt.Sprintf("the service serves %s %s but the manifest does not declare it", r.Method, r.Path))
		}
	}
	for _, r := range m.Routes {
		if _, ok := actual[r.Method+" "+normalizePath(r.Path)]; !ok {
			problems = append(problems, fmt.Sprintf("the manifest declares %s %s but the service does not serve it", r.Method, r.Path))
		}
	}
	sort.Strings(problems)
	return problems
}

// normalizePath makes {id}, :id and {productId} the same segment, and drops a
// trailing slash, so routes compare by shape.
func normalizePath(p string) string {
	segs := strings.Split(strings.TrimRight(p, "/"), "/")
	for i, s := range segs {
		if strings.HasPrefix(s, ":") || (strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}")) {
			segs[i] = "{}"
		}
	}
	return strings.Join(segs, "/")
}
