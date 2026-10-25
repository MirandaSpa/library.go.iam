// Package iam is the Go client of the permissions service (backend.k8s.iam).
//
// It answers "can this user do this on this branch?" (Can), "who can?" (Holders)
// and guards HTTP routes (Guard, and the ginmw package for gin). It has no cache:
// every call reads the service. It uses only the standard library and compiles
// with the Go versions of the older services.
package iam

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultTimeout = 3 * time.Second
	maxBody        = 1 << 20 // 1 MiB: responses are small lists of ids
)

// Client calls the internal API of the permissions service.
type Client struct {
	baseURL string
	http    *http.Client
	// retryWait is the first wait of RegisterInBackground; zero means one second (tests shorten it).
	retryWait time.Duration
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient replaces the HTTP client (transport, tracing, tests).
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.http = h } }

// WithRetryWait sets the first wait of RegisterInBackground between attempts (one
// second by default); it doubles after each failure up to 30 seconds.
func WithRetryWait(d time.Duration) Option { return func(c *Client) { c.retryWait = d } }

// New builds a client. baseURL is the service base path without the /internal
// segment, e.g. http://iam.dev.svc.cluster.local:8080/api/v2/iam.
func New(baseURL string, opts ...Option) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("iam: baseURL must be an absolute http(s) URL")
	}
	c := &Client{baseURL: strings.TrimRight(baseURL, "/"), http: &http.Client{Timeout: defaultTimeout}}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// Can reports whether the user holds the permission, on the branch when the
// permission is scoped by branch. Any failure to ask is an error, never "false":
// the caller decides what an unanswered question means.
func (c *Client) Can(ctx context.Context, userID, permission, branchID string) (bool, error) {
	if userID == "" || permission == "" {
		return false, errors.New("iam: userID and permission are required")
	}
	body, err := json.Marshal(map[string]string{"user_id": userID, "permission": permission, "branch_id": branchID})
	if err != nil {
		return false, fmt.Errorf("iam: encode check: %w", err)
	}
	var out struct {
		Allowed bool `json:"allowed"`
	}
	if err := c.do(ctx, http.MethodPost, c.baseURL+"/internal/check", bytes.NewReader(body), &out); err != nil {
		return false, err
	}
	return out.Allowed, nil
}

// Holders returns the internal ids of the users that hold the permission on the
// branch (the branch is required for permissions scoped by branch).
func (c *Client) Holders(ctx context.Context, permission, branchID string) ([]string, error) {
	if permission == "" {
		return nil, errors.New("iam: permission is required")
	}
	u := c.baseURL + "/internal/permissions/" + url.PathEscape(permission) + "/holders"
	if branchID != "" {
		u += "?branch=" + url.QueryEscape(branchID)
	}
	var out struct {
		UserIDs []string `json:"user_ids"`
	}
	if err := c.do(ctx, http.MethodGet, u, nil, &out); err != nil {
		return nil, err
	}
	return out.UserIDs, nil
}

// StatusError is a non-2xx answer of the permissions service. The body is not
// kept: it can carry details that must not reach logs or clients.
type StatusError struct{ Code int }

func (e *StatusError) Error() string { return fmt.Sprintf("iam: unexpected status %d", e.Code) }

func (c *Client) do(ctx context.Context, method, rawURL string, body io.Reader, out any) error {
	// The URL is built from the configured base URL and ids of the caller, never from client input.
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body) //nolint:gosec // G704: base URL comes from the service configuration
	if err != nil {
		return fmt.Errorf("iam: build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req) //nolint:gosec // G704: see above
	if err != nil {
		return fmt.Errorf("iam: request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
		return &StatusError{Code: resp.StatusCode}
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(out); err != nil {
		return fmt.Errorf("iam: decode response: %w", err)
	}
	return nil
}
