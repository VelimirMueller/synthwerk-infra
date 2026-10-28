// Package bootstrap sets up the Synthwerk Zitadel instance as code: orgs, the
// project and its roles, the studio OIDC app, and the instance policies.
//
// Run is idempotent. It reads before it writes, creates only what is missing,
// and sends full-replace updates (login policy, OIDC settings) built from the
// current value, so fields it does not own keep their value.
package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client calls the Zitadel v1 REST API (management, admin) inside the stack.
// Zitadel finds its instance by host name, so every request carries Host.
type Client struct {
	// BaseURL is the API address, for example http://zitadel:8080.
	BaseURL string
	// Host is the instance host (external domain and port), for example auth.localhost:8080.
	Host string
	// Token is the bearer token (a PAT).
	Token string
	// HTTP is the client to use. Nil means a client with a 15 s timeout.
	HTTP *http.Client
}

// APIError is a non-2xx answer from Zitadel.
type APIError struct {
	Method, Path string
	Status       int
	// Code is the gRPC code in the body (6 = already exists, 9 = failed precondition).
	Code    int
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("zitadel %s %s: status %d, code %d: %s", e.Method, e.Path, e.Status, e.Code, e.Message)
}

// IsAlreadyExists is true for "already exists" answers (gRPC code 6, HTTP 409).
// Some Zitadel v4 endpoints (project grant members) answer it with 404, code 5
// and the message key Errors.AlreadyExists.
func IsAlreadyExists(err error) bool {
	var e *APIError
	return errors.As(err, &e) && (e.Code == 6 || e.Status == http.StatusConflict ||
		strings.Contains(e.Message, "Errors.AlreadyExists"))
}

// IsNotFound is true for "not found" answers (gRPC code 5, HTTP 404).
func IsNotFound(err error) bool {
	var e *APIError
	return errors.As(err, &e) && (e.Code == 5 || e.Status == http.StatusNotFound) &&
		!strings.Contains(e.Message, "Errors.AlreadyExists")
}

// IsNotChanged is true when an update had nothing to change. Some Zitadel
// endpoints answer this with code 9 instead of 200.
func IsNotChanged(err error) bool {
	var e *APIError
	if !errors.As(err, &e) || e.Code != 9 {
		return false
	}
	m := strings.ToLower(e.Message)
	return strings.Contains(m, "not changed") || strings.Contains(m, "not been changed") || strings.Contains(m, "notchanged") || strings.Contains(m, "no changes")
}

// Do sends one request. body is JSON-encoded when not nil; out receives the
// JSON answer when not nil. orgID sets x-zitadel-orgid (empty = the caller's org).
func (c *Client) Do(ctx context.Context, method, path, orgID string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode %s %s: %w", method, path, err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, rd)
	if err != nil {
		return err
	}
	req.Host = c.Host
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if orgID != "" {
		req.Header.Set("x-zitadel-orgid", orgID)
	}
	res, err := c.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("zitadel %s %s: %w", method, path, err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("zitadel %s %s: read body: %w", method, path, err)
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		e := &APIError{Method: method, Path: path, Status: res.StatusCode}
		var g struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		if json.Unmarshal(data, &g) == nil {
			e.Code, e.Message = g.Code, g.Message
		}
		return e
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("zitadel %s %s: decode: %w", method, path, err)
		}
	}
	return nil
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}
