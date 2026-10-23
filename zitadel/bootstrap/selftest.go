package bootstrap

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// StudioScope is the scope the studio asks for (spike run1, variant A): the
// project audience, the roles of every org, and the user's own org.
func StudioScope(projectID string) string {
	return "openid profile urn:zitadel:iam:org:project:id:" + projectID + ":aud" +
		" urn:zitadel:iam:org:projects:roles urn:zitadel:iam:user:resourceowner"
}

// RolesClaim is the Zitadel claim that maps role -> {org id: org domain}.
const RolesClaim = "urn:zitadel:iam:org:project:roles"

// Mint signs a user in without a browser, as the login app does: authorize
// (PKCE), a session with the password check (login client PAT), finalize the
// auth request, then exchange the code with the studio client secret.
// It returns the access token claims. Use it for local and ci checks only.
func Mint(ctx context.Context, c *Client, loginPAT string, sc StudioClient, redirectURI, loginName, password string) (map[string]any, error) {
	verifier := rand.Text() + rand.Text()
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"client_id":             {sc.ClientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {StudioScope(sc.ProjectID)},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
		"state":                 {"selftest"},
	}
	loc, err := c.redirect(ctx, "/oauth/v2/authorize?"+q.Encode())
	if err != nil {
		return nil, err
	}
	authRequest := loc.Query().Get("authRequest")
	if authRequest == "" {
		return nil, fmt.Errorf("authorize: no authRequest in redirect %q", loc.Path)
	}

	login := &Client{BaseURL: c.BaseURL, Host: c.Host, Token: loginPAT, HTTP: c.HTTP}
	var sess struct {
		SessionID    string `json:"sessionId"`
		SessionToken string `json:"sessionToken"`
	}
	if err := login.Do(ctx, http.MethodPost, "/v2/sessions", "", map[string]any{
		"checks": map[string]any{"user": map[string]any{"loginName": loginName}, "password": map[string]any{"password": password}},
	}, &sess); err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}
	var cb struct {
		CallbackURL string `json:"callbackUrl"`
	}
	if err := login.Do(ctx, http.MethodPost, "/v2/oidc/auth_requests/"+authRequest, "", map[string]any{
		"session": map[string]any{"sessionId": sess.SessionID, "sessionToken": sess.SessionToken},
	}, &cb); err != nil {
		return nil, fmt.Errorf("finalize auth request: %w", err)
	}
	cbURL, err := url.Parse(cb.CallbackURL)
	if err != nil {
		return nil, err
	}
	code := cbURL.Query().Get("code")
	if code == "" {
		return nil, fmt.Errorf("callback has no code (error %q)", cbURL.Query().Get("error"))
	}

	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {verifier}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/oauth/v2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Host = c.Host
	// RFC 6749 section 2.3.1: id and secret are form-encoded before Basic auth.
	req.SetBasicAuth(url.QueryEscape(sc.ClientID), url.QueryEscape(sc.ClientSecret))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("token: read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// An OAuth error body (error, error_description) holds no token.
		var e struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &e)
		return nil, fmt.Errorf("token: status %d, %s: %s", resp.StatusCode, e.Error, e.Description)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, err
	}
	return jwtClaims(tok.AccessToken)
}

// CheckRoles is the claim contract the platform depends on (D-50): the token
// names the user's org and carries the role, granted in that org.
func CheckRoles(claims map[string]any, orgID, role string) error {
	if got := claims["urn:zitadel:iam:user:resourceowner:id"]; got != orgID {
		return fmt.Errorf("resourceowner %v, want %s", got, orgID)
	}
	roles, _ := claims[RolesClaim].(map[string]any)
	orgs, _ := roles[role].(map[string]any)
	if _, ok := orgs[orgID]; !ok {
		return fmt.Errorf("%s has no %q for org %s: %v", RolesClaim, role, orgID, claims[RolesClaim])
	}
	return nil
}

// jwtClaims decodes the payload without a signature check: the token comes
// straight from the token endpoint over the internal network.
func jwtClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("access token is not a JWT (set accessTokenType JWT)")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	return claims, json.Unmarshal(raw, &claims)
}

// redirect GETs path without following the redirect and returns its Location.
func (c *Client) redirect(ctx context.Context, path string) (*url.URL, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Host = c.Host
	hc := *c.httpClient()
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 300 || resp.StatusCode > 399 {
		return nil, fmt.Errorf("GET %s: status %d, want a redirect", strings.SplitN(path, "?", 2)[0], resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return nil, fmt.Errorf("GET %s: redirect without Location", strings.SplitN(path, "?", 2)[0])
	}
	return url.Parse(loc)
}
