package bootstrap

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // G505: RFC 6238 TOTP uses HMAC-SHA1, as authenticator apps do
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// StudioScope is the scope the studio asks for (spike run1, variant A): the
// project audience, the roles of every org, and the user's own org.
func StudioScope(projectID string) string {
	return "openid profile urn:zitadel:iam:org:project:id:" + projectID + ":aud" +
		" urn:zitadel:iam:org:projects:roles urn:zitadel:iam:user:resourceowner"
}

// RolesClaim is the Zitadel claim that maps role -> {org id: org domain}.
const RolesClaim = "urn:zitadel:iam:org:project:roles"

// PasswordChecks are the session checks of a password-only sign-in.
func PasswordChecks(loginName, password string) map[string]any {
	return map[string]any{"user": map[string]any{"loginName": loginName}, "password": map[string]any{"password": password}}
}

// ErrMFARefused: the MFA gate refused to finish the sign-in (synthwerk#94). No
// code and no token exist.
var ErrMFARefused = errors.New("the MFA gate refused the sign-in")

// Mint signs a user in without a browser, as the login app does: authorize
// (PKCE), a session with checks (login client PAT), finalize the auth request,
// then exchange the code with the studio client secret.
// It returns the access token claims. A refusal of the MFA gate wraps
// ErrMFARefused. Use it for local and ci checks only.
func Mint(ctx context.Context, c *Client, loginPAT string, sc StudioClient, redirectURI string, checks map[string]any) (map[string]any, error) {
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
	if err := login.Do(ctx, http.MethodPost, "/v2/sessions", "", map[string]any{"checks": checks}, &sess); err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}
	var cb struct {
		CallbackURL string `json:"callbackUrl"`
	}
	if err := login.Do(ctx, http.MethodPost, "/v2/oidc/auth_requests/"+authRequest, "", map[string]any{
		"session": map[string]any{"sessionId": sess.SessionID, "sessionToken": sess.SessionToken},
	}, &cb); err != nil {
		var e *APIError
		if errors.As(err, &e) && e.Status == http.StatusForbidden && strings.Contains(e.Message, "mfa_required") {
			return nil, fmt.Errorf("finalize auth request: %w: %w", ErrMFARefused, err)
		}
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

// HasMFA reports whether the access token claims carry amr with "mfa", the rule of
// kit/auth RequireMFA in synthwerk-contracts.
func HasMFA(claims map[string]any) bool {
	amr, _ := claims["amr"].([]any)
	for _, v := range amr {
		if v == "mfa" {
			return true
		}
	}
	return false
}

// EnrolTOTP gives the user a new TOTP factor and returns its secret. An older TOTP
// factor of the user is removed first, so each selftest run starts clean.
// Test users only (local and ci).
func EnrolTOTP(ctx context.Context, c *Client, userID string) (string, error) {
	if err := c.Do(ctx, http.MethodDelete, "/v2/users/"+userID+"/totp", "", nil, nil); err != nil && !IsNotFound(err) {
		var e *APIError
		// Zitadel answers 400 or 412 when the user has no TOTP: nothing to remove.
		if !errors.As(err, &e) || (e.Status != http.StatusBadRequest && e.Status != http.StatusPreconditionFailed) {
			return "", fmt.Errorf("remove totp: %w", err)
		}
	}
	var reg struct {
		Secret string `json:"secret"`
	}
	if err := c.Do(ctx, http.MethodPost, "/v2/users/"+userID+"/totp", "", map[string]any{}, &reg); err != nil {
		return "", fmt.Errorf("register totp: %w", err)
	}
	if reg.Secret == "" {
		return "", errors.New("register totp: Zitadel returned no secret")
	}
	code, err := TOTP(reg.Secret, time.Now())
	if err != nil {
		return "", err
	}
	if err := c.Do(ctx, http.MethodPost, "/v2/users/"+userID+"/totp/verify", "", map[string]any{"code": code}, nil); err != nil {
		return "", fmt.Errorf("verify totp: %w", err)
	}
	return reg.Secret, nil
}

// TOTP is the RFC 6238 code (HMAC-SHA1, 6 digits, 30 s) for secret (base32) at t.
func TOTP(secret string, t time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimRight(secret, "=")))
	if err != nil {
		return "", fmt.Errorf("totp secret: %w", err)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(t.Unix()/30)) //nolint:gosec // G115: Unix time is positive
	mac := hmac.New(sha1.New, key)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", bin%1_000_000), nil
}
