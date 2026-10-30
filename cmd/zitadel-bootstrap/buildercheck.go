package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/VelimirMueller/synthwerk-infra/zitadel/bootstrap"
)

// builderCheck proves that studio has its page builder database (synthwerk#107, local and
// ci only). It signs owner.demo in through the studio's own code flow (login, Zitadel
// authorize, session with password and TOTP, finalize, studio callback), then calls
// GET /api/auth/session and GET /api/builder/pages with the session cookie. Without a database
// URL the builder answers 503 builder_not_configured to a signed-in admin, so any other
// answer means studio read its database settings. It logs status codes, never a token
// or a cookie.
func builderCheck(ctx context.Context, log *slog.Logger) error {
	cfg, err := bootstrap.ConfigFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	if cfg.TestUserPassword == "" {
		return errors.New("SYNTHWERK_ZITADEL_TEST_USER_PASSWORD is empty: builder-check runs in local and ci only")
	}
	c, err := client()
	if err != nil {
		return err
	}
	// Studio trusts the issuer http://<domain>:8080 (the alias on zitadel): Zitadel builds
	// iss from Host, so every call here sends the port as well.
	c.Host = or(os.Getenv("SYNTHWERK_ZITADEL_ISSUER_HOST"), c.Host+":8080")
	loginPAT, err := readSecret(or(os.Getenv("SYNTHWERK_ZITADEL_LOGIN_PAT_FILE"), "/zitadel/bootstrap/login-client.pat"))
	if err != nil {
		return err
	}
	r, err := bootstrap.Run(ctx, c, cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		return err
	}
	const user = "owner.demo"
	checks := bootstrap.PasswordChecks(user, cfg.TestUserPassword)
	if cfg.MFAGate {
		secret, err := bootstrap.EnrolTOTP(ctx, c, r.TestUserIDs[user])
		if err != nil {
			return err
		}
		// The enrolment used the code of the current 30 s step; sign in with the next one.
		code, err := bootstrap.TOTP(secret, time.Now().Add(30*time.Second))
		if err != nil {
			return err
		}
		checks["totp"] = map[string]any{"code": code}
	}

	s := &studioClient{
		base: strings.TrimRight(or(os.Getenv("SYNTHWERK_STUDIO_URL"), "http://studio:3000"), "/"),
		http: &http.Client{
			Timeout:       15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		cookies: map[string]string{},
	}
	status, loc, err := s.get(ctx, s.base, "/api/auth/login")
	if err != nil {
		return err
	}
	if status != http.StatusFound || loc == nil {
		return fmt.Errorf("studio login: status %d, want 302 to Zitadel", status)
	}
	// The authorize URL names the public issuer; call Zitadel inside the stack with its Host.
	status, loc, err = s.getHost(ctx, c.BaseURL, loc.RequestURI(), c.Host)
	if err != nil {
		return err
	}
	authRequest := ""
	if loc != nil {
		authRequest = loc.Query().Get("authRequest")
	}
	if authRequest == "" {
		return fmt.Errorf("authorize: status %d, no authRequest in the redirect", status)
	}

	login := &bootstrap.Client{BaseURL: c.BaseURL, Host: c.Host, Token: loginPAT}
	var sess struct {
		SessionID    string `json:"sessionId"`
		SessionToken string `json:"sessionToken"`
	}
	if err := login.Do(ctx, http.MethodPost, "/v2/sessions", "", map[string]any{"checks": checks}, &sess); err != nil {
		return fmt.Errorf("session: %w", err)
	}
	var cb struct {
		CallbackURL string `json:"callbackUrl"`
	}
	if err := login.Do(ctx, http.MethodPost, "/v2/oidc/auth_requests/"+authRequest, "", map[string]any{
		"session": map[string]any{"sessionId": sess.SessionID, "sessionToken": sess.SessionToken},
	}, &cb); err != nil {
		return fmt.Errorf("finalize auth request: %w", err)
	}
	cbURL, err := url.Parse(cb.CallbackURL)
	if err != nil {
		return err
	}
	// The callback URL names the published studio port; call studio inside the stack.
	status, loc, err = s.get(ctx, s.base, cbURL.RequestURI())
	if err != nil {
		return err
	}
	if _, ok := s.cookies["__Host-sw_session"]; !ok {
		where := ""
		if loc != nil {
			where = loc.Path + "?" + loc.Query().Get("error")
		}
		return fmt.Errorf("studio callback: status %d, redirect %q, no session cookie", status, where)
	}
	sessionStatus, _, err := s.get(ctx, s.base, "/api/auth/session")
	if err != nil {
		return err
	}
	builderStatus, code, err := s.getJSONCode(ctx, "/api/builder/pages")
	if err != nil {
		return err
	}
	log.Info("builder-check: studio session and builder",
		"session_status", sessionStatus, "builder_status", builderStatus, "code", code)
	if sessionStatus != http.StatusOK {
		return fmt.Errorf("studio session: status %d, want 200", sessionStatus)
	}
	if builderStatus == http.StatusServiceUnavailable || builderStatus >= 500 {
		return fmt.Errorf("builder: status %d code %q with a valid admin session", builderStatus, code)
	}
	log.Info("builder-check ok", "builder_status", builderStatus)
	return nil
}

// studioClient is a tiny cookie-keeping client. Studio sets __Host- cookies with Secure;
// inside the stack studio speaks plain HTTP, so the cookies are kept by hand.
type studioClient struct {
	base    string
	http    *http.Client
	cookies map[string]string
}

func (s *studioClient) get(ctx context.Context, base, path string) (int, *url.URL, error) {
	return s.getHost(ctx, base, path, "")
}

// getHost GETs base+path without following a redirect. It sends the kept cookies to the
// studio only and returns the status and the Location.
func (s *studioClient) getHost(ctx context.Context, base, path, host string) (int, *url.URL, error) {
	resp, err := s.do(ctx, base, path, host)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	var loc *url.URL
	if l := resp.Header.Get("Location"); l != "" {
		if loc, err = url.Parse(l); err != nil {
			return 0, nil, err
		}
	}
	return resp.StatusCode, loc, nil
}

// getJSONCode GETs a studio path and returns the status and the error code of the body.
func (s *studioClient) getJSONCode(ctx context.Context, path string) (int, string, error) {
	resp, err := s.do(ctx, s.base, path, "")
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	var p struct {
		Code string `json:"code"`
		Data struct {
			Code string `json:"code"`
		} `json:"data"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&p)
	return resp.StatusCode, or(p.Data.Code, p.Code), nil
}

func (s *studioClient) do(ctx context.Context, base, path, host string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, http.NoBody) //nolint:gosec // G704: studio and Zitadel URLs from our own config
	if err != nil {
		return nil, err
	}
	if host != "" {
		req.Host = host
	}
	if base == s.base && len(s.cookies) > 0 {
		pairs := make([]string, 0, len(s.cookies))
		for k, v := range s.cookies {
			pairs = append(pairs, k+"="+v)
		}
		req.Header.Set("Cookie", strings.Join(pairs, "; "))
	}
	resp, err := s.http.Do(req) //nolint:gosec // G704: studio and Zitadel URLs from our own config
	if err != nil {
		return nil, err
	}
	if base == s.base {
		for _, ck := range resp.Cookies() {
			if ck.MaxAge < 0 || ck.Value == "" {
				delete(s.cookies, ck.Name)
				continue
			}
			s.cookies[ck.Name] = ck.Value
		}
	}
	return resp, nil
}
