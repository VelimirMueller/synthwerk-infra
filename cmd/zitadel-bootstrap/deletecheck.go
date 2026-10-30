package main

import (
	"context"
	"crypto/rand"
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

// deleteCheck proves the account delete of synthwerk#41 with real Zitadel tokens
// (local and ci only). It makes a throwaway user in the demo org, signs it in with
// password and TOTP and the studio step-up (prompt=login, max_age=0), and calls
// identity DELETE /v1/me: without X-Synthwerk-Id-Token it wants 403
// recent_mfa_required, with the fresh ID token 202. identity must trust Zitadel
// (issuer http://<domain>:8080, audience the project id). It logs status codes and
// the user id, never a token.
func deleteCheck(ctx context.Context, log *slog.Logger) error {
	cfg, err := bootstrap.ConfigFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	if cfg.TestUserPassword == "" {
		return errors.New("SYNTHWERK_ZITADEL_TEST_USER_PASSWORD is empty: delete-check runs in local and ci only")
	}
	c, err := client()
	if err != nil {
		return err
	}
	// Zitadel builds iss from Host: with the port the token says http://<domain>:8080,
	// the issuer identity trusts inside the stack (the alias on zitadel).
	c.Host = or(os.Getenv("SYNTHWERK_ZITADEL_ISSUER_HOST"), c.Host+":8080")
	loginPAT, err := readSecret(or(os.Getenv("SYNTHWERK_ZITADEL_LOGIN_PAT_FILE"), "/zitadel/bootstrap/login-client.pat"))
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(cfg.StudioClientFile)
	if err != nil {
		return err
	}
	var sc bootstrap.StudioClient
	if err := json.Unmarshal(raw, &sc); err != nil {
		return fmt.Errorf("%s: %w", cfg.StudioClientFile, err)
	}
	r, err := bootstrap.Run(ctx, c, cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		return err
	}
	userID, err := bootstrap.EnsureHuman(ctx, c, r.DemoOrgID, "delete-check."+strings.ToLower(rand.Text()[:10]), cfg.TestUserPassword)
	if err != nil {
		return fmt.Errorf("throwaway user: %w", err)
	}
	deleted := false
	defer func() {
		// identity's remover deletes the Zitadel user after a 202. Without one, remove it here.
		if !deleted {
			if err := c.Do(context.WithoutCancel(ctx), http.MethodDelete, "/v2/users/"+userID, "", nil, nil); err != nil {
				log.Warn("delete-check: throwaway user not removed", "user_id", userID, "err", err)
			}
		}
	}()
	secret, err := bootstrap.EnrolTOTP(ctx, c, userID)
	if err != nil {
		return err
	}
	// The enrolment used the code of the current 30 s step; sign in with the next one.
	code, err := bootstrap.TOTP(secret, time.Now().Add(30*time.Second))
	if err != nil {
		return err
	}
	checks := map[string]any{
		"user":     map[string]any{"userId": userID},
		"password": map[string]any{"password": cfg.TestUserPassword},
		"totp":     map[string]any{"code": code},
	}
	step := url.Values{"prompt": {"login"}, "max_age": {"0"}, "nonce": {rand.Text()}}
	tok, err := bootstrap.MintTokens(ctx, c, loginPAT, sc, cfg.StudioRedirectURIs[0], checks, step)
	if err != nil {
		return fmt.Errorf("step-up sign-in: %w", err)
	}
	if tok.ID == "" {
		return errors.New("step-up sign-in: no ID token")
	}
	identity := or(os.Getenv("SYNTHWERK_IDENTITY_URL"), "http://identity:8080")
	status, problem, err := deleteMe(ctx, identity, tok.Access, "")
	if err != nil {
		return err
	}
	log.Info("delete-check: DELETE /v1/me without ID token", "status", status, "code", problem)
	if status != http.StatusForbidden || problem != "recent_mfa_required" {
		return fmt.Errorf("without ID token: status %d code %q, want 403 recent_mfa_required", status, problem)
	}
	status, problem, err = deleteMe(ctx, identity, tok.Access, tok.ID)
	if err != nil {
		return err
	}
	log.Info("delete-check: DELETE /v1/me with the fresh ID token", "status", status, "code", problem)
	if status != http.StatusAccepted {
		return fmt.Errorf("with the fresh ID token: status %d code %q, want 202", status, problem)
	}
	deleted = true
	log.Info("delete-check ok", "user_id", userID)
	return nil
}

// deleteMe calls DELETE /v1/me and returns the status and the problem code.
func deleteMe(ctx context.Context, base, access, idToken string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, base+"/v1/me", http.NoBody) //nolint:gosec // G704: identity URL from our own config
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Authorization", "Bearer "+access)
	if idToken != "" {
		req.Header.Set("X-Synthwerk-Id-Token", idToken)
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req) //nolint:gosec // same G704 as above
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	var p struct {
		Code string `json:"code"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&p)
	return resp.StatusCode, p.Code, nil
}
