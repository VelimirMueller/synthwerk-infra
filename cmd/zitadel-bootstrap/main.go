// Command zitadel-bootstrap sets up the Zitadel instance as code: the demo
// org, the synthwerk-api project and roles, the studio OIDC app, and the
// login, password and token policies. It is a compose one-shot; a rerun
// changes nothing.
//
//	zitadel-bootstrap           apply the setup
//	zitadel-bootstrap selftest  sign the test users in and check the token claims
//	zitadel-bootstrap delete-check  sign a throwaway user in with step-up and delete it in identity
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/VelimirMueller/synthwerk-infra/zitadel/bootstrap"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With(
		"service.name", "synthwerk-zitadel-bootstrap",
		"deployment.environment.name", os.Getenv("SYNTHWERK_PLATFORM_ENV"),
	)
	run := apply
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "selftest":
			run = selftest
		case "delete-check":
			run = deleteCheck
		case "widget-key":
			run = widgetKey
		default:
			// Never fall back to the full bootstrap on a typo.
			log.Error("unknown subcommand: want selftest, delete-check or widget-key", "arg", os.Args[1])
			os.Exit(2)
		}
	}
	if err := withTimeout(run, log); err != nil {
		log.Error("zitadel bootstrap failed", "err", err)
		os.Exit(1)
	}
}

// withTimeout runs fn with a signal-aware 2 min deadline; the defers run before main exits.
func withTimeout(fn func(context.Context, *slog.Logger) error, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	return fn(ctx, log)
}

func client() (*bootstrap.Client, error) {
	pat, err := readSecret(or(os.Getenv("SYNTHWERK_ZITADEL_ADMIN_PAT_FILE"), "/zitadel/admin/admin.pat"))
	if err != nil {
		return nil, err
	}
	host := os.Getenv("SYNTHWERK_ZITADEL_EXTERNAL_DOMAIN")
	if host == "" {
		return nil, errors.New("SYNTHWERK_ZITADEL_EXTERNAL_DOMAIN is empty (Zitadel finds its instance by Host)")
	}
	return &bootstrap.Client{
		BaseURL: or(os.Getenv("SYNTHWERK_ZITADEL_URL"), "http://zitadel:8080"),
		Host:    host,
		Token:   pat,
	}, nil
}

func apply(ctx context.Context, log *slog.Logger) error {
	cfg, err := bootstrap.ConfigFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	c, err := client()
	if err != nil {
		return err
	}
	r, err := bootstrap.Run(ctx, c, cfg, log)
	if err != nil {
		return err
	}
	log.Info("zitadel bootstrap done",
		"platform_org_id", r.PlatformOrgID, "demo_org_id", r.DemoOrgID,
		"project_id", r.ProjectID, "studio_client_id", r.StudioClientID,
		"test_users", len(r.TestUserIDs))
	return nil
}

// widgetKey writes the widget token signing key of identity when it is missing
// (synthwerk#30). It needs no Zitadel: the one-shot identity-widget-key runs it
// before identity starts, because identity reads the key once at start.
func widgetKey(_ context.Context, log *slog.Logger) error {
	path := or(os.Getenv("SYNTHWERK_IDENTITY_WIDGET_SIGNING_KEY_FILE"), "/keys/widget-signing.key")
	// 65532: nonroot in the distroless image of synthwerk-identity.
	made, err := bootstrap.EnsureWidgetKey(path, 65532)
	if err != nil {
		return err
	}
	log.Info("widget key ready", "path", path, "created", made)
	return nil
}

func selftest(ctx context.Context, log *slog.Logger) error {
	cfg, err := bootstrap.ConfigFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	if cfg.TestUserPassword == "" {
		return errors.New("SYNTHWERK_ZITADEL_TEST_USER_PASSWORD is empty: there are no test users")
	}
	c, err := client()
	if err != nil {
		return err
	}
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
	// The ids come from the same idempotent lookups the setup uses.
	r, err := bootstrap.Run(ctx, c, cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		return err
	}
	for _, u := range bootstrap.TestUsers {
		orgID := r.PlatformOrgID
		if u.Org == bootstrap.DemoOrg {
			orgID = r.DemoOrgID
		}
		checks := bootstrap.PasswordChecks(u.UserName, cfg.TestUserPassword)
		if cfg.MFAGate {
			if checks, err = mfaChecks(ctx, c, loginPAT, sc, cfg, u.UserName, r.TestUserIDs[u.UserName]); err != nil {
				return fmt.Errorf("%s: %w", u.UserName, err)
			}
		}
		claims, err := bootstrap.Mint(ctx, c, loginPAT, sc, cfg.StudioRedirectURIs[0], checks)
		if err != nil {
			return fmt.Errorf("%s: %w", u.UserName, err)
		}
		if cfg.MFAGate && !bootstrap.HasMFA(claims) {
			return fmt.Errorf("%s: password and TOTP sign-in: access token amr %v has no mfa", u.UserName, claims["amr"])
		}
		for _, role := range u.Roles {
			if err := bootstrap.CheckRoles(claims, orgID, role); err != nil {
				return fmt.Errorf("%s: %w", u.UserName, err)
			}
		}
		// sid or auth_time bind an account delete to the sign-in (synthwerk#41). Presence only, never the value.
		_, sid := claims["sid"]
		_, authTime := claims["auth_time"]
		log.Info("selftest ok", "user", u.UserName, "org_id", orgID, "roles", u.Roles, "amr", claims["amr"], "mfa_gate", cfg.MFAGate,
			"has_sid", sid, "has_auth_time", authTime)
	}
	return nil
}

// mfaChecks proves the MFA gate for one test user (synthwerk#94): a password-only
// sign-in must get no token. It then enrols TOTP and returns password and TOTP
// checks. The TOTP code is the one of the next 30 s step (Zitadel accepts one step
// of skew); the enrolment used the current step, so the codes are for different steps.
func mfaChecks(ctx context.Context, c *bootstrap.Client, loginPAT string, sc bootstrap.StudioClient, cfg bootstrap.Config, user, userID string) (map[string]any, error) {
	_, err := bootstrap.Mint(ctx, c, loginPAT, sc, cfg.StudioRedirectURIs[0], bootstrap.PasswordChecks(user, cfg.TestUserPassword))
	if err == nil {
		return nil, errors.New("password-only sign-in got a token: the MFA gate is not active")
	}
	if !errors.Is(err, bootstrap.ErrMFARefused) {
		return nil, fmt.Errorf("password-only sign-in: %w", err)
	}
	secret, err := bootstrap.EnrolTOTP(ctx, c, userID)
	if err != nil {
		return nil, err
	}
	code, err := bootstrap.TOTP(secret, time.Now().Add(30*time.Second))
	if err != nil {
		return nil, err
	}
	checks := bootstrap.PasswordChecks(user, cfg.TestUserPassword)
	checks["totp"] = map[string]any{"code": code}
	return checks, nil
}

func readSecret(path string) (string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: path from our own config
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return strings.TrimSpace(string(b)), nil
}

func or(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
