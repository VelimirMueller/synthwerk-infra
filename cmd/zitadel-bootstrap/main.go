// Command zitadel-bootstrap sets up the Zitadel instance as code: the demo
// org, the synthwerk-api project and roles, the studio OIDC app, and the
// login, password and token policies. It is a compose one-shot; a rerun
// changes nothing.
//
//	zitadel-bootstrap           apply the setup
//	zitadel-bootstrap selftest  sign the test users in and check the token claims
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
	if len(os.Args) > 1 && os.Args[1] == "selftest" {
		run = selftest
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
		claims, err := bootstrap.Mint(ctx, c, loginPAT, sc, cfg.StudioRedirectURIs[0], u.UserName, cfg.TestUserPassword)
		if err != nil {
			return fmt.Errorf("%s: %w", u.UserName, err)
		}
		for _, role := range u.Roles {
			if err := bootstrap.CheckRoles(claims, orgID, role); err != nil {
				return fmt.Errorf("%s: %w", u.UserName, err)
			}
		}
		log.Info("selftest ok", "user", u.UserName, "org_id", orgID, "roles", u.Roles, "amr", claims["amr"])
	}
	return nil
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
