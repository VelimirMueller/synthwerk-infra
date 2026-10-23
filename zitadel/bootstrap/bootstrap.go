package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"
)

// Names and roles the platform relies on (D-44: org wording, role operator).
const (
	PlatformOrg = "synthwerk"
	DemoOrg     = "demo"
	Project     = "synthwerk-api"
	StudioApp   = "studio"
)

// Roles of the project. operator is the platform owner role (D-44).
var Roles = []string{"operator", "owner", "admin", "member", "end_user"}

// DemoGrantRoles are the roles the demo org may give to its users.
var DemoGrantRoles = []string{"admin", "member", "end_user"}

// Config is what Run sets up. Load it with ConfigFromEnv.
type Config struct {
	// StudioRedirectURIs and StudioLogoutURIs are exact-match URIs (no wildcard).
	StudioRedirectURIs []string
	StudioLogoutURIs   []string
	// StudioClientFile receives the studio client id and secret (mode 0600).
	StudioClientFile string
	// TestUserPassword creates the test users when not empty (local and ci only).
	TestUserPassword string
	// AccessTokenLifetime is the OIDC access token lifetime, for example "300s".
	AccessTokenLifetime string
}

// TestUser is a user that the bootstrap creates when TestUserPassword is set.
type TestUser struct {
	UserName string
	Org      string // PlatformOrg or DemoOrg
	Roles    []string
}

// TestUsers are the local and ci users. Their login name is the bare user name.
var TestUsers = []TestUser{
	{UserName: "operator.test", Org: PlatformOrg, Roles: []string{"operator"}},
	{UserName: "member.demo", Org: DemoOrg, Roles: []string{"member"}},
}

// ConfigFromEnv reads SYNTHWERK_ZITADEL_* settings. getenv is os.Getenv in production.
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	cfg := Config{
		StudioRedirectURIs:  list(getenv("SYNTHWERK_ZITADEL_STUDIO_REDIRECT_URIS"), "http://localhost:3000/api/auth/callback"),
		StudioLogoutURIs:    list(getenv("SYNTHWERK_ZITADEL_STUDIO_LOGOUT_URIS"), "http://localhost:3000/"),
		StudioClientFile:    or(getenv("SYNTHWERK_ZITADEL_STUDIO_CLIENT_FILE"), "/zitadel/admin/studio-client.json"),
		TestUserPassword:    testPassword(getenv("SYNTHWERK_ZITADEL_TEST_USER_PASSWORD")),
		AccessTokenLifetime: or(getenv("SYNTHWERK_ZITADEL_ACCESS_TOKEN_LIFETIME"), "300s"),
	}
	if len(cfg.StudioRedirectURIs) == 0 {
		return Config{}, errors.New("SYNTHWERK_ZITADEL_STUDIO_REDIRECT_URIS: want at least one URI")
	}
	if _, err := time.ParseDuration(cfg.AccessTokenLifetime); err != nil {
		return Config{}, fmt.Errorf("SYNTHWERK_ZITADEL_ACCESS_TOKEN_LIFETIME: %w", err)
	}
	for _, u := range append(slices.Clone(cfg.StudioRedirectURIs), cfg.StudioLogoutURIs...) {
		if strings.Contains(u, "*") || (!strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://")) {
			return Config{}, fmt.Errorf("studio URI %q: want an exact http(s) URI without wildcard", u)
		}
	}
	return cfg, nil
}

// StudioClient is the content of StudioClientFile.
type StudioClient struct {
	ProjectID    string `json:"project_id"`
	AppID        string `json:"app_id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// Result holds the ids that Run found or made. It holds no secret.
type Result struct {
	PlatformOrgID, DemoOrgID, ProjectID, DemoGrantID, StudioAppID, StudioClientID string
	TestUserIDs                                                                   map[string]string
}

// Run sets up the instance. A second run with the same config changes nothing.
func Run(ctx context.Context, c *Client, cfg Config, log *slog.Logger) (Result, error) {
	r := Result{TestUserIDs: map[string]string{}}
	var me struct {
		Org struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"org"`
	}
	if err := c.Do(ctx, http.MethodGet, "/management/v1/orgs/me", "", nil, &me); err != nil {
		return r, err
	}
	if me.Org.Name != PlatformOrg {
		return r, fmt.Errorf("the bootstrap PAT belongs to org %q, want %q (ZITADEL_FIRSTINSTANCE_ORG_NAME)", me.Org.Name, PlatformOrg)
	}
	r.PlatformOrgID = me.Org.ID

	steps := []struct {
		name string
		fn   func() error
	}{
		{"demo org", func() (err error) { r.DemoOrgID, err = ensureOrg(ctx, c, DemoOrg); return }},
		{"project", func() (err error) { r.ProjectID, err = ensureProject(ctx, c); return }},
		{"roles", func() error { return ensureRoles(ctx, c, r.ProjectID) }},
		{"demo grant", func() (err error) { r.DemoGrantID, err = ensureGrant(ctx, c, r.ProjectID, r.DemoOrgID); return }},
		{"studio app", func() (err error) {
			r.StudioAppID, r.StudioClientID, err = ensureStudioApp(ctx, c, cfg, r.ProjectID)
			return
		}},
		{"login policy", func() error { return ensureLoginPolicy(ctx, c) }},
		{"password policy", func() error { return ensurePasswordPolicies(ctx, c) }},
		{"oidc settings", func() error { return ensureOIDCSettings(ctx, c, cfg.AccessTokenLifetime) }},
	}
	if cfg.TestUserPassword != "" {
		steps = append(steps, struct {
			name string
			fn   func() error
		}{"test users", func() error { return ensureTestUsers(ctx, c, cfg.TestUserPassword, &r) }})
	}
	for _, s := range steps {
		if err := s.fn(); err != nil {
			return r, fmt.Errorf("%s: %w", s.name, err)
		}
		log.Info("bootstrap step done", "step", s.name)
	}
	return r, nil
}

func nameQuery(name string) map[string]any {
	return map[string]any{"queries": []any{map[string]any{"nameQuery": map[string]any{"name": name, "method": "TEXT_QUERY_METHOD_EQUALS"}}}}
}

type idResult struct {
	Result []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"result"`
}

func ensureOrg(ctx context.Context, c *Client, name string) (string, error) {
	var found idResult
	if err := c.Do(ctx, http.MethodPost, "/admin/v1/orgs/_search", "", nameQuery(name), &found); err != nil {
		return "", err
	}
	for _, o := range found.Result {
		if o.Name == name {
			return o.ID, nil
		}
	}
	var made struct {
		ID string `json:"id"`
	}
	err := c.Do(ctx, http.MethodPost, "/management/v1/orgs", "", map[string]any{"name": name}, &made)
	return made.ID, err
}

func ensureProject(ctx context.Context, c *Client) (string, error) {
	want := map[string]any{"name": Project, "projectRoleAssertion": true, "projectRoleCheck": false, "hasProjectCheck": false}
	var found idResult
	if err := c.Do(ctx, http.MethodPost, "/management/v1/projects/_search", "", nameQuery(Project), &found); err != nil {
		return "", err
	}
	for _, p := range found.Result {
		if p.Name == Project {
			// Role assertion puts the roles claim into every token: keep it on.
			if err := c.Do(ctx, http.MethodPut, "/management/v1/projects/"+p.ID, "", want, nil); err != nil && !IsNotChanged(err) {
				return "", err
			}
			return p.ID, nil
		}
	}
	var made struct {
		ID string `json:"id"`
	}
	err := c.Do(ctx, http.MethodPost, "/management/v1/projects", "", want, &made)
	return made.ID, err
}

func ensureRoles(ctx context.Context, c *Client, projectID string) error {
	var found struct {
		Result []struct {
			Key string `json:"key"`
		} `json:"result"`
	}
	if err := c.Do(ctx, http.MethodPost, "/management/v1/projects/"+projectID+"/roles/_search", "", map[string]any{}, &found); err != nil {
		return err
	}
	have := map[string]bool{}
	for _, r := range found.Result {
		have[r.Key] = true
	}
	for _, role := range Roles {
		if have[role] {
			continue
		}
		err := c.Do(ctx, http.MethodPost, "/management/v1/projects/"+projectID+"/roles", "", map[string]any{"roleKey": role, "displayName": role}, nil)
		if err != nil && !IsAlreadyExists(err) {
			return err
		}
	}
	return nil
}

func ensureGrant(ctx context.Context, c *Client, projectID, orgID string) (string, error) {
	var found struct {
		Result []struct {
			GrantID         string   `json:"grantId"`
			GrantedOrgID    string   `json:"grantedOrgId"`
			GrantedRoleKeys []string `json:"grantedRoleKeys"`
		} `json:"result"`
	}
	if err := c.Do(ctx, http.MethodPost, "/management/v1/projects/"+projectID+"/grants/_search", "", map[string]any{}, &found); err != nil {
		return "", err
	}
	for _, g := range found.Result {
		if g.GrantedOrgID != orgID {
			continue
		}
		if !sameSet(g.GrantedRoleKeys, DemoGrantRoles) {
			err := c.Do(ctx, http.MethodPut, "/management/v1/projects/"+projectID+"/grants/"+g.GrantID, "", map[string]any{"roleKeys": DemoGrantRoles}, nil)
			if err != nil && !IsNotChanged(err) {
				return "", err
			}
		}
		return g.GrantID, nil
	}
	var made struct {
		GrantID string `json:"grantId"`
	}
	err := c.Do(ctx, http.MethodPost, "/management/v1/projects/"+projectID+"/grants", "", map[string]any{"grantedOrgId": orgID, "roleKeys": DemoGrantRoles}, &made)
	return made.GrantID, err
}

// studioOIDC is the full OIDC config of the studio app (the update is a full replace).
func studioOIDC(cfg Config) map[string]any {
	dev := false
	for _, u := range append(slices.Clone(cfg.StudioRedirectURIs), cfg.StudioLogoutURIs...) {
		if strings.HasPrefix(u, "http://") {
			dev = true // Zitadel accepts http redirect URIs only in dev mode.
		}
	}
	// G101: enum names (OIDC_AUTH_METHOD_TYPE_BASIC), no credential.
	return map[string]any{ //nolint:gosec
		"redirectUris":             cfg.StudioRedirectURIs,
		"postLogoutRedirectUris":   cfg.StudioLogoutURIs,
		"responseTypes":            []string{"OIDC_RESPONSE_TYPE_CODE"},
		"grantTypes":               []string{"OIDC_GRANT_TYPE_AUTHORIZATION_CODE", "OIDC_GRANT_TYPE_REFRESH_TOKEN"},
		"appType":                  "OIDC_APP_TYPE_WEB",
		"authMethodType":           "OIDC_AUTH_METHOD_TYPE_BASIC",
		"accessTokenType":          "OIDC_TOKEN_TYPE_JWT",
		"accessTokenRoleAssertion": true,
		"idTokenRoleAssertion":     true,
		"idTokenUserinfoAssertion": false,
		"devMode":                  dev,
	}
}

func ensureStudioApp(ctx context.Context, c *Client, cfg Config, projectID string) (appID, clientID string, err error) {
	var found struct {
		Result []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			OIDCConfig struct {
				ClientID string `json:"clientId"`
			} `json:"oidcConfig"`
		} `json:"result"`
	}
	base := "/management/v1/projects/" + projectID + "/apps"
	if err := c.Do(ctx, http.MethodPost, base+"/_search", "", nameQuery(StudioApp), &found); err != nil {
		return "", "", err
	}
	for _, a := range found.Result {
		if a.Name != StudioApp {
			continue
		}
		if err := c.Do(ctx, http.MethodPut, base+"/"+a.ID+"/oidc_config", "", studioOIDC(cfg), nil); err != nil && !IsNotChanged(err) {
			return "", "", err
		}
		// The secret is shown only once. Without a file for this app, make a new one.
		if !clientFileFor(cfg.StudioClientFile, a.ID, a.OIDCConfig.ClientID) {
			var sec struct {
				ClientSecret string `json:"clientSecret"`
			}
			if err := c.Do(ctx, http.MethodPost, base+"/"+a.ID+"/oidc_config/_generate_client_secret", "", map[string]any{}, &sec); err != nil {
				return "", "", err
			}
			if err := writeClient(cfg.StudioClientFile, StudioClient{projectID, a.ID, a.OIDCConfig.ClientID, sec.ClientSecret}); err != nil {
				return "", "", err
			}
		}
		return a.ID, a.OIDCConfig.ClientID, nil
	}
	body := studioOIDC(cfg)
	body["name"] = StudioApp
	var made struct {
		AppID        string `json:"appId"`
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
	}
	if err := c.Do(ctx, http.MethodPost, base+"/oidc", "", body, &made); err != nil {
		return "", "", err
	}
	return made.AppID, made.ClientID, writeClient(cfg.StudioClientFile, StudioClient{projectID, made.AppID, made.ClientID, made.ClientSecret})
}

// clientFileFor is true when path holds the client of this app. A missing,
// unreadable or foreign file (the app was made again) needs a new secret.
func clientFileFor(path, appID, clientID string) bool {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: path from our own config
	if err != nil {
		return false
	}
	var sc StudioClient
	return json.Unmarshal(raw, &sc) == nil && sc.AppID == appID && sc.ClientID == clientID && sc.ClientSecret != ""
}

func writeClient(path string, sc StudioClient) error {
	// G117: writing the secret is the point; the file is 0600 in the zitadel-admin volume.
	b, err := json.MarshalIndent(sc, "", "  ") //nolint:gosec
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// updateFromCurrent GETs a full-replace resource, sets the owned fields and PUTs
// it back, so the fields it does not set keep their value (a PUT with missing
// fields resets them, see the spike).
func updateFromCurrent(ctx context.Context, c *Client, getPath, putPath, key string, set map[string]any) error {
	var cur map[string]json.RawMessage
	if err := c.Do(ctx, http.MethodGet, getPath, "", nil, &cur); err != nil {
		return err
	}
	var obj map[string]any
	if err := json.Unmarshal(cur[key], &obj); err != nil || obj == nil {
		return fmt.Errorf("GET %s: no %q object", getPath, key)
	}
	delete(obj, "details")
	delete(obj, "isDefault")
	changed := false
	for k, v := range set {
		if fmt.Sprint(obj[k]) != fmt.Sprint(v) {
			changed = true
		}
		obj[k] = v
	}
	if !changed {
		return nil
	}
	if err := c.Do(ctx, http.MethodPut, putPath, "", obj, nil); err != nil && !IsNotChanged(err) {
		return err
	}
	return nil
}

// ensureLoginPolicy: Force MFA for every org (D-47), passkeys allowed (a passkey
// counts as MFA), no self-registration (D-51), no hints about unknown users.
func ensureLoginPolicy(ctx context.Context, c *Client) error {
	return updateFromCurrent(ctx, c, "/admin/v1/policies/login", "/admin/v1/policies/login", "policy", map[string]any{
		"forceMfa":               true,
		"forceMfaLocalOnly":      false,
		"allowRegister":          false,
		"allowUsernamePassword":  true,
		"passwordlessType":       "PASSWORDLESS_TYPE_ALLOWED",
		"ignoreUnknownUsernames": true,
	})
}

// ensurePasswordPolicies: min length 12 (spec #28), lockout after 5 tries.
// The lockout update path differs from its GET path (/policies/lockout).
func ensurePasswordPolicies(ctx context.Context, c *Client) error {
	err := c.Do(ctx, http.MethodPut, "/admin/v1/policies/password/complexity", "", map[string]any{
		"minLength": 12, "hasUppercase": true, "hasLowercase": true, "hasNumber": true, "hasSymbol": true,
	}, nil)
	if err != nil && !IsNotChanged(err) {
		return err
	}
	err = c.Do(ctx, http.MethodPut, "/admin/v1/policies/password/lockout", "", map[string]any{"maxPasswordAttempts": 5}, nil)
	if err != nil && !IsNotChanged(err) {
		return err
	}
	return nil
}

func ensureOIDCSettings(ctx context.Context, c *Client, lifetime string) error {
	return updateFromCurrent(ctx, c, "/admin/v1/settings/oidc", "/admin/v1/settings/oidc", "settings", map[string]any{
		"accessTokenLifetime": lifetime,
	})
}

func ensureTestUsers(ctx context.Context, c *Client, password string, r *Result) error {
	for _, u := range TestUsers {
		orgID := r.PlatformOrgID
		grantID := ""
		if u.Org == DemoOrg {
			orgID, grantID = r.DemoOrgID, r.DemoGrantID
		}
		id, err := ensureHuman(ctx, c, orgID, u.UserName, password)
		if err != nil {
			return fmt.Errorf("%s: %w", u.UserName, err)
		}
		if err := ensureUserGrant(ctx, c, orgID, id, r.ProjectID, grantID, u.Roles); err != nil {
			return fmt.Errorf("%s grant: %w", u.UserName, err)
		}
		r.TestUserIDs[u.UserName] = id
	}
	return nil
}

func ensureHuman(ctx context.Context, c *Client, orgID, userName, password string) (string, error) {
	var found struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	q := map[string]any{"queries": []any{map[string]any{"userNameQuery": map[string]any{"userName": userName, "method": "TEXT_QUERY_METHOD_EQUALS"}}}}
	if err := c.Do(ctx, http.MethodPost, "/management/v1/users/_search", orgID, q, &found); err != nil {
		return "", err
	}
	if len(found.Result) > 0 {
		id := found.Result[0].ID
		// Apply a rotated password from .env.
		err := c.Do(ctx, http.MethodPost, "/management/v1/users/"+id+"/password", orgID, map[string]any{"password": password, "noChangeRequired": true}, nil)
		if err != nil && !IsNotChanged(err) {
			return "", err
		}
		return id, nil
	}
	var made struct {
		UserID string `json:"userId"`
	}
	err := c.Do(ctx, http.MethodPost, "/management/v1/users/human/_import", orgID, map[string]any{
		"userName":               userName,
		"profile":                map[string]any{"firstName": strings.Split(userName, ".")[0], "lastName": "Test"},
		"email":                  map[string]any{"email": userName + "@example.test", "isEmailVerified": true},
		"password":               password,
		"passwordChangeRequired": false,
	}, &made)
	return made.UserID, err
}

func ensureUserGrant(ctx context.Context, c *Client, orgID, userID, projectID, projectGrantID string, roles []string) error {
	var found struct {
		Result []struct {
			ID       string   `json:"id"`
			RoleKeys []string `json:"roleKeys"`
		} `json:"result"`
	}
	q := map[string]any{"queries": []any{
		map[string]any{"userIdQuery": map[string]any{"userId": userID}},
		map[string]any{"projectIdQuery": map[string]any{"projectId": projectID}},
	}}
	if err := c.Do(ctx, http.MethodPost, "/management/v1/users/grants/_search", orgID, q, &found); err != nil {
		return err
	}
	if len(found.Result) > 0 {
		g := found.Result[0]
		if sameSet(g.RoleKeys, roles) {
			return nil
		}
		err := c.Do(ctx, http.MethodPut, "/management/v1/users/"+userID+"/grants/"+g.ID, orgID, map[string]any{"roleKeys": roles}, nil)
		if err != nil && !IsNotChanged(err) {
			return err
		}
		return nil
	}
	body := map[string]any{"projectId": projectID, "roleKeys": roles}
	if projectGrantID != "" {
		body["projectGrantId"] = projectGrantID
	}
	return c.Do(ctx, http.MethodPost, "/management/v1/users/"+userID+"/grants", orgID, body, nil)
}

func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

func list(v, def string) []string {
	if strings.TrimSpace(v) == "" {
		v = def
	}
	var out []string
	for s := range strings.SplitSeq(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// testPassword adds a suffix to the generated hex password so that it meets the
// complexity policy (upper, lower, digit, symbol). Empty stays empty: no test users.
func testPassword(v string) string {
	if v == "" {
		return ""
	}
	return v + "Aa1!"
}

func or(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
