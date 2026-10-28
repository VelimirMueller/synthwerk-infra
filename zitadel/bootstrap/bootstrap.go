package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
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

// DemoGrantRoles are the roles the demo org may give to its users. owner, admin
// and member are org roles (synthwerk#29); operator stays with the platform org.
var DemoGrantRoles = []string{"owner", "admin", "member", "end_user"}

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
	// IdentityHookURL is the identity listener for Zitadel Actions (#28 task 5).
	// Empty = no target and no execution.
	IdentityHookURL string
	// IdentityHookKeyFile receives the target signing key (mode 0400, owner
	// IdentityHookKeyOwner) in the volume zitadel-hooks, which identity reads.
	IdentityHookKeyFile string
	// IdentityHookKeyOwner is the uid that owns the key file: identity's nonroot user.
	IdentityHookKeyOwner int
	// IdentityPATFile receives the PAT of the machine user identity-sync (mode 0400,
	// owner IdentityHookKeyOwner). identity writes org role changes to Zitadel user
	// grants with it (synthwerk#29). Set up together with the hook.
	IdentityPATFile string
	// IdentityPATLifetime is the lifetime of a new identity-sync PAT. Default 30 days.
	IdentityPATLifetime time.Duration
	// SMTPHost is the mail server as host:port (Mailpit in local and ci, D-49).
	// Empty = Zitadel's email provider is not touched (dev and prd set it up apart).
	SMTPHost string
	// SMTPSender is the sender address of Zitadel's mails.
	SMTPSender string
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
	{UserName: "owner.demo", Org: DemoOrg, Roles: []string{"owner"}},
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
		IdentityHookURL:     getenv("SYNTHWERK_ZITADEL_IDENTITY_HOOK_URL"),
		IdentityHookKeyFile: or(getenv("SYNTHWERK_ZITADEL_IDENTITY_HOOK_KEY_FILE"), "/zitadel/hooks/identity-signing.key"),
		// 65532: nonroot in the distroless image of synthwerk-identity.
		IdentityHookKeyOwner: 65532,
		IdentityPATFile:      or(getenv("SYNTHWERK_ZITADEL_IDENTITY_PAT_FILE"), "/zitadel/hooks/identity.pat"),
		IdentityPATLifetime:  30 * 24 * time.Hour,
		SMTPHost:             getenv("SYNTHWERK_ZITADEL_SMTP_HOST"),
		SMTPSender:           or(getenv("SYNTHWERK_ZITADEL_SMTP_SENDER"), "auth@synthwerk.localhost"),
	}
	if v := getenv("SYNTHWERK_ZITADEL_IDENTITY_PAT_LIFETIME"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Hour {
			return Config{}, fmt.Errorf("SYNTHWERK_ZITADEL_IDENTITY_PAT_LIFETIME %q: want a duration of at least 1h", v)
		}
		cfg.IdentityPATLifetime = d
	}
	if len(cfg.StudioRedirectURIs) == 0 {
		return Config{}, errors.New("SYNTHWERK_ZITADEL_STUDIO_REDIRECT_URIS: want at least one URI")
	}
	if _, err := time.ParseDuration(cfg.AccessTokenLifetime); err != nil {
		return Config{}, fmt.Errorf("SYNTHWERK_ZITADEL_ACCESS_TOKEN_LIFETIME: %w", err)
	}
	if u := cfg.IdentityHookURL; u != "" {
		if p, err := url.Parse(u); err != nil || (p.Scheme != "http" && p.Scheme != "https") || p.Host == "" {
			return Config{}, fmt.Errorf("SYNTHWERK_ZITADEL_IDENTITY_HOOK_URL %q: want an absolute http(s) URL", u)
		}
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
	if err := waitReady(ctx, c, &me); err != nil {
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
	if cfg.IdentityHookURL != "" {
		steps = append(steps, struct {
			name string
			fn   func() error
		}{"identity hook", func() error { return ensureIdentityHook(ctx, c, cfg) }}, struct {
			name string
			fn   func() error
		}{"identity machine user", func() error {
			return ensureIdentitySync(ctx, c, cfg, r.PlatformOrgID, r.ProjectID, r.DemoGrantID)
		}})
	}
	if cfg.SMTPHost != "" {
		steps = append(steps, struct {
			name string
			fn   func() error
		}{"email provider", func() error { return ensureSMTP(ctx, c, cfg) }})
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

// IdentityHookTarget is the name of the Action target that calls identity.
const IdentityHookTarget = "identity-user-created"

// HookEvents are the Zitadel events identity receives (zitadelhook in synthwerk-identity):
// new users (#28) and the user grants it mirrors as org memberships (#29).
var HookEvents = []string{"user.human.added", "user.grant.added", "user.grant.changed", "user.grant.removed", "user.grant.cascade.removed"}

// IdentitySyncUser is the machine user identity calls Zitadel with.
const IdentitySyncUser = "identity-sync"

// IdentitySyncGrantRoles are its roles on each project grant of synthwerk-api: read
// and write the user grants of that org, nothing else (ADR-0003). It has no
// instance role and no role in the platform org.
var IdentitySyncGrantRoles = []string{"PROJECT_GRANT_OWNER"}

// ensureIdentitySync makes the machine user identity-sync in the platform org and
// gives it IdentitySyncGrantRoles on the given project grant. When the PAT file is
// missing it mints a PAT that lives cfg.IdentityPATLifetime, writes it for identity
// and revokes every older PAT of the user. Zitadel shows a PAT only once, so an
// existing file is kept (root cannot read it: it belongs to identity, mode 0400).
func ensureIdentitySync(ctx context.Context, c *Client, cfg Config, platformOrgID, projectID, projectGrantID string) error {
	id, err := IdentitySyncUserID(ctx, c, platformOrgID)
	if err != nil {
		return err
	}
	if id == "" {
		var made struct {
			UserID string `json:"userId"`
		}
		err := c.Do(ctx, http.MethodPost, "/management/v1/users/machine", platformOrgID, map[string]any{
			"userName":        IdentitySyncUser,
			"name":            IdentitySyncUser,
			"description":     "synthwerk-identity writes org roles to user grants (synthwerk#29, ADR-0003)",
			"accessTokenType": "ACCESS_TOKEN_TYPE_BEARER",
		}, &made)
		if err != nil {
			return err
		}
		id = made.UserID
	}
	// An older bootstrap gave an instance role: take it away (not found = fine).
	if err := c.Do(ctx, http.MethodDelete, "/admin/v1/members/"+id, "", nil, nil); err != nil && !IsNotFound(err) {
		return err
	}
	if err := GrantIdentitySync(ctx, c, platformOrgID, projectID, projectGrantID, id); err != nil {
		return err
	}
	if _, err := os.Stat(cfg.IdentityPATFile); err == nil {
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	var pat struct {
		TokenID string `json:"tokenId"`
		Token   string `json:"token"`
	}
	exp := time.Now().Add(cfg.IdentityPATLifetime).UTC().Format(time.RFC3339)
	if err := c.Do(ctx, http.MethodPost, "/management/v1/users/"+id+"/pats", platformOrgID, map[string]any{"expirationDate": exp}, &pat); err != nil {
		return err
	}
	if pat.Token == "" || pat.TokenID == "" {
		return fmt.Errorf("user %s: Zitadel returned no PAT", IdentitySyncUser)
	}
	if err := writeKey(cfg.IdentityPATFile, pat.Token, cfg.IdentityHookKeyOwner); err != nil {
		return err
	}
	return revokeOtherPATs(ctx, c, platformOrgID, id, pat.TokenID)
}

// IdentitySyncUserID returns the id of identity-sync, or "" when it does not exist.
func IdentitySyncUserID(ctx context.Context, c *Client, platformOrgID string) (string, error) {
	var found struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	q := map[string]any{"queries": []any{map[string]any{"userNameQuery": map[string]any{"userName": IdentitySyncUser, "method": "TEXT_QUERY_METHOD_EQUALS"}}}}
	if err := c.Do(ctx, http.MethodPost, "/management/v1/users/_search", platformOrgID, q, &found); err != nil {
		return "", err
	}
	if len(found.Result) == 0 {
		return "", nil
	}
	return found.Result[0].ID, nil
}

// GrantIdentitySync gives identity-sync IdentitySyncGrantRoles on one project grant.
// Whoever creates a project grant of synthwerk-api for a new org calls it, or role
// changes in that org answer 502 (ADR-0003).
func GrantIdentitySync(ctx context.Context, c *Client, platformOrgID, projectID, projectGrantID, userID string) error {
	path := "/management/v1/projects/" + projectID + "/grants/" + projectGrantID + "/members"
	err := c.Do(ctx, http.MethodPost, path, platformOrgID, map[string]any{"userId": userID, "roles": IdentitySyncGrantRoles}, nil)
	if IsAlreadyExists(err) {
		err = c.Do(ctx, http.MethodPut, path+"/"+userID, platformOrgID, map[string]any{"roles": IdentitySyncGrantRoles}, nil)
		if IsNotChanged(err) {
			return nil
		}
	}
	return err
}

// revokeOtherPATs deletes every PAT of the user except keep.
func revokeOtherPATs(ctx context.Context, c *Client, orgID, userID, keep string) error {
	var found struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := c.Do(ctx, http.MethodPost, "/management/v1/users/"+userID+"/pats/_search", orgID, map[string]any{}, &found); err != nil {
		return err
	}
	for _, p := range found.Result {
		if p.ID == keep {
			continue
		}
		if err := c.Do(ctx, http.MethodDelete, "/management/v1/users/"+userID+"/pats/"+p.ID, orgID, nil, nil); err != nil && !IsNotFound(err) {
			return err
		}
	}
	return nil
}

// ensureIdentityHook creates or updates the target, writes its signing key for
// identity and points the event executions at it. The bootstrap owns these
// executions: their target list is replaced, not merged. Zitadel caches executions and
// targets, so a change can take some seconds to apply.
func ensureIdentityHook(ctx context.Context, c *Client, cfg Config) error {
	want := map[string]any{
		"name":        IdentityHookTarget,
		"restWebhook": map[string]any{"interruptOnError": false},
		"endpoint":    cfg.IdentityHookURL,
		"timeout":     "10s",
	}
	var found struct {
		Targets []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			Endpoint   string `json:"endpoint"`
			Timeout    string `json:"timeout"`
			SigningKey string `json:"signingKey"`
		} `json:"targets"`
	}
	search := map[string]any{"filters": []any{map[string]any{"targetNameFilter": map[string]any{"targetName": IdentityHookTarget, "method": "TEXT_FILTER_METHOD_EQUALS"}}}}
	if err := c.Do(ctx, http.MethodPost, "/v2/actions/targets/search", "", search, &found); err != nil {
		return err
	}
	var id, key string
	for _, t := range found.Targets {
		if t.Name != IdentityHookTarget {
			continue
		}
		id, key = t.ID, t.SigningKey
		if t.Endpoint != cfg.IdentityHookURL || t.Timeout != "10s" {
			if err := c.Do(ctx, http.MethodPost, "/v2/actions/targets/"+id, "", want, nil); err != nil && !IsNotChanged(err) {
				return err
			}
		}
	}
	if id == "" {
		var made struct {
			ID         string `json:"id"`
			SigningKey string `json:"signingKey"`
		}
		if err := c.Do(ctx, http.MethodPost, "/v2/actions/targets", "", want, &made); err != nil {
			return err
		}
		id, key = made.ID, made.SigningKey
	}
	if key == "" {
		return fmt.Errorf("target %s: Zitadel returned no signing key", IdentityHookTarget)
	}
	if err := writeKey(cfg.IdentityHookKeyFile, key, cfg.IdentityHookKeyOwner); err != nil {
		return err
	}
	return ensureExecutions(ctx, c, id)
}

func ensureExecutions(ctx context.Context, c *Client, targetID string) error {
	var found struct {
		Executions []struct {
			Condition struct {
				Event struct {
					Event string `json:"event"`
				} `json:"event"`
			} `json:"condition"`
			Targets []string `json:"targets"`
		} `json:"executions"`
	}
	if err := c.Do(ctx, http.MethodPost, "/v2/actions/executions/search", "", map[string]any{}, &found); err != nil {
		return err
	}
	have := map[string][]string{}
	for _, e := range found.Executions {
		if e.Condition.Event.Event != "" {
			have[e.Condition.Event.Event] = e.Targets
		}
	}
	for _, ev := range HookEvents {
		if slices.Equal(have[ev], []string{targetID}) {
			continue
		}
		body := map[string]any{"condition": map[string]any{"event": map[string]any{"event": ev}}, "targets": []string{targetID}}
		if err := c.Do(ctx, http.MethodPut, "/v2/actions/executions", "", body, nil); err != nil && !IsNotChanged(err) {
			return err
		}
	}
	return nil
}

// writeKey writes key with mode 0400 for owner, only when the content differs.
// The bootstrap needs CAP_CHOWN for this (compose cap_add).
func writeKey(path, key string, owner int) error {
	if cur, err := os.ReadFile(path); err == nil && string(cur) == key { //nolint:gosec // G304: our own path
		return nil
	}
	// Without CAP_DAC_OVERRIDE root cannot read or replace a 0400 file of another
	// owner, so the compare above fails after the first run and the file is
	// replaced through a fresh temp file (the directory belongs to root).
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	if err := os.WriteFile(tmp, []byte(key), 0o400); err != nil {
		return err
	}
	if err := os.Chown(tmp, owner, -1); err != nil { // mode 0400: the group does not matter
		_ = os.Remove(tmp)
		return fmt.Errorf("chown %s: %w", tmp, err)
	}
	return os.Rename(tmp, path)
}

// ReadyTimeout bounds waitReady.
var ReadyTimeout = 90 * time.Second

// waitReady repeats the first read until Zitadel answers it. Zitadel reports
// ready before its API gateway accepts calls: the first call can get 503,
// code 14 "connection error" (seen on a CI runner). Only that answer is retried.
func waitReady(ctx context.Context, c *Client, out any) error {
	deadline := time.Now().Add(ReadyTimeout)
	for {
		err := c.Do(ctx, http.MethodGet, "/management/v1/orgs/me", "", nil, out)
		var e *APIError
		if err == nil || !errors.As(err, &e) || e.Status != http.StatusServiceUnavailable || time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// SMTPDescription names the email provider the bootstrap owns.
const SMTPDescription = "synthwerk-local"

// ensureSMTP points Zitadel's mail (invite codes, email verification) at an SMTP
// server without TLS and login: Mailpit in local and ci (D-49). The provider is
// found by its description, made when missing and activated.
func ensureSMTP(ctx context.Context, c *Client, cfg Config) error {
	var found struct {
		Result []struct {
			ID          string `json:"id"`
			Description string `json:"description"`
			State       string `json:"state"`
			SMTP        struct {
				Host          string `json:"host"`
				SenderAddress string `json:"senderAddress"`
			} `json:"smtp"`
		} `json:"result"`
	}
	if err := c.Do(ctx, http.MethodPost, "/admin/v1/email/_search", "", map[string]any{}, &found); err != nil {
		return err
	}
	id, state := "", ""
	for _, p := range found.Result {
		if p.Description != SMTPDescription {
			continue
		}
		if id != "" || p.SMTP.Host != cfg.SMTPHost || p.SMTP.SenderAddress != cfg.SMTPSender {
			// A second provider with this name, or changed settings: drop it (the
			// update endpoint is a full replace that wants the password). Zitadel
			// deletes an active provider too; the new one is activated below.
			if err := c.Do(ctx, http.MethodDelete, "/admin/v1/email/"+p.ID, "", nil, nil); err != nil {
				return err
			}
			continue
		}
		id, state = p.ID, p.State
	}
	if id == "" {
		var made struct {
			ID string `json:"id"`
		}
		err := c.Do(ctx, http.MethodPost, "/admin/v1/email/smtp", "", map[string]any{
			"description":   SMTPDescription,
			"senderAddress": cfg.SMTPSender,
			"senderName":    "Synthwerk",
			"tls":           false,
			"host":          cfg.SMTPHost,
		}, &made)
		if err != nil {
			return err
		}
		id = made.ID
	}
	if state == "EMAIL_PROVIDER_ACTIVE" {
		return nil
	}
	err := c.Do(ctx, http.MethodPost, "/admin/v1/email/"+id+"/_activate", "", map[string]any{}, nil)
	if err != nil && !IsNotChanged(err) {
		return err
	}
	return nil
}
