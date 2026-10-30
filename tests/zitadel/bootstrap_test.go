package zitadel_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/VelimirMueller/synthwerk-infra/zitadel/bootstrap"
)

// fake is a small in-memory Zitadel: the paths and answer shapes the bootstrap
// uses, measured on Zitadel v4.20.0 (an empty search returns no "result").
type fake struct {
	mu       sync.Mutex
	next     int
	calls    []string
	orgs     map[string]string // name -> id
	projects map[string]string // name -> id
	roles    map[string]bool
	grants   map[string][]string // granted org id -> role keys
	apps     map[string]string   // name -> id
	users    map[string]string   // org/user -> id
	ugrants  map[string][]string // user id -> role keys
	secrets  int
	targets  map[string]map[string]any // id -> target
	execs    map[string][]string       // condition key (event:x, request:m, function:f) -> target ids
	conds    map[string]any            // condition key -> condition as sent
	policies map[string]map[string]any
	smtp     map[string]map[string]any // id -> provider
	members  map[string][]string       // instance member user id -> roles
	gmembers map[string][]string       // project grant id/user id -> roles
	omembers map[string][]string       // org id/user id -> org roles
	pats     map[string]string         // user id/token id of live PATs -> expiration date
	patN     int
	// notChanged answers every PUT with Zitadel's "not changed" error.
	notChanged bool
	// unavailable answers the first n calls with 503, code 14, like a starting Zitadel.
	unavailable int
}

func newFake() *fake {
	return &fake{
		orgs: map[string]string{"synthwerk": "o-platform"}, projects: map[string]string{},
		roles: map[string]bool{}, grants: map[string][]string{}, apps: map[string]string{},
		users: map[string]string{}, ugrants: map[string][]string{},
		targets: map[string]map[string]any{}, execs: map[string][]string{}, conds: map[string]any{},
		smtp: map[string]map[string]any{}, members: map[string][]string{},
		gmembers: map[string][]string{}, omembers: map[string][]string{}, pats: map[string]string{},
		policies: map[string]map[string]any{
			"/admin/v1/policies/login": {"allowRegister": true, "allowExternalIdp": true, "forceMfa": false,
				"secondFactors": []any{"SECOND_FACTOR_TYPE_OTP"}, "passwordCheckLifetime": "864000s"},
			"/admin/v1/settings/oidc": {"accessTokenLifetime": "43200s", "idTokenLifetime": "43200s"},
		},
	}
}

func (f *fake) id(prefix string) string { f.next++; return fmt.Sprintf("%s-%d", prefix, f.next) }

// creates lists the calls that make a new object.
func (f *fake) creates() []string {
	var out []string
	for _, c := range f.calls {
		if strings.HasPrefix(c, "POST ") && !strings.HasSuffix(c, "/_search") {
			out = append(out, c)
		}
	}
	return out
}

func (f *fake) puts() []string {
	var out []string
	for _, c := range f.calls {
		if strings.HasPrefix(c, "PUT ") {
			out = append(out, c)
		}
	}
	return out
}

var (
	reProject = regexp.MustCompile(`^/management/v1/projects/([^/]+)$`)
	reSub     = regexp.MustCompile(`^/management/v1/projects/[^/]+/(roles|grants|apps)(/.*)?$`)
	reUser    = regexp.MustCompile(`^/management/v1/users/([^/]+)/(password|grants)(/.*)?$`)
	rePAT     = regexp.MustCompile(`^/management/v1/users/([^/]+)/pats(/.*)?$`)
	// reGrantMember is checked before reSub: members of a project grant.
	reGrantMember = regexp.MustCompile(`^/management/v1/projects/[^/]+/grants/([^/]+)/members/?([^/]*)$`)
)

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	if f.unavailable > 0 {
		f.unavailable--
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 14, "message": "connection error"})
		return
	}
	if r.Host != "auth.test" || r.Header.Get("Authorization") != "Bearer pat" {
		http.Error(w, `{"code":16,"message":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}
	var in map[string]any
	_ = json.NewDecoder(r.Body).Decode(&in)
	org := r.Header.Get("x-zitadel-orgid")
	reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	result := func(items []map[string]any) {
		if len(items) == 0 {
			reply(map[string]any{"details": map[string]any{}})
			return
		}
		reply(map[string]any{"result": items})
	}
	if r.Method == http.MethodPut && f.notChanged {
		w.WriteHeader(http.StatusBadRequest)
		reply(map[string]any{"code": 9, "message": "Default Password Complexity Policy has not been changed (INSTANCE-9jlsf)"})
		return
	}
	p := r.URL.Path
	switch {
	case p == "/management/v1/orgs/me":
		reply(map[string]any{"org": map[string]any{"id": "o-platform", "name": "synthwerk"}})
	case p == "/admin/v1/orgs/_search":
		var items []map[string]any
		for n, id := range f.orgs {
			if n == queryName(in) {
				items = append(items, map[string]any{"id": id, "name": n})
			}
		}
		result(items)
	case p == "/management/v1/orgs":
		id := f.id("o")
		f.orgs[in["name"].(string)] = id
		reply(map[string]any{"id": id})
	case p == "/management/v1/projects/_search":
		var items []map[string]any
		if id, ok := f.projects[queryName(in)]; ok {
			items = append(items, map[string]any{"id": id, "name": queryName(in)})
		}
		result(items)
	case p == "/management/v1/projects":
		id := f.id("p")
		f.projects[in["name"].(string)] = id
		reply(map[string]any{"id": id})
	case reProject.MatchString(p) && r.Method == http.MethodPut:
		reply(map[string]any{})
	case reSub.MatchString(p) && !reGrantMember.MatchString(p):
		f.project(w, r.Method, p, in, reply, result)
	case p == "/management/v1/users/_search":
		var items []map[string]any
		if id, ok := f.users[org+"/"+userName(in)]; ok {
			items = append(items, map[string]any{"id": id})
		}
		result(items)
	case p == "/management/v1/users/machine":
		id := f.id("m")
		f.users[org+"/"+in["userName"].(string)] = id
		reply(map[string]any{"userId": id})
	case strings.HasPrefix(p, "/admin/v1/members/") && r.Method == http.MethodDelete:
		uid := strings.TrimPrefix(p, "/admin/v1/members/")
		if f.members[uid] == nil {
			w.WriteHeader(http.StatusNotFound)
			reply(map[string]any{"code": 5, "message": "member not found"})
			return
		}
		delete(f.members, uid)
		reply(map[string]any{})
	case p == "/management/v1/orgs/me/members" && r.Method == http.MethodPost:
		uid := in["userId"].(string)
		if f.omembers[org+"/"+uid] != nil {
			w.WriteHeader(http.StatusConflict)
			reply(map[string]any{"code": 6, "message": "Errors.Org.Member.AlreadyExists"})
			return
		}
		f.omembers[org+"/"+uid] = strSlice(in["roles"])
		reply(map[string]any{})
	case strings.HasPrefix(p, "/management/v1/orgs/me/members/") && r.Method == http.MethodPut:
		f.omembers[org+"/"+strings.TrimPrefix(p, "/management/v1/orgs/me/members/")] = strSlice(in["roles"])
		reply(map[string]any{})
	case reGrantMember.MatchString(p):
		m := reGrantMember.FindStringSubmatch(p)
		uid := m[2]
		if uid == "" {
			uid = in["userId"].(string)
			if f.gmembers[m[1]+"/"+uid] != nil && r.Method == http.MethodPost {
				// Zitadel v4.20 answers a second grant member with 404, code 5.
				w.WriteHeader(http.StatusNotFound)
				reply(map[string]any{"code": 5, "message": "Errors.AlreadyExists (PROJECT-37fug)"})
				return
			}
		}
		f.gmembers[m[1]+"/"+uid] = strSlice(in["roles"])
		reply(map[string]any{})
	case rePAT.MatchString(p):
		m := rePAT.FindStringSubmatch(p)
		switch {
		case m[2] == "/_search":
			var items []map[string]any
			for _, k := range slices.Sorted(maps.Keys(f.pats)) {
				if strings.HasPrefix(k, m[1]+"/") {
					items = append(items, map[string]any{"id": strings.TrimPrefix(k, m[1]+"/"), "expirationDate": f.pats[k]})
				}
			}
			// The query pages like Zitadel: offset (a string) and limit.
			q, _ := in["query"].(map[string]any)
			off, _ := strconv.Atoi(fmt.Sprint(q["offset"]))
			limit, _ := q["limit"].(float64)
			if limit == 0 || limit > 100 {
				limit = 100
			}
			items = items[min(off, len(items)):min(off+int(limit), len(items))]
			result(items)
		case r.Method == http.MethodDelete:
			delete(f.pats, m[1]+m[2]) // m[2] is "/<token id>"
			reply(map[string]any{})
		default:
			f.patN++
			tid := fmt.Sprintf("tok-%d", f.patN)
			exp, _ := in["expirationDate"].(string)
			f.pats[m[1]+"/"+tid] = exp
			reply(map[string]any{"tokenId": tid, "token": fmt.Sprintf("pat-%d", f.patN)})
		}
	case p == "/management/v1/users/human/_import":
		id := f.id("u")
		f.users[org+"/"+in["userName"].(string)] = id
		reply(map[string]any{"userId": id})
	case p == "/management/v1/users/grants/_search":
		var items []map[string]any
		for uid, keys := range f.ugrants {
			if strings.Contains(fmt.Sprint(in), uid+"]") {
				items = append(items, map[string]any{"id": "g-" + uid, "roleKeys": keys})
			}
		}
		result(items)
	case reUser.MatchString(p):
		m := reUser.FindStringSubmatch(p)
		if m[2] == "grants" && r.Method == http.MethodPost {
			f.ugrants[m[1]] = strSlice(in["roleKeys"])
		}
		reply(map[string]any{})
	case p == "/v2/actions/targets/search":
		var items []any
		for _, t := range f.targets {
			items = append(items, t)
		}
		reply(map[string]any{"targets": items})
	case p == "/v2/actions/targets":
		id := f.id("t")
		in["id"], in["signingKey"] = id, "key-"+id
		f.targets[id] = in
		reply(map[string]any{"id": id, "signingKey": "key-" + id})
	case strings.HasPrefix(p, "/v2/actions/targets/"):
		id := strings.TrimPrefix(p, "/v2/actions/targets/")
		if f.targets[id] == nil {
			w.WriteHeader(http.StatusNotFound)
			reply(map[string]any{"code": 5, "message": "target not found"})
			return
		}
		in["id"], in["signingKey"] = id, f.targets[id]["signingKey"]
		f.targets[id] = in
		reply(map[string]any{})
	case p == "/v2/actions/executions/search":
		var items []any
		for k, ids := range f.execs {
			cond := f.conds[k]
			if fn, ok := cond.(map[string]any)["function"].(map[string]any); ok {
				// Zitadel v4.20 returns the function name with its prefix.
				cond = map[string]any{"function": map[string]any{"name": "function/" + fn["name"].(string)}}
			}
			items = append(items, map[string]any{"condition": cond, "targets": ids})
		}
		reply(map[string]any{"executions": items})
	case p == "/v2/actions/executions":
		k := condKey(in["condition"].(map[string]any))
		f.execs[k], f.conds[k] = strSlice(in["targets"]), in["condition"]
		reply(map[string]any{})
	case p == "/admin/v1/policies/password/complexity", p == "/admin/v1/policies/password/lockout":
		if r.Method == http.MethodPut {
			f.policies[p] = in
		}
		reply(map[string]any{})
	case f.policies[p] != nil:
		key := "policy"
		if strings.Contains(p, "/settings/") {
			key = "settings"
		}
		if r.Method == http.MethodPut {
			f.policies[p] = in
			reply(map[string]any{})
			return
		}
		cur := map[string]any{"details": map[string]any{"sequence": "1"}, "isDefault": true}
		for k, v := range f.policies[p] {
			cur[k] = v
		}
		reply(map[string]any{key: cur})
	case p == "/admin/v1/email/_search":
		var items []map[string]any
		for _, v := range f.smtp {
			items = append(items, v)
		}
		result(items)
	case p == "/admin/v1/email/smtp":
		id := f.id("smtp")
		f.smtp[id] = map[string]any{"id": id, "description": in["description"], "state": "EMAIL_PROVIDER_INACTIVE",
			"smtp": map[string]any{"host": in["host"], "senderAddress": in["senderAddress"], "tls": in["tls"]}}
		reply(map[string]any{"id": id})
	case strings.HasPrefix(p, "/admin/v1/email/") && strings.HasSuffix(p, "/_activate"):
		id := strings.TrimSuffix(strings.TrimPrefix(p, "/admin/v1/email/"), "/_activate")
		for k, v := range f.smtp {
			v["state"] = "EMAIL_PROVIDER_INACTIVE"
			if k == id {
				v["state"] = "EMAIL_PROVIDER_ACTIVE"
			}
		}
		reply(map[string]any{})
	case strings.HasPrefix(p, "/admin/v1/email/") && r.Method == http.MethodDelete:
		delete(f.smtp, strings.TrimPrefix(p, "/admin/v1/email/"))
		reply(map[string]any{})
	default:
		w.WriteHeader(http.StatusNotFound)
		reply(map[string]any{"code": 5, "message": "fake: no route " + r.Method + " " + p})
	}
}

func (f *fake) project(w http.ResponseWriter, method, p string, in map[string]any, reply func(any), result func([]map[string]any)) {
	m := reSub.FindStringSubmatch(p)
	kind, rest := m[1], m[2]
	switch {
	case kind == "roles" && rest == "/_search":
		var items []map[string]any
		for k := range f.roles {
			items = append(items, map[string]any{"key": k})
		}
		result(items)
	case kind == "roles":
		key := in["roleKey"].(string)
		if f.roles[key] {
			w.WriteHeader(http.StatusConflict)
			reply(map[string]any{"code": 6, "message": "already exists"})
			return
		}
		f.roles[key] = true
		reply(map[string]any{})
	case kind == "grants" && rest == "/_search":
		var items []map[string]any
		for org, keys := range f.grants {
			items = append(items, map[string]any{"grantId": "pg-" + org, "grantedOrgId": org, "grantedRoleKeys": keys})
		}
		result(items)
	case kind == "grants" && method == http.MethodPost:
		org := in["grantedOrgId"].(string)
		f.grants[org] = strSlice(in["roleKeys"])
		reply(map[string]any{"grantId": "pg-" + org})
	case kind == "grants":
		reply(map[string]any{})
	case kind == "apps" && rest == "/_search":
		var items []map[string]any
		if id, ok := f.apps[queryName(in)]; ok {
			items = append(items, map[string]any{"id": id, "name": queryName(in), "oidcConfig": map[string]any{"clientId": "cid-" + id}})
		}
		result(items)
	case kind == "apps" && rest == "/oidc":
		id := f.id("a")
		f.apps[in["name"].(string)] = id
		f.secrets++
		reply(map[string]any{"appId": id, "clientId": "cid-" + id, "clientSecret": "secret-1"})
	case kind == "apps" && strings.HasSuffix(rest, "/_generate_client_secret"):
		f.secrets++
		reply(map[string]any{"clientSecret": fmt.Sprintf("secret-%d", f.secrets)})
	default:
		reply(map[string]any{})
	}
}

func queryName(in map[string]any) string {
	qs, _ := in["queries"].([]any)
	for _, q := range qs {
		if nq, ok := q.(map[string]any)["nameQuery"].(map[string]any); ok {
			return nq["name"].(string)
		}
	}
	return ""
}

func userName(in map[string]any) string {
	qs, _ := in["queries"].([]any)
	for _, q := range qs {
		if uq, ok := q.(map[string]any)["userNameQuery"].(map[string]any); ok {
			return uq["userName"].(string)
		}
	}
	return ""
}

// condKey names a condition: event:<event>, request:<method> or function:<name>.
func condKey(c map[string]any) string {
	for kind, field := range map[string]string{"event": "event", "request": "method", "function": "name"} {
		if m, ok := c[kind].(map[string]any); ok {
			return kind + ":" + m[field].(string)
		}
	}
	return ""
}

func strSlice(v any) []string {
	out := []string{}
	for _, s := range v.([]any) {
		out = append(out, s.(string))
	}
	return out
}

func setup(t *testing.T, env map[string]string) (*fake, *bootstrap.Client, bootstrap.Config) {
	t.Helper()
	f := newFake()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	env["SYNTHWERK_ZITADEL_STUDIO_CLIENT_FILE"] = filepath.Join(t.TempDir(), "studio-client.json")
	cfg, err := bootstrap.ConfigFromEnv(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	return f, &bootstrap.Client{BaseURL: srv.URL, Host: "auth.test", Token: "pat"}, cfg
}

func run(t *testing.T, c *bootstrap.Client, cfg bootstrap.Config) bootstrap.Result {
	t.Helper()
	r, err := bootstrap.Run(context.Background(), c, cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRunTwiceCreatesNothingTheSecondTime(t *testing.T) {
	f, c, cfg := setup(t, map[string]string{"SYNTHWERK_ZITADEL_TEST_USER_PASSWORD": "hex"})
	first := run(t, c, cfg)
	if len(f.roles) != len(bootstrap.Roles) || len(f.apps) != 1 || len(f.users) != len(bootstrap.TestUsers) {
		t.Fatalf("first run: roles %d, apps %d, users %d", len(f.roles), len(f.apps), len(f.users))
	}
	f.calls = nil
	second := run(t, c, cfg)
	// Only the password reset of the test users may write (POST .../password).
	for _, call := range f.creates() {
		if !strings.HasSuffix(call, "/password") {
			t.Errorf("second run created %s", call)
		}
	}
	for _, call := range f.puts() {
		if strings.Contains(call, "/policies/login") || strings.Contains(call, "/settings/oidc") {
			t.Errorf("second run changed an unchanged policy: %s", call)
		}
	}
	if first.ProjectID != second.ProjectID || first.StudioAppID != second.StudioAppID || first.DemoOrgID != second.DemoOrgID {
		t.Errorf("ids changed between runs: %+v vs %+v", first, second)
	}
	if f.secrets != 1 {
		t.Errorf("client secret made %d times, want 1 (the file exists)", f.secrets)
	}
}

func TestPolicyUpdateKeepsFieldsItDoesNotOwn(t *testing.T) {
	f, c, cfg := setup(t, map[string]string{})
	run(t, c, cfg)
	login := f.policies["/admin/v1/policies/login"]
	if login["forceMfa"] != true || login["allowRegister"] != false {
		t.Errorf("login policy not applied: %v", login)
	}
	if login["allowExternalIdp"] != true || login["passwordCheckLifetime"] != "864000s" || login["secondFactors"] == nil {
		t.Errorf("login policy lost fields it does not own: %v", login)
	}
	if _, ok := login["details"]; ok {
		t.Errorf("PUT sent the read-only details: %v", login)
	}
	oidc := f.policies["/admin/v1/settings/oidc"]
	if oidc["accessTokenLifetime"] != "300s" || oidc["idTokenLifetime"] != "43200s" {
		t.Errorf("oidc settings: %v", oidc)
	}
}

func TestNotChangedCountsAsSuccess(t *testing.T) {
	f, c, cfg := setup(t, map[string]string{})
	run(t, c, cfg)
	f.notChanged = true
	f.policies["/admin/v1/policies/login"]["forceMfa"] = false // force a PUT
	run(t, c, cfg)
}

func TestMissingClientFileMakesANewSecret(t *testing.T) {
	f, c, cfg := setup(t, map[string]string{})
	run(t, c, cfg)
	if err := os.Remove(cfg.StudioClientFile); err != nil {
		t.Fatal(err)
	}
	run(t, c, cfg)
	raw, err := os.ReadFile(cfg.StudioClientFile)
	if err != nil {
		t.Fatal(err)
	}
	var sc bootstrap.StudioClient
	if err := json.Unmarshal(raw, &sc); err != nil {
		t.Fatal(err)
	}
	if f.secrets != 2 || sc.ClientSecret != "secret-2" || sc.ClientID == "" {
		t.Errorf("secrets %d, file %+v", f.secrets, sc)
	}
	if st, _ := os.Stat(cfg.StudioClientFile); st.Mode().Perm() != 0o600 {
		t.Errorf("client file mode %v, want 0600", st.Mode().Perm())
	}
}

func TestForeignClientFileMakesANewSecret(t *testing.T) {
	f, c, cfg := setup(t, map[string]string{})
	run(t, c, cfg)
	if err := os.WriteFile(cfg.StudioClientFile, []byte(`{"app_id":"other","client_id":"x","client_secret":"y"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, c, cfg)
	if f.secrets != 2 {
		t.Errorf("secrets %d, want 2: a file for another app must not count", f.secrets)
	}
}

func TestNoTestUsersWithoutPassword(t *testing.T) {
	f, c, cfg := setup(t, map[string]string{})
	run(t, c, cfg)
	if len(f.users) != 0 {
		t.Errorf("made %d users without SYNTHWERK_ZITADEL_TEST_USER_PASSWORD", len(f.users))
	}
}

func TestWrongOrgPATFails(t *testing.T) {
	f, c, cfg := setup(t, map[string]string{})
	c.Token = "other"
	if _, err := bootstrap.Run(context.Background(), c, cfg, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("want an error for a bad PAT")
	}
	if len(f.creates()) != 0 {
		t.Errorf("created %v with a bad PAT", f.creates())
	}
}

func TestConfigRejectsWildcardAndRelativeURIs(t *testing.T) {
	if _, err := bootstrap.ConfigFromEnv(func(k string) string {
		if k == "SYNTHWERK_ZITADEL_IDENTITY_HOOK_URL" {
			return "identity-hooks:8081/x"
		}
		return ""
	}); err == nil {
		t.Error("hook URL without scheme: want an error")
	}
	for _, uri := range []string{"https://*.example.com/cb", "/callback", "javascript:alert(1)", " , "} {
		_, err := bootstrap.ConfigFromEnv(func(k string) string {
			if k == "SYNTHWERK_ZITADEL_STUDIO_REDIRECT_URIS" {
				return uri
			}
			return ""
		})
		if err == nil {
			t.Errorf("%q: want an error", uri)
		}
	}
}

func TestCheckRoles(t *testing.T) {
	claims := map[string]any{
		"urn:zitadel:iam:user:resourceowner:id": "o-1",
		bootstrap.RolesClaim:                    map[string]any{"member": map[string]any{"o-1": "demo.localhost"}},
	}
	if err := bootstrap.CheckRoles(claims, "o-1", "member"); err != nil {
		t.Error(err)
	}
	if err := bootstrap.CheckRoles(claims, "o-1", "admin"); err == nil {
		t.Error("admin: want an error")
	}
	if err := bootstrap.CheckRoles(claims, "o-2", "member"); err == nil {
		t.Error("other org: want an error")
	}
}

func hookSetup(t *testing.T) (*fake, *bootstrap.Client, bootstrap.Config) {
	t.Helper()
	f, c, cfg := setup(t, map[string]string{"SYNTHWERK_ZITADEL_IDENTITY_HOOK_URL": "http://identity-hooks:8081/internal/zitadel/actions"})
	cfg.IdentityHookKeyFile = filepath.Join(t.TempDir(), "identity-signing.key")
	cfg.IdentityHookKeyOwner = os.Getuid() // tests run unprivileged
	cfg.IdentityPATFile = filepath.Join(t.TempDir(), "identity.pat")
	return f, c, cfg
}

func TestIdentitySyncUserGetsOnePAT(t *testing.T) {
	f, c, cfg := hookSetup(t)
	r := run(t, c, cfg)
	id := f.users["o-platform/"+bootstrap.IdentitySyncUser]
	if id == "" {
		t.Fatal("no machine user identity-sync")
	}
	if f.members[id] != nil {
		t.Errorf("identity-sync has instance roles %v, want none", f.members[id])
	}
	if got := f.gmembers[r.DemoGrantID+"/"+id]; !slices.Equal(got, bootstrap.IdentitySyncGrantRoles) {
		t.Errorf("roles on the demo project grant %v, want %v", got, bootstrap.IdentitySyncGrantRoles)
	}
	if got := f.omembers[r.DemoOrgID+"/"+id]; !slices.Equal(got, bootstrap.IdentitySyncOrgRoles) {
		t.Errorf("roles in the demo org %v, want %v", got, bootstrap.IdentitySyncOrgRoles)
	}
	if got := f.omembers[r.PlatformOrgID+"/"+id]; got != nil {
		t.Errorf("identity-sync has roles %v in the platform org, want none", got)
	}
	pat, err := os.ReadFile(cfg.IdentityPATFile)
	if err != nil || string(pat) != "pat-1" {
		t.Fatalf("pat file %q, %v", pat, err)
	}
	if st, _ := os.Stat(cfg.IdentityPATFile); st.Mode().Perm() != 0o400 {
		t.Errorf("pat file mode %v, want 0400", st.Mode().Perm())
	}
	run(t, c, cfg)
	if f.patN != 1 {
		t.Errorf("second run made %d PATs, want 1 in total", f.patN)
	}
	for _, ev := range []string{"user.grant.added", "user.grant.changed", "user.grant.removed", "user.grant.cascade.removed"} {
		if len(f.execs["event:"+ev]) != 1 {
			t.Errorf("no execution for %s", ev)
		}
	}
}

func TestIdentitySyncNewPATRevokesOldOnes(t *testing.T) {
	f, c, cfg := hookSetup(t)
	run(t, c, cfg)
	id := f.users["o-platform/"+bootstrap.IdentitySyncUser]
	f.members[id] = []string{"IAM_USER_MANAGER"} // made by an older bootstrap
	// The file is gone (new volume): a new PAT, and the old one is revoked.
	if err := os.Remove(cfg.IdentityPATFile); err != nil {
		t.Fatal(err)
	}
	run(t, c, cfg)
	if len(f.pats) != 1 || f.pats[id+"/tok-2"] == "" {
		t.Errorf("live PATs %v, want only tok-2", f.pats)
	}
	if f.members[id] != nil {
		t.Errorf("old instance role kept: %v", f.members[id])
	}
}

func TestIdentityPATRenewedNearExpiry(t *testing.T) {
	f, c, cfg := hookSetup(t)
	run(t, c, cfg)
	id := f.users["o-platform/"+bootstrap.IdentitySyncUser]
	// A rerun with a fresh PAT keeps it.
	run(t, c, cfg)
	if len(f.pats) != 1 || f.pats[id+"/tok-1"] == "" {
		t.Fatalf("fresh PAT replaced: %v", f.pats)
	}
	// The PAT ends in a day (under a third of its lifetime): the rerun mints a new one
	// and revokes the old one.
	f.pats[id+"/tok-1"] = time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	run(t, c, cfg)
	if len(f.pats) != 1 || f.pats[id+"/tok-2"] == "" {
		t.Fatalf("live PATs %v, want only tok-2", f.pats)
	}
	got, err := os.ReadFile(cfg.IdentityPATFile)
	if err != nil || string(got) != "pat-2" {
		t.Fatalf("PAT file %q, %v: want pat-2", got, err)
	}
}

func TestIdentityPATRunTwiceOneActive(t *testing.T) {
	f, c, cfg := hookSetup(t)
	run(t, c, cfg)
	run(t, c, cfg)
	id := f.users["o-platform/"+bootstrap.IdentitySyncUser]
	got, err := os.ReadFile(cfg.IdentityPATFile + ".id")
	if err != nil || len(f.pats) != 1 || f.pats[id+"/"+string(got)] == "" {
		t.Fatalf("live PATs %v, id file %q (%v): want one, the one in the file", f.pats, got, err)
	}
}

func TestIdentityPATRevokesLeftoversOnEveryRun(t *testing.T) {
	f, c, cfg := hookSetup(t)
	run(t, c, cfg)
	id := f.users["o-platform/"+bootstrap.IdentitySyncUser]
	// An earlier run failed to revoke: 150 old PATs, more than one search page.
	exp := time.Now().Add(240 * time.Hour).UTC().Format(time.RFC3339)
	for i := range 150 {
		f.pats[fmt.Sprintf("%s/old-%03d", id, i)] = exp
	}
	run(t, c, cfg) // the file is there and fresh: no new PAT, but the leftovers go
	if len(f.pats) != 1 || f.pats[id+"/tok-1"] == "" {
		t.Fatalf("%d live PATs, want only tok-1", len(f.pats))
	}
}

func TestIdentityPATWriteFailureDeletesTheNewPAT(t *testing.T) {
	f, c, cfg := hookSetup(t)
	// The id file cannot be written: a non-empty directory sits at its path.
	if err := os.MkdirAll(cfg.IdentityPATFile+".id/x", 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrap.Run(context.Background(), c, cfg, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("run passed, want the write error")
	}
	if len(f.pats) != 0 {
		t.Fatalf("live PATs %v after a failed write, want none", f.pats)
	}
}

func TestIdentityPATLifetime(t *testing.T) {
	cfg, err := bootstrap.ConfigFromEnv(func(string) string { return "" })
	if err != nil || cfg.IdentityPATLifetime != 30*24*time.Hour {
		t.Fatalf("default %v, %v", cfg.IdentityPATLifetime, err)
	}
	if _, err := bootstrap.ConfigFromEnv(func(k string) string {
		if k == "SYNTHWERK_ZITADEL_IDENTITY_PAT_LIFETIME" {
			return "1m"
		}
		return ""
	}); err == nil {
		t.Fatal("1m accepted")
	}
}

func TestDemoOrgMayGrantOwner(t *testing.T) {
	f, c, cfg := setup(t, map[string]string{"SYNTHWERK_ZITADEL_TEST_USER_PASSWORD": "Test-Password-1!"})
	r := run(t, c, cfg)
	if !slices.Contains(f.grants[r.DemoOrgID], "owner") || slices.Contains(f.grants[r.DemoOrgID], "operator") {
		t.Fatalf("demo grant %v: want owner, not operator", f.grants[r.DemoOrgID])
	}
	if id := r.TestUserIDs["owner.demo"]; id == "" || !slices.Equal(f.ugrants[id], []string{"owner"}) {
		t.Fatalf("owner.demo %q grants %v", id, f.ugrants[id])
	}
}

func TestIdentityHookIsSetUpOnce(t *testing.T) {
	f, c, cfg := hookSetup(t)
	run(t, c, cfg)
	if len(f.targets) != 1 {
		t.Fatalf("targets %d, want 1", len(f.targets))
	}
	var id string
	for k := range f.targets {
		id = k
	}
	if got := f.execs["event:user.human.added"]; len(got) != 1 || got[0] != id {
		t.Errorf("execution user.human.added -> %v, want [%s]", got, id)
	}
	key, err := os.ReadFile(cfg.IdentityHookKeyFile)
	if err != nil || string(key) != "key-"+id {
		t.Fatalf("key file %q, %v", key, err)
	}
	if st, _ := os.Stat(cfg.IdentityHookKeyFile); st.Mode().Perm() != 0o400 {
		t.Errorf("key file mode %v, want 0400", st.Mode().Perm())
	}
	f.calls = nil
	run(t, c, cfg)
	for _, call := range f.calls {
		if call == "POST /v2/actions/targets" || call == "PUT /v2/actions/executions" || strings.HasPrefix(call, "POST /v2/actions/targets/"+id) {
			t.Errorf("second run changed the hook: %s", call)
		}
	}
}

func TestIdentityHookFollowsANewURL(t *testing.T) {
	f, c, cfg := hookSetup(t)
	run(t, c, cfg)
	cfg.IdentityHookURL = "http://identity-hooks:9091/internal/zitadel/actions"
	run(t, c, cfg)
	if len(f.targets) != 1 {
		t.Fatalf("targets %d, want 1 (update, not a second target)", len(f.targets))
	}
	for _, tg := range f.targets {
		if tg["endpoint"] != cfg.IdentityHookURL {
			t.Errorf("endpoint %v", tg["endpoint"])
		}
	}
}

func TestNoIdentityHookWithoutURL(t *testing.T) {
	f, c, cfg := setup(t, map[string]string{})
	run(t, c, cfg)
	if len(f.targets) != 0 || len(f.execs) != 0 {
		t.Errorf("targets %d, executions %d without SYNTHWERK_ZITADEL_IDENTITY_HOOK_URL", len(f.targets), len(f.execs))
	}
}

func TestWaitsForAStartingZitadel(t *testing.T) {
	f, c, cfg := setup(t, map[string]string{})
	f.unavailable = 1
	run(t, c, cfg)
	if f.calls[0] != "GET /management/v1/orgs/me" || f.calls[1] != "GET /management/v1/orgs/me" {
		t.Errorf("want the first read repeated, got %v", f.calls[:2])
	}
}

func TestSMTPProviderIsMadeOnceAndActive(t *testing.T) {
	f, c, cfg := setup(t, map[string]string{"SYNTHWERK_ZITADEL_SMTP_HOST": "mailpit:1025"})
	run(t, c, cfg)
	run(t, c, cfg)
	if len(f.smtp) != 1 {
		t.Fatalf("providers %d, want 1", len(f.smtp))
	}
	for _, v := range f.smtp {
		if v["state"] != "EMAIL_PROVIDER_ACTIVE" || v["smtp"].(map[string]any)["host"] != "mailpit:1025" || v["smtp"].(map[string]any)["tls"] != false {
			t.Errorf("provider %v, want active, host mailpit:1025, no TLS", v)
		}
	}
}

func TestSMTPHostChangeReplacesTheProvider(t *testing.T) {
	f, c, cfg := setup(t, map[string]string{"SYNTHWERK_ZITADEL_SMTP_HOST": "mailpit:1025"})
	run(t, c, cfg)
	cfg.SMTPHost = "mailpit:2525"
	run(t, c, cfg)
	if len(f.smtp) != 1 {
		t.Fatalf("providers %d, want 1", len(f.smtp))
	}
	for _, v := range f.smtp {
		if v["smtp"].(map[string]any)["host"] != "mailpit:2525" || v["state"] != "EMAIL_PROVIDER_ACTIVE" {
			t.Errorf("provider %v, want the new host, active", v)
		}
	}
}

func TestNoSMTPHostLeavesTheProviderAlone(t *testing.T) {
	f, c, cfg := setup(t, map[string]string{})
	run(t, c, cfg)
	for _, call := range f.calls {
		if strings.Contains(call, "/admin/v1/email") {
			t.Errorf("unexpected email provider call %s", call)
		}
	}
}

func TestDuplicateSMTPProviderIsDropped(t *testing.T) {
	f, c, cfg := setup(t, map[string]string{"SYNTHWERK_ZITADEL_SMTP_HOST": "mailpit:1025"})
	run(t, c, cfg)
	f.smtp["smtp-dup"] = map[string]any{"id": "smtp-dup", "description": bootstrap.SMTPDescription, "state": "EMAIL_PROVIDER_INACTIVE",
		"smtp": map[string]any{"host": "mailpit:1025", "senderAddress": cfg.SMTPSender}}
	run(t, c, cfg)
	if len(f.smtp) != 1 {
		t.Fatalf("providers %d, want 1", len(f.smtp))
	}
}

func gateSetup(t *testing.T) (*fake, *bootstrap.Client, bootstrap.Config) {
	t.Helper()
	dir := t.TempDir()
	f, c, cfg := setup(t, map[string]string{
		"SYNTHWERK_ZITADEL_IDENTITY_HOOK_URL":      "http://identity-hooks:8081/internal/zitadel/actions",
		"SYNTHWERK_ZITADEL_IDENTITY_HOOK_KEY_FILE": filepath.Join(dir, "identity-signing.key"),
		"SYNTHWERK_ZITADEL_IDENTITY_PAT_FILE":      filepath.Join(dir, "identity.pat"),
		"SYNTHWERK_ZITADEL_MFA_GATE":               "true",
		"SYNTHWERK_ZITADEL_MFA_GATE_KEY_FILE":      filepath.Join(dir, "identity-mfa-gate.key"),
		"SYNTHWERK_ZITADEL_TOKEN_CLAIMS_KEY_FILE":  filepath.Join(dir, "identity-token-claims.key"),
	})
	cfg.IdentityHookKeyOwner = os.Getuid()
	return f, c, cfg
}

func targetByName(f *fake, name string) (string, map[string]any) {
	for id, tg := range f.targets {
		if tg["name"] == name {
			return id, tg
		}
	}
	return "", nil
}

func TestMFAGateIsSetUpOnce(t *testing.T) {
	f, c, cfg := gateSetup(t)
	run(t, c, cfg)
	gateID, gate := targetByName(f, bootstrap.MFAGateTarget)
	claimsID, claims := targetByName(f, bootstrap.TokenClaimsTarget)
	if gate == nil || claims == nil || len(f.targets) != 3 {
		t.Fatalf("targets %v", f.targets)
	}
	// The gate must answer for every sign-in; the claims target may fail (no amr then).
	if fmt.Sprint(gate["restCall"]) != "map[interruptOnError:true]" || gate["endpoint"] != "http://identity-hooks:8081/internal/zitadel/mfa-gate" {
		t.Errorf("gate target %v", gate)
	}
	if fmt.Sprint(claims["restCall"]) != "map[interruptOnError:false]" || claims["endpoint"] != "http://identity-hooks:8081/internal/zitadel/token-claims" {
		t.Errorf("claims target %v", claims)
	}
	for _, m := range bootstrap.GatedMethods {
		if got := f.execs["request:"+m]; !slices.Equal(got, []string{gateID}) {
			t.Errorf("execution %s -> %v, want [%s]", m, got, gateID)
		}
	}
	if got := f.execs["function:preaccesstoken"]; !slices.Equal(got, []string{claimsID}) {
		t.Errorf("execution preaccesstoken -> %v, want [%s]", got, claimsID)
	}
	for file, id := range map[string]string{cfg.MFAGateKeyFile: gateID, cfg.TokenClaimsKeyFile: claimsID} {
		key, err := os.ReadFile(file) //nolint:gosec // G304: a temp file of this test
		if err != nil || string(key) != "key-"+id {
			t.Fatalf("key file %s: %q, %v", file, key, err)
		}
		if st, _ := os.Stat(file); st.Mode().Perm() != 0o400 {
			t.Errorf("key file %s mode %v, want 0400", file, st.Mode().Perm())
		}
	}
	f.calls = nil
	run(t, c, cfg)
	for _, call := range f.calls {
		if call == "POST /v2/actions/targets" || call == "PUT /v2/actions/executions" ||
			strings.HasPrefix(call, "POST /v2/actions/targets/"+gateID) || strings.HasPrefix(call, "POST /v2/actions/targets/"+claimsID) {
			t.Errorf("second run changed the gate: %s", call)
		}
	}
}

func TestMFAGateOffClearsTheExecutions(t *testing.T) {
	f, c, cfg := gateSetup(t)
	run(t, c, cfg)
	cfg.MFAGate = false
	run(t, c, cfg)
	for _, m := range bootstrap.GatedMethods {
		if got := f.execs["request:"+m]; len(got) != 0 {
			t.Errorf("execution %s -> %v after the gate was turned off", m, got)
		}
	}
	if got := f.execs["function:preaccesstoken"]; len(got) != 0 {
		t.Errorf("execution preaccesstoken -> %v after the gate was turned off", got)
	}
	if got := f.execs["event:user.human.added"]; len(got) != 1 {
		t.Errorf("the user hook was touched: %v", got)
	}
	f.calls = nil
	run(t, c, cfg)
	for _, call := range f.calls {
		if call == "PUT /v2/actions/executions" {
			t.Errorf("third run changed an execution: %s", call)
		}
	}
}

func TestMFAGateConfig(t *testing.T) {
	for _, env := range []map[string]string{
		{"SYNTHWERK_ZITADEL_MFA_GATE": "true"},
		{"SYNTHWERK_ZITADEL_MFA_GATE": "yes", "SYNTHWERK_ZITADEL_IDENTITY_HOOK_URL": "http://identity-hooks:8081/x"},
	} {
		if _, err := bootstrap.ConfigFromEnv(func(k string) string { return env[k] }); err == nil {
			t.Errorf("%v: no error", env)
		}
	}
}

func TestTOTP(t *testing.T) {
	// RFC 6238 appendix B, SHA-1 secret "12345678901234567890", last 6 of the 8 digits.
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" //nolint:gosec // G101: the public RFC 6238 test secret
	for unix, want := range map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 20000000000: "353130"} {
		got, err := bootstrap.TOTP(secret, time.Unix(unix, 0))
		if err != nil || got != want {
			t.Errorf("T=%d: %q %v, want %q", unix, got, err, want)
		}
	}
	if _, err := bootstrap.TOTP("not base32!", time.Now()); err == nil {
		t.Error("bad secret: no error")
	}
}

func TestHasMFA(t *testing.T) {
	for _, c := range []struct {
		claims map[string]any
		want   bool
	}{
		{map[string]any{"amr": []any{"pwd", "otp", "mfa"}}, true},
		{map[string]any{"amr": []any{"pwd"}}, false},
		{map[string]any{"synthwerk:mfa": true}, false},
		{map[string]any{}, false},
	} {
		if got := bootstrap.HasMFA(c.claims); got != c.want {
			t.Errorf("%v: %v, want %v", c.claims, got, c.want)
		}
	}
}

func TestIdentitySyncOrgRoleIsSetOnce(t *testing.T) {
	f, c, cfg := hookSetup(t)
	r := run(t, c, cfg)
	id := f.users["o-platform/"+bootstrap.IdentitySyncUser]
	f.calls = nil
	run(t, c, cfg)
	// The second run finds the member (409) and puts the same roles back.
	if got := f.omembers[r.DemoOrgID+"/"+id]; !slices.Equal(got, bootstrap.IdentitySyncOrgRoles) {
		t.Errorf("roles after the second run %v, want %v", got, bootstrap.IdentitySyncOrgRoles)
	}
}

func TestIdentitySyncOrgRoleRefusesThePlatformOrg(t *testing.T) {
	_, c, _ := hookSetup(t)
	for _, org := range []string{"o-platform", ""} {
		if err := bootstrap.GrantIdentitySyncOrg(context.Background(), c, "o-platform", org, "m-1"); err == nil {
			t.Errorf("org %q: want an error", org)
		}
	}
}

func TestStudioClientIsSharedWithStudio(t *testing.T) {
	_, c, cfg := setup(t, map[string]string{})
	cfg.StudioShareFile = filepath.Join(t.TempDir(), "studio-client.json")
	cfg.StudioShareOwner = os.Getuid()
	run(t, c, cfg)
	want, err := os.ReadFile(cfg.StudioClientFile)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(cfg.StudioShareFile)
	if err != nil || string(got) != string(want) {
		t.Fatalf("shared file %q, %v; want the client file", got, err)
	}
	if st, _ := os.Stat(cfg.StudioShareFile); st.Mode().Perm() != 0o400 {
		t.Errorf("shared file mode %v, want 0400", st.Mode().Perm())
	}
	run(t, c, cfg) // a rerun replaces the 0400 file without error
}

func TestWidgetKeyIsMadeOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "widget-signing.key")
	made, err := bootstrap.EnsureWidgetKey(path, os.Getuid())
	if err != nil || !made {
		t.Fatalf("first call: made %v, err %v", made, err)
	}
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the test's own temp file
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("not a PKCS #8 PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if ec, ok := key.(*ecdsa.PrivateKey); err != nil || !ok || ec.Curve != elliptic.P256() {
		t.Fatalf("key is not ECDSA P-256: %T, %v", key, err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o400 {
		t.Errorf("key mode %v, want 0400", st.Mode().Perm())
	}
	if made, err := bootstrap.EnsureWidgetKey(path, os.Getuid()); err != nil || made {
		t.Errorf("second call: made %v, err %v; want the old key kept", made, err)
	}
	if again, _ := os.ReadFile(path); string(again) != string(raw) { //nolint:gosec // G304: the test's own temp file
		t.Error("second call changed the key")
	}
}
