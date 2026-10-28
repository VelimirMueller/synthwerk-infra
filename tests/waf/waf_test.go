package waf_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/VelimirMueller/synthwerk-infra/waf"
)

var (
	handlerOnce sync.Once
	handler     *waf.Handler
	handlerErr  error
)

// blockingHandler builds the WAF once: loading CRS takes about a second.
func blockingHandler(t *testing.T) *waf.Handler {
	t.Helper()
	handlerOnce.Do(func() {
		cfg, err := waf.ConfigFromEnv(func(k string) string {
			if k == "SYNTHWERK_WAF_GRPC_HOSTS" {
				return grpcHost
			}
			return ""
		})
		if err != nil {
			handlerErr = err
			return
		}
		handler, handlerErr = waf.New(cfg, slog.New(slog.DiscardHandler))
	})
	if handlerErr != nil {
		t.Fatalf("build waf: %v", handlerErr)
	}
	return handler
}

// grpcHost may send gRPC; forwardAuth sends every other request for "localhost".
const grpcHost = "auth.localhost"

// grpcFrame is one gRPC message frame: flag 0, length 2, protobuf field 1 = 1.
const grpcFrame = "\x00\x00\x00\x00\x02\x08\x01"

// forwardAuth builds the request that Traefik sends to the WAF.
func forwardAuth(method, uri, body string, header map[string]string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), method, "http://waf:8080/check", strings.NewReader(body))
	r.Header.Set("X-Forwarded-Method", method)
	r.Header.Set("X-Forwarded-Uri", uri)
	r.Header.Set("X-Forwarded-Host", "localhost")
	r.Header.Set("X-Forwarded-Proto", "http")
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	r.Header.Set("User-Agent", "synthwerk-test/1.0")
	r.Header.Set("Accept", "*/*")
	for k, v := range header {
		r.Header.Set(k, v)
	}
	return r
}

func TestCheck_KnownAttack_Returns403(t *testing.T) {
	h := blockingHandler(t)
	cases := map[string]*http.Request{
		"sql injection in query": forwardAuth(http.MethodGet, "/stub/?id=1%27%20OR%20%271%27=%271", "", nil),
		"path traversal":         forwardAuth(http.MethodGet, "/stub/?file=../../../../etc/passwd", "", nil),
		"xss in query":           forwardAuth(http.MethodGet, "/stub/?q=%3Cscript%3Ealert(1)%3C/script%3E", "", nil),
		"sql injection in form body": forwardAuth(http.MethodPost, "/stub/login", "user=admin%27%20OR%201=1--&pass=x",
			map[string]string{"Content-Type": "application/x-www-form-urlencoded"}),
		"command injection in json body": forwardAuth(http.MethodPost, "/stub/run", `{"cmd":"; cat /etc/passwd"}`,
			map[string]string{"Content-Type": "application/json"}),
		"content type not on the list": forwardAuth(http.MethodPost, "/stub/upload", "data",
			map[string]string{"Content-Type": "application/x-unknown"}),
		"sql injection in a grpc-web query": forwardAuth(http.MethodPost, "/zitadel.admin.v1.AdminService/Healthz?id=1%27%20OR%20%271%27=%271", grpcFrame,
			map[string]string{"Content-Type": "application/grpc-web+proto", "X-Forwarded-Host": grpcHost + ":8080"}),
		// Without the gRPC host, the gRPC content type is not on the list and the body is read.
		"grpc content type on another host": forwardAuth(http.MethodPost, "/llm/v1/chat", grpcFrame,
			map[string]string{"Content-Type": "application/grpc"}),
		"command injection as grpc on another host": forwardAuth(http.MethodPost, "/llm/v1/chat", `{"cmd":"; cat /etc/passwd"}`,
			map[string]string{"Content-Type": "application/grpc"}),
		"command injection as grpc-web-text on the gRPC host": forwardAuth(http.MethodPost, "/zitadel.admin.v1.AdminService/Healthz", "user=admin%27%20OR%201=1--",
			map[string]string{"Content-Type": "application/grpc-web-text", "X-Forwarded-Host": grpcHost}),
		"grpc to the login UI path on the gRPC host": forwardAuth(http.MethodPost, "/ui/v2/login/login", grpcFrame,
			map[string]string{"Content-Type": "application/grpc", "X-Forwarded-Host": grpcHost}),
		"text/plain server action on another host": forwardAuth(http.MethodPost, "/ui/v2/login/verify", `["x"]`,
			map[string]string{"Content-Type": "text/plain;charset=UTF-8", "Next-Action": "7f3a"}),
		"text/plain to the login UI without Next-Action": forwardAuth(http.MethodPost, "/ui/v2/login/verify", `["x"]`,
			map[string]string{"Content-Type": "text/plain;charset=UTF-8", "X-Forwarded-Host": grpcHost}),
		"text/plain server action outside the login UI": forwardAuth(http.MethodPost, "/v2/users/human", `["x"]`,
			map[string]string{"Content-Type": "text/plain;charset=UTF-8", "Next-Action": "7f3a", "X-Forwarded-Host": grpcHost}),
		"sql injection in a login UI server action": forwardAuth(http.MethodPost, "/ui/v2/login/password", `[{"loginName":"admin' OR 1=1--","password":"x"}]`,
			map[string]string{"Content-Type": "text/plain;charset=UTF-8", "Next-Action": "7f3a", "X-Forwarded-Host": grpcHost}),
		"mongodb operator in json on another host": forwardAuth(http.MethodPost, "/stub/find", `{"user":{"$ne":null}}`,
			map[string]string{"Content-Type": "application/json"}),
		"localhost URL in another argument of authorize": forwardAuth(http.MethodGet, "/oauth/v2/authorize?client_id=1&redirect_uri=https%3A%2F%2Fstudio.example&login_hint=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data", "",
			map[string]string{"X-Forwarded-Host": grpcHost}),
		"localhost redirect_uri on another host": forwardAuth(http.MethodGet, "/stub/oauth/v2/authorize?redirect_uri=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data", "", nil),
		"sessionId without Referer on another host": forwardAuth(http.MethodGet, "/stub/?sessionId=397091455929197316", "", nil),
		"gRPC host with a lookalike name": forwardAuth(http.MethodPost, "/zitadel.admin.v1.AdminService/Healthz", grpcFrame,
			map[string]string{"Content-Type": "application/grpc", "X-Forwarded-Host": "auth.localhost.evil.example"}),
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", w.Code)
			}
		})
	}
}

func TestCheck_BenignRequest_Returns200(t *testing.T) {
	h := blockingHandler(t)
	cases := map[string]*http.Request{
		"plain get":  forwardAuth(http.MethodGet, "/stub/", "", nil),
		"query text": forwardAuth(http.MethodGet, "/stub/search?q=red+synthesizer&page=2", "", nil),
		"json body": forwardAuth(http.MethodPost, "/stub/notes", `{"title":"Hello","text":"A short note about filters."}`,
			map[string]string{"Content-Type": "application/json"}),
		// Zitadel API and console on the edge (gRPC, gRPC-web, Connect).
		"grpc-web proto": forwardAuth(http.MethodPost, "/zitadel.admin.v1.AdminService/Healthz", grpcFrame,
			map[string]string{"Content-Type": "application/grpc-web+proto", "X-Grpc-Web": "1", "X-Forwarded-Host": grpcHost + ":8080"}),
		"grpc": forwardAuth(http.MethodPost, "/zitadel.admin.v1.AdminService/Healthz", grpcFrame,
			map[string]string{"Content-Type": "application/grpc", "X-Forwarded-Host": grpcHost}),
		// Zitadel login UI v2 (Next.js server action): text/plain with a JSON argument list.
		"login UI server action": forwardAuth(http.MethodPost, "/ui/v2/login/verify", `[{"userId":"397091281899135748","code":"BX70WU","isInvite":true}]`,
			map[string]string{"Content-Type": "text/plain;charset=UTF-8", "Next-Action": "7f3a", "X-Forwarded-Host": grpcHost + ":8080"}),
		"login UI server action with Next.js references": forwardAuth(http.MethodPost, "/ui/v2/login/passkey", `[{"sessionId":"397091702638158596","organization":"$undefined","requestId":"$undefined"},"$K1"]`,
			map[string]string{"Content-Type": "text/plain;charset=UTF-8", "Next-Action": "7f3a", "X-Forwarded-Host": grpcHost}),
		"authorize with a localhost redirect_uri": forwardAuth(http.MethodGet, "/oauth/v2/authorize?client_id=1&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fapi%2Fauth%2Fcallback&response_type=code&scope=openid", "",
			map[string]string{"X-Forwarded-Host": grpcHost + ":8080"}),
		"token request with a localhost redirect_uri": forwardAuth(http.MethodPost, "/oauth/v2/token", "grant_type=authorization_code&code=abc&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fapi%2Fauth%2Fcallback&code_verifier=x",
			map[string]string{"Content-Type": "application/x-www-form-urlencoded", "X-Forwarded-Host": grpcHost}),
		"login UI step with sessionId and no Referer": forwardAuth(http.MethodGet, "/ui/v2/login/authenticator/set?sessionId=397091455929197316&loginName=probe.x", "",
			map[string]string{"X-Forwarded-Host": grpcHost + ":8080"}),
		"connect proto": forwardAuth(http.MethodPost, "/zitadel.settings.v2.SettingsService/GetGeneralSettings", "\x08\x01",
			map[string]string{"Content-Type": "application/proto", "X-Forwarded-Host": grpcHost}),
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", w.Code)
			}
		})
	}
}

func TestCheck_TwoContentTypes_Returns400(t *testing.T) {
	h := blockingHandler(t)
	r := forwardAuth(http.MethodPost, "/zitadel.admin.v1.AdminService/Healthz", `{"cmd":"; cat /etc/passwd"}`,
		map[string]string{"X-Forwarded-Host": grpcHost})
	r.Header.Add("Content-Type", "application/grpc")
	r.Header.Add("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestConfigFromEnv_GRPCHosts(t *testing.T) {
	cfg, err := waf.ConfigFromEnv(func(k string) string {
		if k == "SYNTHWERK_WAF_GRPC_HOSTS" {
			return " Auth.localhost , synthwerkauth.velimir-mueller.de,"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"auth.localhost", "synthwerkauth.velimir-mueller.de"}
	if strings.Join(cfg.GRPCHosts, " ") != strings.Join(want, " ") {
		t.Fatalf("GRPCHosts = %v, want %v", cfg.GRPCHosts, want)
	}
	if _, err := waf.ConfigFromEnv(func(k string) string {
		if k == "SYNTHWERK_WAF_GRPC_HOSTS" {
			return "auth.localhost:8080"
		}
		return ""
	}); err == nil {
		t.Fatal("host with a port: want error")
	}
}

func TestCheck_NotForwardAuth_Returns400(t *testing.T) {
	h := blockingHandler(t)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://waf:8080/check", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestCheck_DetectionOnly_LetsAttackPass(t *testing.T) {
	cfg, err := waf.ConfigFromEnv(func(k string) string {
		if k == "SYNTHWERK_WAF_ENGINE" {
			return "DetectionOnly"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	h, err := waf.New(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, forwardAuth(http.MethodGet, "/stub/?id=1%27%20OR%20%271%27=%271", "", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func TestConfigFromEnv_Defaults(t *testing.T) {
	cfg, err := waf.ConfigFromEnv(func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Engine != "On" || cfg.ParanoiaLevel != 1 || cfg.BodyLimitBytes != 1<<20 {
		t.Fatalf("defaults = %+v", cfg)
	}
}

func TestConfigFromEnv_InvalidValue_ReturnsError(t *testing.T) {
	cases := map[string]string{
		"SYNTHWERK_WAF_ENGINE":           "Off",
		"SYNTHWERK_WAF_PARANOIA_LEVEL":   "5",
		"SYNTHWERK_WAF_BODY_LIMIT_BYTES": "lots",
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := waf.ConfigFromEnv(func(k string) string {
				if k == name {
					return value
				}
				return ""
			})
			if err == nil {
				t.Fatalf("%s=%q: want error", name, value)
			}
		})
	}
}

func TestDirectives_SetsContentTypesBeforeCRS(t *testing.T) {
	d := waf.Directives(waf.Config{Engine: "On", ParanoiaLevel: 1, BodyLimitBytes: 1024, GRPCHosts: []string{grpcHost}})
	ct := strings.Index(d, "tx.allowed_request_content_type=")
	crs := strings.Index(d, "Include @owasp_crs/")
	if ct < 0 || crs < 0 || ct > crs {
		t.Fatalf("content types must be set before the CRS rules:\n%s", d)
	}
}

func TestDirectives_SetsParanoiaLevelBeforeCRS(t *testing.T) {
	d := waf.Directives(waf.Config{Engine: "On", ParanoiaLevel: 2, BodyLimitBytes: 1024})
	pl := strings.Index(d, "tx.blocking_paranoia_level=2")
	crs := strings.Index(d, "Include @owasp_crs/")
	if pl < 0 || crs < 0 || pl > crs {
		t.Fatalf("paranoia level must be set before the CRS rules:\n%s", d)
	}
}

// chatPath is the llm send route on the edge, before the prefix strip.
const chatPath = "/llm/v1/conversations/0199f3b0-1a2c-7c3d-8e4f-5a6b7c8d9e10/messages"

// A chat prompt is plain user text: SQL or HTML in it is a question, not an attack.
// Only the JSON field "content" of the send route skips the CRS rules (#32).
func TestCheck_ChatPrompt_PassesOnlyInContent(t *testing.T) {
	h := blockingHandler(t)
	prompt := `{"content":"Why is ' OR 1=1 -- bad, and what does <script>alert(1)</script> do? Also ; cat /etc/passwd"}`
	jsonHeader := map[string]string{"Content-Type": "application/json"}
	pass := map[string]*http.Request{
		"prompt in content": forwardAuth(http.MethodPost, chatPath, prompt, jsonHeader),
		"plain prompt":      forwardAuth(http.MethodPost, chatPath, `{"content":"exit"}`, jsonHeader),
	}
	for name, req := range pass {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status %d, want 200", name, rec.Code)
		}
	}
	block := map[string]*http.Request{
		"same text in another field": forwardAuth(http.MethodPost, chatPath, `{"content":"hi","model":"' OR 1=1 --"}`, jsonHeader),
		"same text in the query":     forwardAuth(http.MethodPost, chatPath+"?q=1%27%20OR%201=1%20--", `{"content":"hi"}`, jsonHeader),
		"same text in a header": forwardAuth(http.MethodPost, chatPath, `{"content":"hi"}`,
			map[string]string{"Content-Type": "application/json", "Referer": "http://x/?id=1' OR '1'='1"}),
		"content on another route": forwardAuth(http.MethodPost, "/llm/v1/conversations", prompt, jsonHeader),
		"content on a longer path": forwardAuth(http.MethodPost, chatPath+"/x", prompt, jsonHeader),
		"content on GET":           forwardAuth(http.MethodGet, chatPath, prompt, jsonHeader),
	}
	for name, req := range block {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", name, rec.Code)
		}
	}
}

// A login UI server action body is parsed as JSON. A body that is not JSON is refused
// (the body processor error answers 400), so text/plain cannot skip the inspection.
func TestCheck_LoginUIActionNotJSON_Refused(t *testing.T) {
	h := blockingHandler(t)
	r := forwardAuth(http.MethodPost, "/ui/v2/login/password", `user=x&<script>`,
		map[string]string{"Content-Type": "text/plain;charset=UTF-8", "Next-Action": "7f3a", "X-Forwarded-Host": grpcHost})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code == http.StatusOK {
		t.Fatalf("status = %d, want a refusal", w.Code)
	}
}
