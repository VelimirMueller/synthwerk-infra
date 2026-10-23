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
		cfg, err := waf.ConfigFromEnv(func(string) string { return "" })
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
		"sql injection in a grpc-web path": forwardAuth(http.MethodPost, "/zitadel.admin.v1.AdminService/Healthz?id=1%27%20OR%20%271%27=%271", grpcFrame,
			map[string]string{"Content-Type": "application/grpc-web+proto"}),
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
			map[string]string{"Content-Type": "application/grpc-web+proto", "X-Grpc-Web": "1"}),
		"grpc": forwardAuth(http.MethodPost, "/zitadel.admin.v1.AdminService/Healthz", grpcFrame,
			map[string]string{"Content-Type": "application/grpc"}),
		"connect proto": forwardAuth(http.MethodPost, "/zitadel.settings.v2.SettingsService/GetGeneralSettings", "\x08\x01",
			map[string]string{"Content-Type": "application/proto"}),
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
	d := waf.Directives(waf.Config{Engine: "On", ParanoiaLevel: 1, BodyLimitBytes: 1024})
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
