// Package waf checks requests with Coraza and the OWASP Core Rule Set (CRS v4).
//
// Traefik calls the handler as a forwardAuth middleware. Traefik sends the
// original request line in X-Forwarded-* headers and the original body. The
// handler answers 200 to let the request pass, or the status of the matched
// rule (403 for CRS) to block it. Traefik returns that status to the client.
package waf

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

// Config holds the WAF settings. Load it with ConfigFromEnv.
type Config struct {
	// Engine is "On" (block) or "DetectionOnly" (log only).
	Engine string
	// ParanoiaLevel is the CRS blocking paranoia level, 1 to 4.
	ParanoiaLevel int
	// BodyLimitBytes is the largest request body the WAF reads.
	BodyLimitBytes int
}

// Defaults: block, CRS paranoia level 1, 1 MiB body (same as the edge buffer).
const (
	DefaultEngine         = "On"
	DefaultParanoiaLevel  = 1
	DefaultBodyLimitBytes = 1 << 20
)

// ConfigFromEnv reads SYNTHWERK_WAF_* settings. getenv is os.Getenv in production.
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	cfg := Config{Engine: DefaultEngine, ParanoiaLevel: DefaultParanoiaLevel, BodyLimitBytes: DefaultBodyLimitBytes}
	if v := getenv("SYNTHWERK_WAF_ENGINE"); v != "" {
		cfg.Engine = v
	}
	if cfg.Engine != "On" && cfg.Engine != "DetectionOnly" {
		return Config{}, fmt.Errorf("SYNTHWERK_WAF_ENGINE must be On or DetectionOnly, got %q", cfg.Engine)
	}
	var err error
	if cfg.ParanoiaLevel, err = intFromEnv(getenv, "SYNTHWERK_WAF_PARANOIA_LEVEL", cfg.ParanoiaLevel, 1, 4); err != nil {
		return Config{}, err
	}
	if cfg.BodyLimitBytes, err = intFromEnv(getenv, "SYNTHWERK_WAF_BODY_LIMIT_BYTES", cfg.BodyLimitBytes, 1, 64<<20); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func intFromEnv(getenv func(string) string, name string, def, lo, hi int) (int, error) {
	v := getenv(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		return 0, fmt.Errorf("%s must be an integer from %d to %d, got %q", name, lo, hi, v)
	}
	return n, nil
}

// Directives returns the SecLang directives for cfg. CRS is read from the
// embedded coraza-coreruleset files, so the container needs no rule files.
func Directives(cfg Config) string {
	return strings.Join([]string{
		"Include @coraza.conf-recommended",
		"SecRuleEngine " + cfg.Engine,
		"SecRequestBodyAccess On",
		fmt.Sprintf("SecRequestBodyLimit %d", cfg.BodyLimitBytes),
		fmt.Sprintf("SecRequestBodyInMemoryLimit %d", cfg.BodyLimitBytes),
		"SecRequestBodyLimitAction Reject",
		// forwardAuth never sends the response, so response rules have nothing to read.
		"SecResponseBodyAccess Off",
		// Audit logs would hold request content. Block events go to stdout without it.
		"SecAuditEngine Off",
		"Include @crs-setup.conf.example",
		fmt.Sprintf(`SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=%d"`, cfg.ParanoiaLevel),
		"Include @owasp_crs/*.conf",
	}, "\n")
}

// Handler is the forwardAuth endpoint.
type Handler struct {
	waf coraza.WAF
	log *slog.Logger
}

// New builds the WAF. It fails when a directive does not parse.
func New(cfg Config, log *slog.Logger) (*Handler, error) {
	w, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithDirectives(Directives(cfg)))
	if err != nil {
		return nil, fmt.Errorf("build waf: %w", err)
	}
	return &Handler{waf: w, log: log}, nil
}

// forwardHeaders are set by Traefik for the WAF. They are not part of the
// client request, so the rules do not see them.
var forwardHeaders = map[string]bool{
	"X-Forwarded-For":    true,
	"X-Forwarded-Host":   true,
	"X-Forwarded-Method": true,
	"X-Forwarded-Port":   true,
	"X-Forwarded-Proto":  true,
	"X-Forwarded-Uri":    true,
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	method := r.Header.Get("X-Forwarded-Method")
	uri := r.Header.Get("X-Forwarded-Uri")
	if method == "" || uri == "" {
		// Not a forwardAuth call. Fail closed.
		http.Error(w, "missing X-Forwarded-Method or X-Forwarded-Uri", http.StatusBadRequest)
		return
	}
	host := r.Header.Get("X-Forwarded-Host")

	tx := h.waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		if err := tx.Close(); err != nil {
			h.log.Warn("close transaction", "err", err)
		}
	}()

	tx.ProcessConnection(clientIP(r), 0, "", 0)
	tx.ProcessURI(uri, method, r.Proto)
	for name, values := range r.Header {
		if forwardHeaders[name] {
			continue
		}
		for _, v := range values {
			tx.AddRequestHeader(name, v)
		}
	}
	if host != "" {
		tx.AddRequestHeader("Host", host)
		tx.SetServerName(host)
	}

	it := tx.ProcessRequestHeaders()
	if it == nil {
		// Phase 2 runs for every request, also without a body.
		body := r.Body
		if body == nil {
			body = http.NoBody
		}
		var err error
		if it, _, err = tx.ReadRequestBodyFrom(body); err != nil {
			h.log.Error("read body", "err", err)
			http.Error(w, "waf error", http.StatusInternalServerError)
			return
		}
		if it == nil {
			if it, err = tx.ProcessRequestBody(); err != nil {
				h.log.Error("process body", "err", err)
				http.Error(w, "waf error", http.StatusInternalServerError)
				return
			}
		}
	}

	if it != nil {
		status := statusOf(it)
		// Rule IDs and the path only. The query and the body can hold personal data.
		h.log.Info("request blocked",
			"status", status,
			"rule_id", it.RuleID,
			"matched_rules", matchedRuleIDs(tx.MatchedRules()),
			"http.request.method", method,
			"url.path", pathOf(uri),
		)
		w.WriteHeader(status)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func statusOf(it *types.Interruption) int {
	if it.Status >= 400 && it.Status < 600 {
		return it.Status
	}
	return http.StatusForbidden
}

// clientIP is the last X-Forwarded-For entry: the peer address that Traefik saw.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func pathOf(uri string) string {
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		return uri[:i]
	}
	return uri
}

func matchedRuleIDs(rules []types.MatchedRule) []int {
	ids := make([]int, 0, len(rules))
	for _, m := range rules {
		if m.Rule().ID() != 0 && len(m.Message()) > 0 {
			ids = append(ids, m.Rule().ID())
		}
	}
	return ids
}
