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
	"regexp"
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
	// GRPCHosts are the host names (without port) that may send gRPC, gRPC-web
	// and Connect requests. Empty: no host may.
	GRPCHosts []string
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
	for h := range strings.SplitSeq(getenv("SYNTHWERK_WAF_GRPC_HOSTS"), ",") {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if !hostName.MatchString(h) {
			return Config{}, fmt.Errorf("SYNTHWERK_WAF_GRPC_HOSTS: %q is not a host name", h)
		}
		cfg.GRPCHosts = append(cfg.GRPCHosts, h)
	}
	return cfg, nil
}

var hostName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

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

// GRPCContentTypes is the CRS list of request content types (rule 920420
// blocks every other one) for the GRPCHosts: the CRS v4 defaults plus gRPC,
// gRPC-web and Connect, which the Zitadel API and console use on the edge.
// Every other host keeps the CRS defaults.
const GRPCContentTypes = "|application/x-www-form-urlencoded| |multipart/form-data| |text/xml| |application/xml| |application/soap+xml| |application/json|" +
	" |application/grpc| |application/grpc+proto| |application/grpc-web| |application/grpc-web+proto| |application/grpc-web-text| |application/grpc-web-text+proto|" +
	" |application/proto| |application/connect+proto| |application/connect+json|"

// LoginUIContentTypes is the CRS v4 default list of request content types. Rule
// 900223 adds text/plain to it for login UI server actions only.
const LoginUIContentTypes = "|application/x-www-form-urlencoded| |multipart/form-data| |multipart/related| |text/xml| |application/xml| |application/soap+xml| |application/json| |application/cloudevents+json| |application/cloudevents-batch+json|"

// grpcRules returns the rules for the GRPCHosts, or only 900222 without hosts.
// 900220 and 900221 apply only to a request for a GRPCHosts host AND a gRPC
// method path (/<package>.<Service>/<Method>), so the login UI on the same host
// keeps the CRS defaults.
//
//   - 900220: such a request gets the GRPCContentTypes list.
//   - 900221: such a request with a binary protobuf body (gRPC, gRPC-web,
//     Connect proto) is not body-inspected. Every gRPC frame starts with null
//     bytes, which CRS reads as form arguments and blocks (rule 920270). The
//     method, URI, query and headers are still checked. Text bodies (Connect
//     JSON, gRPC-web-text in base64) keep body inspection.
//   - 900222: more than one Content-Type header gets 400 on every host, so a
//     second header cannot switch off the body check for a body the backend
//     reads as something else.
//   - 900223: a Zitadel login UI v2 server action (POST under /ui/v2/login/ with
//     a Next-Action header) on a GRPCHosts host may send text/plain: Next.js
//     posts its JSON argument list with that type. CRS 920420 refuses
//     text/plain, so without this rule nobody can sign in through the edge. The
//     body is parsed as JSON, so it is still inspected; a body that is not
//     JSON fails the CRS body check (200002). CRS 942290 (MongoDB operators
//     like "$ne") is off for these requests only: Next.js writes "$"-prefixed
//     references ("$undefined", "$K1") into every argument list. The other
//     SQL injection rules stay on.
//   - 900224: on a GRPCHosts host under /ui/v2/login/, CRS 943120 (session
//     fixation: a "sessionId" argument without a Referer) skips the argument name sessionId.
//     Login UI v2 passes its own Zitadel session id in that argument on every
//     step and checks it against its signed session cookie. Every other rule
//     still reads sessionId.
//   - 900225: on a GRPCHosts host, CRS 934110 (SSRF: a URL to a local or
//     private address in an argument) skips redirect_uri and
//     post_logout_redirect_uri on /oauth/v2/authorize, /oauth/v2/token and
//     /oidc/v1/end_session.
//     Zitadel only redirects to URIs registered on the app (exact match), and
//     local studio callbacks are http://localhost:3000/... .
func grpcRules(hosts []string) []string {
	rules := []string{
		`SecRule &REQUEST_HEADERS:Content-Type "@gt 1" "id:900222,phase:1,deny,status:400,t:none,log,msg:'More than one Content-Type header'"`,
	}
	if len(hosts) == 0 {
		return rules
	}
	quoted := make([]string, len(hosts))
	for i, h := range hosts {
		quoted[i] = regexp.QuoteMeta(h)
	}
	host := fmt.Sprintf(`SecRule REQUEST_HEADERS:Host "@rx ^(?:%s)(?::[0-9]+)?$"`, strings.Join(quoted, "|"))
	path := `  SecRule REQUEST_FILENAME "@rx ^/[a-z0-9_]+(?:\.[a-z0-9_]+)*\.[A-Za-z0-9_]+/[A-Za-z0-9_]+$" "t:none,chain"`
	return append(rules,
		host+` "id:900220,phase:1,pass,t:none,t:lowercase,nolog,chain"`+"\n"+path+"\n"+
			fmt.Sprintf(`  SecAction "setvar:'tx.allowed_request_content_type=%s'"`, GRPCContentTypes),
		host+` "id:900221,phase:1,pass,t:none,t:lowercase,nolog,chain"`+"\n"+path+"\n"+
			`  SecRule REQUEST_HEADERS:Content-Type "@rx ^application/(?:grpc(?:-web)?(?:\+proto)?|connect\+proto|proto)(?:;|$)" "t:none,t:lowercase,ctl:requestBodyAccess=Off"`,
		host+` "id:900223,phase:1,pass,t:none,t:lowercase,nolog,chain"`+"\n"+
			`  SecRule REQUEST_METHOD "@streq POST" "t:none,chain"`+"\n"+
			`  SecRule REQUEST_FILENAME "@beginsWith /ui/v2/login/" "t:none,chain"`+"\n"+
			`  SecRule &REQUEST_HEADERS:Next-Action "@eq 1" "t:none,chain"`+"\n"+
			`  SecRule REQUEST_HEADERS:Content-Type "@rx ^text/plain(?:;\s*charset=utf-8)?$" "t:none,t:lowercase,ctl:requestBodyProcessor=JSON,ctl:ruleRemoveById=942290,`+
			fmt.Sprintf(`setvar:'tx.allowed_request_content_type=%s |text/plain|'"`, LoginUIContentTypes),
		host+` "id:900224,phase:1,pass,t:none,t:lowercase,nolog,chain"`+"\n"+
			`  SecRule REQUEST_FILENAME "@beginsWith /ui/v2/login/" "t:none,ctl:ruleRemoveTargetById=943120;ARGS_NAMES:sessionId"`,
		host+` "id:900225,phase:1,pass,t:none,t:lowercase,nolog,chain"`+"\n"+
			`  SecRule REQUEST_FILENAME "@rx ^/(?:oauth/v2/(?:authorize|token)|oidc/v1/end_session)$" "t:none,ctl:ruleRemoveTargetById=934110;ARGS:redirect_uri,ctl:ruleRemoveTargetById=934110;ARGS:post_logout_redirect_uri"`,
	)
}

// ChatContentRule lets a chat prompt through (synthwerk-llm, #32). A prompt is plain
// user text: SQL, HTML or shell in it is a question, not an attack, and the gateway
// never runs or renders it. Only the JSON field "content" of
// POST /llm/v1/conversations/<uuid>/messages leaves the CRS rules. The URI, the
// query, the headers and every other body field are still checked.
const ChatContentRule = `SecRule REQUEST_METHOD "@streq POST" "id:900230,phase:1,pass,t:none,nolog,chain"` + "\n" +
	`  SecRule REQUEST_FILENAME "@rx ^/llm/v1/conversations/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/messages$" "t:none,ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS:json.content"`

// Directives returns the SecLang directives for cfg. CRS is read from the
// embedded coraza-coreruleset files, so the container needs no rule files.
func Directives(cfg Config) string {
	d := []string{
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
	}
	d = append(d, grpcRules(cfg.GRPCHosts)...)
	d = append(d, ChatContentRule, "Include @owasp_crs/*.conf")
	return strings.Join(d, "\n")
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
