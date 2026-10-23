#!/usr/bin/env bash
# Stack test: the running compose stack is healthy, the edge WAF works and pulse
# streams the status of each service.
# Needs a running stack: scripts/init-env.sh && docker compose up --wait
#
# Usage: tests/stack/stack_test.sh   (exit 0 = all checks pass)
set -euo pipefail
cd "$(dirname "$0")/../.."

EDGE="http://127.0.0.1:${SYNTHWERK_EDGE_HTTP_PORT:-8080}"
# Zitadel is routed by host name. --resolve sends it to the local edge.
AUTH_HOST="${SYNTHWERK_ZITADEL_EXTERNAL_DOMAIN:-auth.localhost}"
AUTH="http://$AUTH_HOST:${SYNTHWERK_EDGE_HTTP_PORT:-8080}"
AUTH_RESOLVE=(--resolve "$AUTH_HOST:${SYNTHWERK_EDGE_HTTP_PORT:-8080}:127.0.0.1")
failures=0
big=""
stream_log=""
stream_pid=""
cleanup() {
  [[ -n "$stream_pid" ]] && kill "$stream_pid" 2>/dev/null
  rm -f "$big" "$stream_log"
}
trap cleanup EXIT

pass() { printf 'ok   %s\n' "$1"; }
fail() { printf 'FAIL %s\n' "$1"; failures=$((failures + 1)); }

# expect_status <name> <want> <curl args...>
expect_status() {
  local name=$1 want=$2 got
  shift 2
  got=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$@" || true)
  if [[ "$got" == "$want" ]]; then pass "$name ($got)"; else fail "$name: got $got, want $want"; fi
}

# One-shot services: they must have exited with code 0, not be healthy.
oneshot=" database-init "

echo "# every default service is running and healthy"
# "config --services" lists only the services of the active profiles (none by default,
# or COMPOSE_PROFILES), so a profile service such as ollama is expected only when enabled.
expected=$(docker compose config --services | sort)
for svc in $expected; do
  if [[ "$oneshot" == *" $svc "* ]]; then
    state=$(docker compose ps --all --format '{{.State}} {{.ExitCode}}' "$svc" 2>/dev/null || true)
    if [[ "$state" == "exited 0" ]]; then pass "$svc exited 0"; else fail "$svc: state '${state:-not run}'"; fi
    continue
  fi
  state=$(docker compose ps --format '{{.Health}}' "$svc" 2>/dev/null || true)
  if [[ "$state" == "healthy" ]]; then pass "$svc healthy"; else fail "$svc: health '${state:-not running}'"; fi
done

echo "# services answer through the edge"
expect_status "GET /identity/readyz" 200 "$EDGE/identity/readyz"
expect_status "GET /llm/readyz" 200 "$EDGE/llm/readyz"
expect_status "Zitadel /debug/ready" 200 "${AUTH_RESOLVE[@]}" "$AUTH/debug/ready"
expect_status "Zitadel OIDC discovery" 200 "${AUTH_RESOLVE[@]}" "$AUTH/.well-known/openid-configuration"
expect_status "Zitadel login UI" 200 "${AUTH_RESOLVE[@]}" "$AUTH/ui/v2/login/healthy"
expect_status "Zitadel gRPC-web passes the WAF" 200 "${AUTH_RESOLVE[@]}" -X POST \
  -H 'Content-Type: application/grpc-web+proto' -H 'X-Grpc-Web: 1' --data-binary @/dev/null \
  "$AUTH/zitadel.admin.v1.AdminService/Healthz"
expect_status "gRPC content type on /llm gets 403" 403 -X POST -H 'Content-Type: application/grpc' \
  --data '{"cmd":"; cat /etc/passwd"}' "$EDGE/llm/v1/chat"
expect_status "SQL injection on the auth host gets 403" 403 "${AUTH_RESOLVE[@]}" \
  "$AUTH/oauth/v2/authorize?client_id=1%27%20OR%20%271%27=%271"
issuer=$(curl -s --max-time 10 "${AUTH_RESOLVE[@]}" "$AUTH/.well-known/openid-configuration" | grep -o '"issuer":"[^"]*"' || true)
if [[ "$issuer" == "\"issuer\":\"$AUTH\"" ]]; then pass "issuer is $AUTH"; else fail "issuer: got '${issuer:-none}', want $AUTH"; fi

echo "# database roles see only their own schema"
# psql_as <role> <sql> [database]: run as a service role inside the database container.
psql_as() {
  local role=$1 sql=$2 db=${3:-${SYNTHWERK_POSTGRES_DB:-synthwerk}} var password
  var="SYNTHWERK_$(tr '[:lower:]' '[:upper:]' <<<"$role")_DB_PASSWORD"
  password=$(grep "^$var=" .env | cut -d= -f2- || true)
  if [[ -z "$password" ]]; then
    echo "no $var in .env"
    return
  fi
  docker compose exec -T -e PGPASSWORD="$password" database \
    psql -h 127.0.0.1 -U "$role" -d "$db" -tAc "$sql" 2>&1 || true
}
if [[ "$(psql_as identity 'SHOW search_path')" == "identity" ]]; then pass "identity search_path"; else fail "identity search_path"; fi
# Capture first: grep -q in a pipe ends early, and pipefail turns the SIGPIPE into a failure.
out=$(psql_as llm 'SELECT count(*) FROM identity.synthwerk_outbox')
if [[ "$out" == *"permission denied"* ]]; then pass "llm cannot read the identity schema"; else fail "llm can read the identity schema"; fi
out=$(psql_as llm 'SELECT 1' zitadel)
if [[ "$out" == *"permission denied"* ]]; then pass "llm cannot connect to the zitadel database"; else fail "llm can connect to the zitadel database"; fi

echo "# CORS on /llm and /identity"
# cors_origin <origin>: the Access-Control-Allow-Origin of a preflight, or empty.
cors_origin() {
  curl -s -o /dev/null -D - --max-time 10 -X OPTIONS -H "Origin: $1" \
    -H 'Access-Control-Request-Method: POST' -H 'Access-Control-Request-Headers: authorization,content-type' \
    "$EDGE/llm/v1/chat" | tr -d '\r' | awk -F': ' 'tolower($1) == "access-control-allow-origin" { print $2 }'
}
allowed="${SYNTHWERK_CORS_ORIGINS:-http://localhost:3000,http://localhost:5173}"
allowed="${allowed%%,*}"
if [[ "$(cors_origin "$allowed")" == "$allowed" ]]; then pass "preflight from $allowed is allowed"; else fail "preflight from $allowed has no allow-origin"; fi
if [[ -z "$(cors_origin https://evil.example)" ]]; then pass "preflight from a foreign origin is not allowed"; else fail "foreign origin is allowed"; fi

echo "# benign requests pass the WAF"
expect_status "GET /stub/" 200 "$EDGE/stub/"
expect_status "GET with a plain query" 200 "$EDGE/stub/search?q=red+synthesizer&page=2"
expect_status "POST JSON body" 200 -H 'Content-Type: application/json' \
  --data '{"title":"Hello","text":"A short note about filters."}' "$EDGE/stub/notes"

echo "# known attacks get 403 from the WAF"
expect_status "SQL injection in query" 403 "$EDGE/stub/?id=1%27%20OR%20%271%27=%271"
expect_status "path traversal in query" 403 "$EDGE/stub/?file=../../../../etc/passwd"
expect_status "XSS in query" 403 "$EDGE/stub/?q=%3Cscript%3Ealert(1)%3C/script%3E"
expect_status "SQL injection in form body" 403 --data "user=admin' OR 1=1--&pass=x" "$EDGE/stub/login"

echo "# limits"
big=$(mktemp)
head -c 1100000 /dev/zero | tr '\0' 'a' >"$big"
expect_status "body over 1 MiB gets 413" 413 --data-binary "@$big" "$EDGE/stub/upload"
expect_status "unknown route gets 404" 404 "$EDGE/unknown"

echo "# no query string or client IP in the edge and WAF logs"
canary="canary$RANDOM$RANDOM"
expect_status "benign request with a canary query" 200 "$EDGE/stub/?token=$canary"
expect_status "attack with a canary query" 403 "$EDGE/stub/?token=$canary&id=1%27%20OR%20%271%27=%271"
sleep 1
logs=$(docker compose logs --no-color edge waf 2>&1)
if grep -q "$canary" <<<"$logs"; then fail "a query value is in the logs"; else pass "no query value in the logs"; fi
expect_status "request with ?token=secret123" 200 "$EDGE/stub/?token=secret123"
sleep 1
if docker compose logs --no-color edge 2>&1 | grep -q secret123; then fail "secret123 is in the edge logs"; else pass "secret123 is not in the edge logs"; fi
if grep -qE '"Client(Addr|Host)"' <<<"$logs"; then fail "the access log has the client IP"; else pass "no client IP in the access log"; fi
if grep -q '"RouterName":"stub@file"' <<<"$logs"; then pass "access log is written"; else fail "no access log line for the stub router"; fi

echo "# pulse streams the status of each service (synthwerk#26)"
# wait_for <pattern> <seconds>: true when the stream log holds the pattern in time.
wait_for() {
  local pattern=$1 limit=$2 start=$SECONDS
  while ((SECONDS - start < limit)); do
    grep -q -- "$pattern" "$stream_log" && return 0
    sleep 1
  done
  return 1
}
stream_log=$(mktemp)
curl -sN --max-time 180 "$EDGE/pulse/v1/health/stream" >"$stream_log" 2>/dev/null &
stream_pid=$!
if wait_for '^event: snapshot' 10; then pass "stream starts with a snapshot"; else fail "no snapshot on the pulse stream"; fi
# The snapshot data line can land after the event line: wait for each target.
# A target turns ok after 3 good checks (5 s apart), so a service that just
# started can need about 15 s: wait up to 30 s.
for svc in edge waf bus database telemetry stub zitadel zitadel-login identity llm; do
  if wait_for "\"target\":\"$svc\",\"status\":\"ok\"" 30; then pass "snapshot: $svc ok"; else fail "snapshot: $svc not ok"; fi
done
docker compose stop stub >/dev/null 2>&1
start=$SECONDS
if wait_for '"target":"stub","from":"ok","status":"down"' 30; then
  pass "stopped stub is down on the stream after $((SECONDS - start)) s (limit 30 s)"
else
  fail "stopped stub is not down on the stream within 30 s"
fi
# Wait for the container itself first, so the window measures pulse, not container start.
docker compose up --wait stub >/dev/null 2>&1
start=$SECONDS
if wait_for '"target":"stub","from":"down","status":"ok"' 60; then
  pass "started stub is ok on the stream after $((SECONDS - start)) s"
else
  fail "started stub is not ok on the stream within 60 s"
fi
kill "$stream_pid" 2>/dev/null || true
stream_pid=""

echo "# the edge fails closed when the WAF is down"
docker compose stop waf >/dev/null 2>&1
expect_status "request without WAF gets 500" 500 "$EDGE/stub/"
docker compose start waf >/dev/null 2>&1
docker compose up --wait waf >/dev/null 2>&1
expect_status "request after WAF restart gets 200" 200 "$EDGE/stub/"

# Last: the burst leaves this client rate limited for a moment.
echo "# the rate limit answers 429 to a burst"
limited=$(curl -s -Z --parallel-max 100 -o /dev/null -w '%{http_code}\n' "$EDGE/stub/?n=[1-400]" | grep -c '^429$' || true)
if ((limited > 0)); then pass "burst of 400 requests: $limited got 429"; else fail "burst of 400 requests: no 429"; fi

if ((failures > 0)); then
  echo "$failures check(s) failed"
  exit 1
fi
echo "all checks passed"
