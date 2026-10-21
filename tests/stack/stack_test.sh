#!/usr/bin/env bash
# Stack test: the running compose stack is healthy and the edge WAF works.
# Needs a running stack: scripts/init-env.sh && docker compose up --wait
#
# Usage: tests/stack/stack_test.sh   (exit 0 = all checks pass)
set -euo pipefail
cd "$(dirname "$0")/../.."

EDGE="http://127.0.0.1:${SYNTHWERK_EDGE_HTTP_PORT:-8080}"
failures=0

pass() { printf 'ok   %s\n' "$1"; }
fail() { printf 'FAIL %s\n' "$1"; failures=$((failures + 1)); }

# expect_status <name> <want> <curl args...>
expect_status() {
  local name=$1 want=$2 got
  shift 2
  got=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$@" || true)
  if [[ "$got" == "$want" ]]; then pass "$name ($got)"; else fail "$name: got $got, want $want"; fi
}

echo "# every default service is running and healthy"
expected=$(docker compose config --services | sort)
for svc in $expected; do
  state=$(docker compose ps --format '{{.Health}}' "$svc" 2>/dev/null || true)
  if [[ "$state" == "healthy" ]]; then pass "$svc healthy"; else fail "$svc: health '${state:-not running}'"; fi
done

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
trap 'rm -f "$big"' EXIT
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
