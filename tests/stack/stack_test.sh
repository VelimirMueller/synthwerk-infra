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
# Space on both ends: the loop matches *" $svc "*.
oneshot=" database-init zitadel-bootstrap ollama-pull "

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
# A response over 4 KiB passes the edge (the 4 KiB cap is on the WAF answer only).
script=$(curl -s --max-time 10 "${AUTH_RESOLVE[@]}" "$AUTH/ui/console/" | grep -o 'src="[^"]*\.js"' | head -n 1 | cut -d'"' -f2 || true)
size=$(curl -s -o /dev/null -w '%{size_download}' --max-time 10 "${AUTH_RESOLVE[@]}" "$AUTH/ui/console/$script" || true)
if ((${size:-0} > 4096)); then pass "console script of $size bytes passes the edge"; else fail "console script '$script': got ${size:-0} bytes"; fi
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

echo "# Zitadel setup as code (zitadel/bootstrap)"
# A second run on the real Zitadel must succeed (idempotent).
if out=$(docker compose run --rm --no-deps zitadel-bootstrap 2>&1); then pass "zitadel-bootstrap rerun exits 0"; else fail "zitadel-bootstrap rerun: $(grep -o '"err":"[^"]*"' <<<"$out" || echo "$out" | tail -n 3)"; fi
# Signs both test users in without a browser and checks org and roles in the token.
out=$(docker compose run --rm --no-deps zitadel-bootstrap selftest 2>&1 || true)
if [[ $(grep -c '"msg":"selftest ok"' <<<"$out") == 2 ]]; then pass "selftest: token claims carry org and role"; else fail "selftest: $(grep -o '"err":"[^"]*"' <<<"$out" || echo no output)"; fi
# The login UI must not see the IAM owner token.
out=$(docker compose exec -T zitadel-login sh -c 'test -e /zitadel/admin && echo present || echo absent' 2>&1 || true)
if [[ "$out" == "absent" ]]; then pass "zitadel-login cannot read the admin PAT"; else fail "zitadel-login sees /zitadel/admin: $out"; fi

echo "# Zitadel Actions reach identity (synthwerk#28 task 5)"
# A new user must reach identity as user.created. The test makes its own user: Zitadel
# caches executions, so users made in the first seconds after the bootstrap may miss it.
auth_domain=${SYNTHWERK_ZITADEL_EXTERNAL_DOMAIN:-auth.localhost}
user_id=$(docker run --rm --network synthwerk_app -v synthwerk_zitadel-admin:/b:ro --user 0 --entrypoint sh \
  curlimages/curl:8.17.0 -c "curl -s -H 'Host: $auth_domain' -H \"Authorization: Bearer \$(cat /b/admin.pat)\" \
  -H 'Content-Type: application/json' -X POST http://zitadel:8080/management/v1/users/human/_import \
  -d '{\"userName\":\"hook.stack.$$\",\"profile\":{\"firstName\":\"Hook\",\"lastName\":\"Stack\"},\"email\":{\"email\":\"hook.stack.$$@example.test\",\"isEmailVerified\":true}}'" \
  | grep -o '"userId":"[0-9]*"' | cut -d'"' -f4 || true)
rows=0
for _ in $(seq 1 30); do
  [[ -z "$user_id" ]] && break
  rows=$(docker compose exec -T database psql -U "${SYNTHWERK_POSTGRES_USER:-synthwerk}" -d "${SYNTHWERK_POSTGRES_DB:-synthwerk}" -tAc \
    "SELECT count(*) FROM identity.synthwerk_outbox WHERE nats_subject = 'evt.identity.user.created.v1' AND event->>'subject' = '$user_id'" 2>/dev/null || echo 0)
  ((rows >= 1)) && break
  sleep 3
done
if ((rows == 1)); then pass "new user $user_id is one user.created row in the identity outbox"; else fail "user.created for '${user_id:-no user}': got ${rows:-0} rows, want 1"; fi
# The deny list opens identity's address only: a target on the gateway (the host) is refused.
out=$(docker run --rm --network synthwerk_app -v synthwerk_zitadel-admin:/b:ro --user 0 --entrypoint sh \
  curlimages/curl:8.17.0 -c "curl -s -H 'Host: $auth_domain' -H \"Authorization: Bearer \$(cat /b/admin.pat)\" \
  -H 'Content-Type: application/json' -X POST http://zitadel:8080/v2/actions/targets \
  -d '{\"name\":\"gateway-probe-$$\",\"restWebhook\":{},\"endpoint\":\"http://172.31.250.1:8080/x\",\"timeout\":\"5s\"}'" || true)
if [[ "$out" == *"DeniedURL"* ]]; then pass "Action target on the zitadel-hooks gateway is denied"; else fail "gateway target not denied: ${out:0:120}"; fi
expect_status "hook path through the edge gets 404" 404 -X POST --data '{}' "$EDGE/identity/internal/zitadel/actions"
out=$(docker compose exec -T zitadel-login sh -c 'wget -q -S -O /dev/null --post-data "{}" http://identity:8081/internal/zitadel/actions 2>&1 | head -n 1' || true)
if [[ "$out" == *"401"* ]]; then pass "unsigned hook call gets 401"; else fail "unsigned hook call: '$out'"; fi

echo "# Zitadel mail goes to Mailpit (synthwerk#28, D-49)"
# An invite code for a new user without a password: the invite mail must reach Mailpit.
mail_to="invite.stack.$$@example.test"
mail_user=$(docker run --rm --network synthwerk_app -v synthwerk_zitadel-admin:/b:ro --user 0 --entrypoint sh \
  curlimages/curl:8.17.0 -c "curl -s -H 'Host: $auth_domain' -H \"Authorization: Bearer \$(cat /b/admin.pat)\" \
  -H 'Content-Type: application/json' -X POST http://zitadel:8080/v2/users/human \
  -d '{\"username\":\"invite.stack.$$\",\"profile\":{\"givenName\":\"Invite\",\"familyName\":\"Stack\"},\"email\":{\"email\":\"$mail_to\",\"isVerified\":true}}'" \
  | grep -o '"userId":"[0-9][0-9]*"' | cut -d'"' -f4 || true)
[[ -n "$mail_user" ]] || fail "invite test: could not create a user"
[[ -n "$mail_user" ]] && docker run --rm --network synthwerk_app -v synthwerk_zitadel-admin:/b:ro --user 0 --entrypoint sh \
  curlimages/curl:8.17.0 -c "curl -s -o /dev/null -H 'Host: $auth_domain' -H \"Authorization: Bearer \$(cat /b/admin.pat)\" \
  -H 'Content-Type: application/json' -X POST http://zitadel:8080/v2/users/$mail_user/invite_code -d '{\"sendCode\":{}}'" || true
mails=0
for _ in $(seq 1 20); do
  [[ -z "$mail_user" ]] && break
  mails=$(curl -s --max-time 5 "http://127.0.0.1:${SYNTHWERK_MAILPIT_UI_PORT:-8025}/api/v1/search?query=to%3A$mail_to" | grep -o '"messages_count":[0-9]*' | cut -d: -f2 || echo 0)
  ((${mails:-0} >= 1)) && break
  sleep 3
done
if ((${mails:-0} >= 1)); then pass "invite mail for a new user is in Mailpit"; else fail "no invite mail in Mailpit for '${mail_user:-no user}'"; fi
expect_status "Mailpit is not on the edge" 404 "$EDGE/api/v1/messages"

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

echo "# llm: signed-in chat streams, signed-out gets 401 before any model call (synthwerk#32)"
if tests/stack/issuer.sh active; then
  # sql <query>: one value from the database as the superuser (RLS does not apply).
  sql() {
    docker compose exec -T database psql -U "${SYNTHWERK_POSTGRES_USER:-synthwerk}" -d "${SYNTHWERK_POSTGRES_DB:-synthwerk}" -tAc "$1" 2>/dev/null || echo error
  }
  tok_a=$(tests/stack/issuer.sh mint stack-user-a org-1)
  tok_b=$(tests/stack/issuer.sh mint stack-user-b org-1)
  ready=$(curl -s --max-time 10 "$EDGE/llm/readyz" || true)
  if [[ "$ready" == *'"name":"jwks","status":"ok"'* ]]; then pass "llm reads the issuer key set"; else fail "llm jwks not ok: ${ready:0:200}"; fi
  expect_status "create without a token gets 401" 401 -X POST -H 'Content-Type: application/json' --data '{}' "$EDGE/llm/v1/conversations"
  conv=$(curl -s --max-time 10 -X POST -H "Authorization: Bearer $tok_a" -H 'Content-Type: application/json' --data '{}' \
    "$EDGE/llm/v1/conversations" | grep -o '"id":"[0-9a-f-]*"' | cut -d'"' -f4 || true)
  if [[ -n "$conv" ]]; then pass "signed-in user creates conversation $conv"; else fail "no conversation id"; fi

  before=$(sql 'SELECT count(*) FROM llm.message')
  expect_status "send without a token gets 401" 401 -X POST -H 'Content-Type: application/json' \
    --data '{"content":"no token"}' "$EDGE/llm/v1/conversations/$conv/messages"
  expect_status "send with a forged token gets 401" 401 -X POST -H "Authorization: Bearer ${tok_a%.*}.AAAA" \
    -H 'Content-Type: application/json' --data '{"content":"forged"}' "$EDGE/llm/v1/conversations/$conv/messages"
  after=$(sql 'SELECT count(*) FROM llm.message')
  if [[ "$before" == "$after" && "$after" != error ]]; then pass "refused sends store nothing and reach no model ($after messages)"; else fail "messages $before -> $after after refused sends"; fi
  expect_status "another user gets 404 on the conversation" 404 -H "Authorization: Bearer $tok_b" "$EDGE/llm/v1/conversations/$conv"

  # The fake provider answers "echo: one two three four" one word per 300 ms.
  # Each line gets its arrival time: the deltas must arrive spread out, not in one block.
  chat_log=$(mktemp)
  curl -sN --max-time 30 -X POST -H "Authorization: Bearer $tok_a" -H 'Content-Type: application/json' \
    --data '{"content":"one two three four"}' "$EDGE/llm/v1/conversations/$conv/messages" \
    | perl -MTime::HiRes=time -ne '$|=1; printf "%.3f %s", time, $_' >"$chat_log" || true
  deltas=$(grep -c ' event: delta$' "$chat_log" || true)
  if ((deltas == 5)) && grep -q ' event: done$' "$chat_log"; then pass "answer streams as 5 deltas, then done"; else fail "stream: $deltas deltas, done=$(grep -c ' event: done$' "$chat_log" || true)"; fi
  spread=$(grep ' event: delta$' "$chat_log" | awk 'NR==1{f=$1} {l=$1} END{printf "%d", (l-f)*1000}')
  if ((${spread:-0} >= 900)); then pass "deltas arrive over ${spread} ms through edge and WAF (no buffering)"; else fail "deltas arrive within ${spread:-0} ms: the stream is buffered"; fi
  rm -f "$chat_log"

  expect_status "SQL and HTML in a prompt pass the WAF" 200 -X POST -H "Authorization: Bearer $tok_a" -H 'Content-Type: application/json' \
    --data "{\"content\":\"Why is ' OR 1=1 -- bad, and what does <script>alert(1)</script> do?\"}" "$EDGE/llm/v1/conversations/$conv/messages"
  expect_status "SQL in the query still gets 403" 403 -X POST -H "Authorization: Bearer $tok_a" -H 'Content-Type: application/json' \
    --data '{"content":"hi"}' "$EDGE/llm/v1/conversations/$conv/messages?id=1%27%20OR%20%271%27=%271"

  published=0
  for _ in $(seq 1 20); do
    published=$(sql "SELECT count(*) FROM llm.synthwerk_outbox WHERE nats_subject = 'evt.llm.message.completed.v1' AND published_at IS NOT NULL")
    [[ "$published" =~ ^[0-9]+$ ]] && ((published >= 2)) && break
    sleep 1
  done
  if [[ "$published" =~ ^[0-9]+$ ]] && ((published >= 2)); then pass "message.completed facts reach the bus ($published)"; else fail "published facts: $published"; fi
  leak=$(sql "SELECT count(*) FROM llm.synthwerk_outbox WHERE event::text LIKE '%one two three%' OR event::text LIKE '%script%'")
  if [[ "$leak" == "0" ]]; then pass "facts hold no prompt or answer text"; else fail "facts with text: $leak"; fi
  out=$(docker compose exec -T bus wget -q -O - 'http://127.0.0.1:8222/jsz?streams=true' 2>/dev/null || true)
  # The monitor prints indented JSON: "name": "EVT_LLM".
  if grep -qE '"name": ?"EVT_LLM"' <<<"$out"; then pass "llm created the stream EVT_LLM"; else fail "no stream EVT_LLM on the bus"; fi
  logs=$(docker compose logs --no-color llm 2>&1)
  if grep -qE 'one two three|alert\(1\)|no token|forged' <<<"$logs"; then fail "llm logs hold prompt or answer text"; else pass "llm logs hold no prompt or answer text"; fi
else
  echo "skip: llm does not trust the stack test issuer (run tests/stack/issuer.sh setup before compose up)"
fi

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
# wait_for <ERE pattern> <seconds>: true when the stream log holds the pattern in time.
wait_for() {
  local pattern=$1 limit=$2 start=$SECONDS
  while ((SECONDS - start < limit)); do
    grep -qE -- "$pattern" "$stream_log" && return 0
    sleep 1
  done
  return 1
}
stream_log=$(mktemp)
curl -sN --max-time 180 "$EDGE/pulse/v1/health/stream" >"$stream_log" 2>/dev/null &
stream_pid=$!
if wait_for '^event: snapshot' 10; then pass "stream starts with a snapshot"; else fail "no snapshot on the pulse stream"; fi
# The snapshot data line can land after the event line: wait for each target.
# A target turns ok after 3 good checks (5 s apart), so a service that started
# just before pulse is ok only in a later change event ("from" before "status").
for svc in edge waf bus database telemetry stub zitadel zitadel-login identity llm; do
  if wait_for "\"target\":\"$svc\",(\"from\":\"[a-z]+\",)?\"status\":\"ok\"" 30; then pass "$svc ok on the stream"; else fail "$svc not ok on the stream within 30 s"; fi
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
