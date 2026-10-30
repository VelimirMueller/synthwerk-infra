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
oneshot=" database-init studio-db-secret identity-widget-key zitadel-bootstrap ollama-pull vision-admin-token objectstore-bucket "

# setting <name> <default>: a stack setting as compose reads it: the shell first, then .env.
setting() {
  local value=${!1:-}
  [[ -n "$value" ]] || value=$(grep -E "^$1=" .env 2>/dev/null | tail -n 1 | cut -d= -f2- || true)
  printf '%s' "${value:-$2}"
}

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
if [[ $(grep -c '"msg":"selftest ok"' <<<"$out") == 3 ]]; then pass "selftest: token claims carry org and role"; else fail "selftest: $(grep -o '"err":"[^"]*"' <<<"$out" || echo no output)"; fi
# Account delete binds the recent MFA to the sign-in by sid, else auth_time (synthwerk#41).
# Report only: the selftest logs whether Zitadel access tokens carry them, never the value.
echo "info: Zitadel access token claims: $(grep -o '"has_sid":[a-z]*,"has_auth_time":[a-z]*' <<<"$out" | head -n 1 || echo 'not logged')"
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
# The studio database belongs to the role studio alone (synthwerk#107).
for role in identity llm; do
  out=$(psql_as "$role" 'SELECT 1' studio)
  if [[ "$out" == *"permission denied"* ]]; then pass "$role cannot connect to the studio database"; else fail "$role can connect to the studio database: ${out:0:120}"; fi
done
owner=$(docker compose exec -T database psql -U "${SYNTHWERK_POSTGRES_USER:-synthwerk}" -d "${SYNTHWERK_POSTGRES_DB:-synthwerk}" -tAc \
  "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = 'studio'" 2>/dev/null | tr -d '\r' || true)
if [[ "$owner" == studio ]]; then pass "database studio is owned by the role studio"; else fail "owner of database studio: '${owner:-none}'"; fi

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
  # Erasure (synthwerk#41): llm reads user.deleted from identity's EVT_IDENTITY with its own durable.
  if [[ "$ready" == *'"name":"erasure"'* ]]; then
    out=""
    for _ in $(seq 1 20); do
      out=$(docker compose exec -T bus wget -q -O - 'http://127.0.0.1:8222/jsz?consumers=true' 2>/dev/null || true)
      grep -qE '"name": ?"llm-user-deleted"' <<<"$out" && break
      sleep 2
    done
    if grep -qE '"name": ?"llm-user-deleted"' <<<"$out"; then pass "llm consumer llm-user-deleted is on EVT_IDENTITY"; else fail "no consumer llm-user-deleted on the bus"; fi
  else
    echo "skip: the llm image has no erasure consumer (synthwerk#41)"
  fi
  logs=$(docker compose logs --no-color llm 2>&1)
  if grep -qE 'one two three|alert\(1\)|no token|forged' <<<"$logs"; then fail "llm logs hold prompt or answer text"; else pass "llm logs hold no prompt or answer text"; fi
else
  echo "skip: llm does not trust the stack test issuer (run tests/stack/issuer.sh setup before compose up)"
fi

echo "# org roles: owner changes a role, a member gets 403 (synthwerk#29)"
# The test makes its own org, project grant, two users and their grants: grants made
# by the bootstrap can miss the Action cache (see the user.created check above).
if tests/stack/issuer.sh active; then
  # zapi <method> <path> <org id or -> [json]: Zitadel API as the IAM owner, inside the stack.
  zapi() {
    local org_hdr=""
    [[ "$3" != "-" ]] && org_hdr="-H 'x-zitadel-orgid: $3'"
    docker run --rm --network synthwerk_app -v synthwerk_zitadel-admin:/b:ro --user 0 --entrypoint sh \
      curlimages/curl:8.17.0 -c "curl -s -X $1 -H 'Host: $auth_domain' -H \"Authorization: Bearer \$(cat /b/admin.pat)\" \
      -H 'Content-Type: application/json' $org_hdr http://zitadel:8080$2 ${4:+-d '$4'}" || true
  }
  isql() {
    docker compose exec -T database psql -U "${SYNTHWERK_POSTGRES_USER:-synthwerk}" -d "${SYNTHWERK_POSTGRES_DB:-synthwerk}" -tAc "$1" 2>/dev/null || echo error
  }
  # first_id <key>: the first "<key>": "<digits>" value on stdin, or nothing.
  first_id() { { grep -oE "\"$1\": *\"[0-9]+\"" || true; } | head -n 1 | tr -d ' ' | cut -d'"' -f4; }
  project=$(docker run --rm -v synthwerk_zitadel-admin:/b:ro --user 0 --entrypoint cat curlimages/curl:8.17.0 /b/studio-client.json | first_id project_id)
  zorg=$(zapi POST /management/v1/orgs - "{\"name\":\"Roles Stack $$\"}" | first_id id)
  pgrant=$(zapi POST "/management/v1/projects/$project/grants" - "{\"grantedOrgId\":\"$zorg\",\"roleKeys\":[\"owner\",\"admin\",\"member\"]}" | first_id grantId)
  # identity-sync may write the grants of an org only with PROJECT_GRANT_OWNER on its
  # project grant (ADR-0003): whoever makes a project grant adds it.
  platform=$(zapi GET /management/v1/orgs/me - | first_id id)
  sync_id=$(zapi POST /management/v1/users/_search "$platform" \
    '{"queries":[{"userNameQuery":{"userName":"identity-sync","method":"TEXT_QUERY_METHOD_EQUALS"}}]}' | first_id id)
  zapi POST "/management/v1/projects/$project/grants/$pgrant/members" - "{\"userId\":\"$sync_id\",\"roles\":[\"PROJECT_GRANT_OWNER\"]}" >/dev/null
  # ... and ORG_USER_MANAGER in the org (ADR-0005): invites and the removal of deleted users.
  zapi POST /management/v1/orgs/me/members "$zorg" "{\"userId\":\"$sync_id\",\"roles\":[\"ORG_USER_MANAGER\"]}" >/dev/null
  iam=$(zapi POST /admin/v1/members/_search - '{}')
  if [[ -n "$sync_id" && "$iam" != *"$sync_id"* ]]; then pass "identity-sync has no instance role"; else fail "identity-sync '${sync_id:-missing}' is an instance member"; fi
  # After two bootstrap runs identity-sync has one live PAT: the one whose id is in the file.
  pats=$(zapi POST "/management/v1/users/$sync_id/pats/_search" "$platform" '{}' | { grep -oE '"id": *"[0-9]+"' || true; } | tr -d ' ' | cut -d'"' -f4)
  pat_id=$(docker run --rm -v synthwerk_zitadel-hooks:/h:ro --entrypoint cat curlimages/curl:8.17.0 /h/identity.pat.id 2>/dev/null)
  if [[ -n "$pat_id" && "$pats" == "$pat_id" ]]; then pass "identity-sync has one live PAT, the one in the file"; else fail "identity-sync PATs '$pats', file id '$pat_id'"; fi
  # mkuser <name> <role>: a user in the test org with one grant; prints the user id.
  mkuser() {
    local id
    id=$(zapi POST /management/v1/users/human/_import "$zorg" \
      "{\"userName\":\"$1.$$\",\"profile\":{\"firstName\":\"Roles\",\"lastName\":\"Stack\"},\"email\":{\"email\":\"$1.$$@example.test\",\"isEmailVerified\":true}}" | first_id userId)
    [[ -n "$id" ]] && zapi POST "/management/v1/users/$id/grants" "$zorg" \
      "{\"projectId\":\"$project\",\"projectGrantId\":\"$pgrant\",\"roleKeys\":[\"$2\"]}" >/dev/null
    echo "$id"
  }
  owner_id=$(mkuser roles.owner owner)
  member_id=$(mkuser roles.member member)
  org_id=""
  for _ in $(seq 1 30); do
    [[ -z "$owner_id" || -z "$member_id" ]] && break
    org_id=$(isql "SELECT o.id FROM identity.orgs o WHERE o.zitadel_org_id = '$zorg' AND o.status = 'active'
      AND (SELECT count(*) FROM identity.memberships m WHERE m.org_id = o.id) = 2")
    [[ "$org_id" =~ ^[0-9a-f-]{36}$ ]] && break
    org_id=""
    sleep 3
  done
  if [[ -n "$org_id" ]]; then pass "grants of a new org reach identity: org $org_id active with 2 members"; else fail "org '$zorg' (project '$project', grant '$pgrant', users '$owner_id' '$member_id') not mirrored as active with 2 members"; fi
  slug=$(isql "SELECT slug FROM identity.orgs WHERE id = '$org_id'")
  # identity reads the org name from the grant since synthwerk-identity#12; older images fall back to org-<id>.
  if [[ "$slug" == "roles-stack-$$" || "$slug" == org-* ]]; then pass "org has a slug: $slug"; else fail "slug '$slug', want roles-stack-$$ or org-<id>"; fi
  rows=$(isql "SELECT count(*) FROM identity.synthwerk_outbox WHERE event->>'type' = 'dev.synthwerk.identity.org.created.v1' AND event->>'subject' = '$org_id'")
  if [[ "$rows" == 1 ]]; then pass "one org.created for the new org"; else fail "org.created rows: $rows, want 1"; fi
  tok_owner=$(tests/stack/issuer.sh mint "$owner_id" "$zorg" owner)
  tok_member=$(tests/stack/issuer.sh mint "$member_id" "$zorg" member)
  members="$EDGE/identity/v1/orgs/$org_id/members"
  expect_status "member changes a role: 403" 403 -X PATCH -H "Authorization: Bearer $tok_member" \
    -H 'Content-Type: application/json' --data '{"role":"admin"}' "$members/$owner_id"
  expect_status "member lists members: 403" 403 -H "Authorization: Bearer $tok_member" "$members"
  expect_status "owner promotes the member to admin: 200" 200 -X PATCH -H "Authorization: Bearer $tok_owner" \
    -H 'Content-Type: application/json' --data '{"role":"admin"}' "$members/$member_id"
  expect_status "owner lists members: 200" 200 -H "Authorization: Bearer $tok_owner" "$members"
  expect_status "token of another org: 404" 404 -H "Authorization: Bearer $(tests/stack/issuer.sh mint "$owner_id" 1 owner)" "$members"
  rows=$(isql "SELECT count(*) FROM identity.synthwerk_outbox WHERE event->>'type' = 'dev.synthwerk.identity.member.role_changed.v1'
    AND event->>'subject' = '$member_id' AND event->>'actor' = 'user:$owner_id'")
  if [[ "$rows" == 1 ]]; then pass "one member.role_changed by the owner in the outbox"; else fail "member.role_changed rows: $rows, want 1"; fi
  keys=$(zapi POST /management/v1/users/grants/_search "$zorg" "{\"queries\":[{\"userIdQuery\":{\"userId\":\"$member_id\"}}]}")
  if [[ "$keys" == *'"roleKeys":["admin"]'* ]]; then pass "Zitadel user grant now holds admin"; else fail "Zitadel grant: ${keys:0:200}"; fi
  published=0
  for _ in $(seq 1 10); do
    published=$(isql "SELECT count(*) FROM identity.synthwerk_outbox WHERE event->>'subject' = '$member_id' AND published_at IS NOT NULL
      AND event->>'type' = 'dev.synthwerk.identity.member.role_changed.v1'")
    [[ "$published" == 1 ]] && break
    sleep 2
  done
  if [[ "$published" == 1 ]]; then pass "member.role_changed published to EVT_IDENTITY"; else fail "member.role_changed not published"; fi
  # Zitadel calls the hook for the grant change identity made: the mirror has it, no second event.
  sleep 5
  rows=$(isql "SELECT count(*) FROM identity.synthwerk_outbox WHERE event->>'type' = 'dev.synthwerk.identity.member.role_changed.v1' AND event->>'subject' = '$member_id'")
  role=$(isql "SELECT role FROM identity.memberships WHERE user_sub = '$member_id'")
  if [[ "$rows" == 1 && "$role" == admin ]]; then pass "hook echo of the change writes nothing new"; else fail "after the echo: $rows events, role '$role'"; fi
  # zsync <method> <path> <org id> [json]: HTTP status of a Zitadel call as identity-sync (its PAT).
  zsync() {
    docker run --rm --network synthwerk_app -v synthwerk_zitadel-hooks:/h:ro --user 0 --entrypoint sh \
      curlimages/curl:8.17.0 -c "curl -s -o /dev/null -w '%{http_code}' -X $1 -H 'Host: $auth_domain' \
      -H \"Authorization: Bearer \$(cat /h/identity.pat)\" -H 'Content-Type: application/json' \
      -H 'x-zitadel-orgid: $3' http://zitadel:8080$2 ${4:+-d '$4'}" || true
  }
  # A refused write must leave the grant as it was; Zitadel answers "not changed" with 400, so
  # each try asks for a real change and the check reads the grant back.
  grant_keys() { zapi POST /management/v1/users/grants/_search "$1" "{\"queries\":[{\"userIdQuery\":{\"userId\":\"$2\"}}]}" | grep -oE '"roleKeys": *\[[^]]*\]' | head -n 1 | tr -d ' '; }
  mgrant=$(zapi POST /management/v1/users/grants/_search "$zorg" "{\"queries\":[{\"userIdQuery\":{\"userId\":\"$member_id\"}}]}" | first_id id)
  code=$(zsync PUT "/management/v1/users/$member_id/grants/$mgrant" "$zorg" '{"roleKeys":["admin","operator"]}')
  keys=$(grant_keys "$zorg" "$member_id")
  if [[ -n "$mgrant" && "$code" != 200 && "$keys" == '"roleKeys":["admin"]' ]]; then pass "identity-sync cannot give operator in an org: $code"; else fail "operator write: status $code, grant $keys"; fi
  op_id=$(zapi POST /management/v1/users/_search "$platform" \
    '{"queries":[{"userNameQuery":{"userName":"operator.test","method":"TEXT_QUERY_METHOD_EQUALS"}}]}' | first_id id)
  opgrant=$(zapi POST /management/v1/users/grants/_search "$platform" "{\"queries\":[{\"userIdQuery\":{\"userId\":\"$op_id\"}}]}" | first_id id)
  code=$(zsync PUT "/management/v1/users/$op_id/grants/$opgrant" "$platform" '{"roleKeys":["operator","member"]}')
  keys=$(grant_keys "$platform" "$op_id")
  if [[ -n "$opgrant" && "$code" == 403 && "$keys" == '"roleKeys":["operator"]' ]]; then pass "identity-sync cannot write platform-org grants: 403"; else fail "platform grant write: status $code, grant $keys"; fi
  # identity-sync removes the Zitadel user of a deleted account (synthwerk#41, ADR-0005):
  # it may delete users in a customer org, never in the platform org.
  demo=$(zapi POST /admin/v1/orgs/_search - '{"queries":[{"nameQuery":{"name":"demo","method":"TEXT_QUERY_METHOD_EQUALS"}}]}' | first_id id)
  demo_members=$(zapi POST /management/v1/orgs/me/members/_search "$demo" "{\"queries\":[{\"userIdQuery\":{\"userId\":\"$sync_id\"}}]}")
  if [[ "$demo_members" == *ORG_USER_MANAGER* ]]; then pass "bootstrap gives identity-sync ORG_USER_MANAGER in the demo org"; else fail "identity-sync in the demo org: ${demo_members:0:160}"; fi
  platform_members=$(zapi POST /management/v1/orgs/me/members/_search "$platform" "{\"queries\":[{\"userIdQuery\":{\"userId\":\"$sync_id\"}}]}")
  if [[ "$platform_members" != *"$sync_id"* ]]; then pass "identity-sync has no role in the platform org"; else fail "identity-sync is a member of the platform org"; fi
  # throwaway <org id> <name>: a user without grants; prints the user id.
  throwaway() {
    zapi POST /management/v1/users/human/_import "$1" \
      "{\"userName\":\"$2.$$\",\"profile\":{\"firstName\":\"Gone\",\"lastName\":\"Stack\"},\"email\":{\"email\":\"$2.$$@example.test\",\"isEmailVerified\":true}}" | first_id userId
  }
  gone=$(throwaway "$demo" delete.demo)
  code=$(zsync DELETE "/v2/users/$gone" "$demo")
  if [[ -n "$gone" && "$code" == 200 ]]; then pass "identity-sync deletes a user of a customer org: 200"; else fail "delete in the demo org: user '$gone', status $code"; fi
  kept=$(throwaway "$platform" delete.platform)
  code=$(zsync DELETE "/v2/users/$kept" "$platform")
  if [[ -n "$kept" && "$code" == 403 ]]; then pass "identity-sync cannot delete a platform-org user: 403"; else fail "delete in the platform org: user '$kept', status $code"; fi
  [[ -n "$kept" ]] && zapi DELETE "/v2/users/$kept" - >/dev/null

  echo "# invites and grant status from Zitadel (synthwerk#37)"
  # identity reads the project id from the file zitadel-bootstrap writes after identity starts.
  pid=$(docker run --rm -v synthwerk_zitadel-hooks:/h:ro --entrypoint cat curlimages/curl:8.17.0 /h/project-id 2>/dev/null || true)
  if [[ -n "$project" && "$pid" == "$project" ]]; then pass "bootstrap writes the project id for identity"; else fail "project id file '$pid', project '$project'"; fi
  invite_to="invited.stack.$$@example.test"
  expect_status "owner invites a new email: 202" 202 -X POST -H "Authorization: Bearer $tok_owner" \
    -H 'Content-Type: application/json' --data "{\"email\":\"$invite_to\",\"role\":\"member\"}" "$members"
  mails=0
  for _ in $(seq 1 20); do
    mails=$(curl -s --max-time 5 "http://127.0.0.1:${SYNTHWERK_MAILPIT_UI_PORT:-8025}/api/v1/search?query=to%3A$invite_to" | grep -o '"messages_count":[0-9]*' | cut -d: -f2 || echo 0)
    ((${mails:-0} >= 1)) && break
    sleep 3
  done
  if ((${mails:-0} >= 1)); then pass "invite mail from identity is in Mailpit"; else fail "no invite mail in Mailpit for $invite_to"; fi
  rows=$(isql "SELECT count(*) FROM identity.invitations i JOIN identity.memberships m ON m.org_id = i.org_id AND m.user_sub = i.user_sub
    WHERE i.org_id = '$org_id' AND i.email = '$invite_to' AND m.status = 'invited' AND i.accepted_at IS NULL")
  if [[ "$rows" == 1 ]]; then pass "invitation pending, invitee row invited"; else fail "invitation rows: $rows, want 1"; fi
  # wait_status <status>: poll the member row of member_id until it has <status>; prints the last status.
  wait_status() {
    local st=""
    for _ in $(seq 1 30); do
      st=$(isql "SELECT status FROM identity.memberships WHERE org_id = '$org_id' AND user_sub = '$member_id'")
      [[ "$st" == "$1" ]] && break
      sleep 2
    done
    echo "$st"
  }
  audit_status() {
    isql "SELECT count(*) FROM identity.audit_events WHERE org_id = '$org_id' AND type = 'dev.synthwerk.identity.member.$1.v1'
      AND subject = '$member_id' AND actor = 'system'"
  }
  expect_status "active member reads the org: 200" 200 -H "Authorization: Bearer $tok_member" "$EDGE/identity/v1/orgs/$org_id"
  zapi POST "/management/v1/users/$member_id/grants/$mgrant/_deactivate" "$zorg" '{}' >/dev/null
  st=$(wait_status deactivated)
  if [[ "$st" == deactivated ]]; then pass "grant deactivated in Zitadel: member deactivated in identity"; else fail "member status after deactivate: '$st'"; fi
  rows=$(audit_status deactivated)
  if [[ "$rows" == 1 ]]; then pass "one member.deactivated by system in the audit list"; else fail "member.deactivated audit rows: $rows, want 1"; fi
  expect_status "deactivated member reads the org: 404" 404 -H "Authorization: Bearer $tok_member" "$EDGE/identity/v1/orgs/$org_id"
  expect_status "deactivated member lists members: 404" 404 -H "Authorization: Bearer $tok_member" "$members"
  zapi POST "/management/v1/users/$member_id/grants/$mgrant/_reactivate" "$zorg" '{}' >/dev/null
  st=$(wait_status active)
  if [[ "$st" == active ]]; then pass "grant reactivated in Zitadel: member active again"; else fail "member status after reactivate: '$st'"; fi
  rows=$(audit_status reactivated)
  if [[ "$rows" == 1 ]]; then pass "one member.reactivated by system in the audit list"; else fail "member.reactivated audit rows: $rows, want 1"; fi
  expect_status "reactivated member reads the org: 200" 200 -H "Authorization: Bearer $tok_member" "$EDGE/identity/v1/orgs/$org_id"

  echo "# apps and widget routes on the edge (synthwerk#30, #38)"
  apps="$EDGE/identity/v1/orgs/$org_id/apps"
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H "Authorization: Bearer $tok_owner" "$apps" || true)
  if [[ "$code" == 404 ]]; then
    echo "skip: the identity image has no app routes (synthwerk#30)"
  else
    shop=https://shop.stack.test
    app_id=$(curl -s --max-time 10 -X POST -H "Authorization: Bearer $tok_owner" -H 'Content-Type: application/json' \
      --data "{\"name\":\"Stack shop $$\",\"allowed_origins\":[\"$shop\"]}" "$apps" | grep -oE '"id": ?"[0-9a-f-]{36}"' | head -n 1 | grep -oE '[0-9a-f-]{36}' || true)
    if [[ -n "$app_id" ]]; then pass "owner creates app $app_id with origin $shop"; else fail "no app id from POST $apps"; fi
    # allow_origin <curl args...>: the Access-Control-Allow-Origin of the answer, or empty.
    allow_origin() { curl -s -o /dev/null -D - --max-time 10 "$@" | tr -d '\r' | awk -F': ' 'tolower($1) == "access-control-allow-origin" { print $2 }'; }
    settings="$EDGE/identity/v1/apps/$app_id/widget-settings"
    # The shop origin is not in SYNTHWERK_CORS_ORIGINS: identity answers CORS per app, not edge-cors.
    expect_status "widget settings from the listed origin, no token: 200" 200 -H "Origin: $shop" "$settings"
    if [[ "$(allow_origin -H "Origin: $shop" "$settings")" == "$shop" ]]; then pass "widget settings allow the app origin"; else fail "widget settings: no allow-origin for $shop"; fi
    if [[ "$(allow_origin -X OPTIONS -H "Origin: $shop" -H 'Access-Control-Request-Method: GET' "$settings")" == "$shop" ]]; then pass "widget settings preflight reaches identity"; else fail "widget settings preflight: no allow-origin for $shop"; fi
    expect_status "widget settings from a foreign origin: 403" 403 -H 'Origin: https://evil.stack.test' "$settings"
    if [[ -z "$(allow_origin -H 'Origin: https://evil.stack.test' "$settings")" ]]; then pass "foreign origin gets no allow-origin"; else fail "foreign origin gets an allow-origin"; fi
    if [[ "$(allow_origin -X OPTIONS -H "Origin: $shop" -H 'Access-Control-Request-Method: POST' \
      -H 'Access-Control-Request-Headers: authorization,content-type' "$EDGE/identity/v1/apps/$app_id/widget-tokens")" == "$shop" ]]; then
      pass "widget token preflight reaches identity"
    else
      fail "widget token preflight: no allow-origin for $shop"
    fi
    # synthwerk-widgets#41: a foreign origin passes the token preflight, and the trade refuses
    # it with a 403 origin_not_allowed the page can read (no token, no credentials).
    trade="$EDGE/identity/v1/apps/$app_id/widget-tokens"
    if [[ "$(allow_origin -X OPTIONS -H 'Origin: https://evil.stack.test' -H 'Access-Control-Request-Method: POST' \
      -H 'Access-Control-Request-Headers: authorization' "$trade")" == "https://evil.stack.test" ]]; then
      pass "widget token preflight passes a foreign origin"
    else
      fail "widget token preflight: no allow-origin for https://evil.stack.test"
    fi
    expect_status "widget token trade from a foreign origin: 403" 403 -X POST -H "Authorization: Bearer $tok_owner" \
      -H 'Origin: https://evil.stack.test' "$trade"
    if [[ "$(allow_origin -X POST -H "Authorization: Bearer $tok_owner" -H 'Origin: https://evil.stack.test' "$trade")" == "https://evil.stack.test" ]]; then
      pass "widget token refusal is readable to the foreign origin"
    else
      fail "widget token refusal: no allow-origin for https://evil.stack.test"
    fi
    wtok=$(curl -s --max-time 10 -X POST -H "Authorization: Bearer $tok_owner" -H "Origin: $shop" -H 'Content-Type: application/json' \
      --data '{}' "$EDGE/identity/v1/apps/$app_id/widget-tokens" | grep -oE '"(token|access_token)": ?"[^"]+"' | head -n 1 | sed -E 's/.*"([^"]+)"$/\1/' || true)
    # Claims only (no signature check here): iss is the widget issuer, origin is bound.
    # base64url without padding: restore "=" so GNU and BSD base64 decode the whole body.
    wpart=$(cut -d. -f2 <<<"$wtok" | tr '_-' '/+')
    while (( ${#wpart} % 4 )); do wpart+="="; done
    wbody=$(printf '%s' "$wpart" | { base64 -d 2>/dev/null || true; })
    # The issuer compose gives identity: .env, else the default from the edge port.
    wiss=$(grep -E '^SYNTHWERK_IDENTITY_WIDGET_ISSUER=' .env 2>/dev/null | tail -n 1 | cut -d= -f2- || true)
    wiss="${wiss:-http://localhost:${SYNTHWERK_EDGE_HTTP_PORT:-8080}/identity}"
    if [[ "$wbody" == *"\"iss\":\"$wiss\""* && "$wbody" == *"\"synthwerk:origin\":\"$shop\""* ]]; then pass "widget token: iss $wiss, bound to $shop"; else fail "widget token claims: ${wbody:0:200}"; fi
    jwks=$(curl -s --max-time 10 "$EDGE/identity/.well-known/jwks.json" || true)
    if [[ "$jwks" == *'"kty":"EC"'* && "$jwks" == *'"crv":"P-256"'* ]]; then pass "widget key set on the edge: one P-256 key"; else fail "widget key set: ${jwks:0:120}"; fi

    echo "# llm chat with the widget token (synthwerk#30, #34)"
    # llm trusts identity's widget issuer next to the user issuer (SYNTHWERK_LLM_WIDGET_*).
    lready=$(curl -s --max-time 10 "$EDGE/llm/readyz" || true)
    if [[ "$lready" == *'"name":"jwks_widget","status":"ok"'* ]]; then pass "llm reads the widget key set"; else fail "llm jwks_widget not ok: ${lready:0:240}"; fi
    if [[ -z "$wtok" ]]; then
      fail "llm: no widget token to test with (see the widget routes above)"
    else
      wauth=(-H "Authorization: Bearer $wtok" -H 'Content-Type: application/json')
      wconv=$(curl -s --max-time 10 -X POST "${wauth[@]}" -H "Origin: $shop" --data '{}' \
        "$EDGE/llm/v1/conversations" | grep -o '"id":"[0-9a-f-]*"' | cut -d'"' -f4 || true)
      if [[ -n "$wconv" ]]; then pass "widget token from $shop creates conversation $wconv"; else fail "widget token: no conversation id"; fi
      expect_status "widget token from $shop reads its conversation: 200" 200 "${wauth[@]}" -H "Origin: $shop" "$EDGE/llm/v1/conversations/$wconv"
      wlog=$(mktemp)
      curl -sN --max-time 30 -X POST "${wauth[@]}" -H "Origin: $shop" --data '{"content":"one two three four"}' \
        "$EDGE/llm/v1/conversations/$wconv/messages" >"$wlog" || true
      wdeltas=$(grep -c '^event: delta' "$wlog" || true)
      if ((wdeltas >= 1)) && grep -q '^event: done' "$wlog"; then pass "widget token from $shop: answer streams ($wdeltas deltas, then done)"; else fail "widget stream: $wdeltas deltas, $(head -c 200 "$wlog")"; fi
      rm -f "$wlog"
      wbefore=$(isql "SELECT count(*) FROM llm.message")
      expect_status "widget token from another origin: create 403" 403 -X POST "${wauth[@]}" -H 'Origin: https://evil.stack.test' \
        --data '{}' "$EDGE/llm/v1/conversations"
      expect_status "widget token from another origin: send 403" 403 -X POST "${wauth[@]}" -H 'Origin: https://evil.stack.test' \
        --data '{"content":"hi"}' "$EDGE/llm/v1/conversations/$wconv/messages"
      expect_status "widget token without an Origin: send 403" 403 -X POST "${wauth[@]}" \
        --data '{"content":"hi"}' "$EDGE/llm/v1/conversations/$wconv/messages"
      wafter=$(isql "SELECT count(*) FROM llm.message")
      if [[ "$wbefore" == "$wafter" ]]; then pass "refused widget sends store nothing ($wafter messages)"; else fail "messages $wbefore -> $wafter after refused widget sends"; fi
      expect_status "widget token on the export: 403" 403 "${wauth[@]}" -H "Origin: $shop" "$EDGE/llm/v1/me/export"
      expect_status "widget token on the AI settings: 403" 403 "${wauth[@]}" -H "Origin: $shop" "$EDGE/llm/v1/ai-settings"
      expect_status "widget token changes the AI settings: 403" 403 -X PUT "${wauth[@]}" -H "Origin: $shop" \
        --data '{"version":0}' "$EDGE/llm/v1/ai-settings"

      echo "# llm answers CORS on the widget chat routes per app origin (infra#21 follow-up)"
      # lpre <origin> <method> <path>: "<status> <Access-Control-Allow-Origin>" of a browser
      # preflight through the edge. The edge has no edge-cors on these routes: llm answers.
      lpre() {
        curl -s -o /dev/null -D - --max-time 10 -X OPTIONS -H "Origin: $1" -H "Access-Control-Request-Method: $2" \
          -H 'Access-Control-Request-Headers: authorization,content-type' "$EDGE/llm$3" |
          tr -d '\r' | awk -F': ' 'NR == 1 { split($0, a, " "); st = a[2] } tolower($1) == "access-control-allow-origin" { o = $2 } END { print st " " o }'
      }
      for route in "POST /v1/conversations" "GET /v1/conversations/$wconv" "POST /v1/conversations/$wconv/messages"; do
        got=$(lpre "$shop" ${route% *} "${route#* }")
        if [[ "$got" == "204 $shop" ]]; then pass "preflight from the app origin $shop, $route: 204 with allow-origin"; else fail "preflight from $shop, $route: '$got'"; fi
      done
      got=$(lpre https://evil.stack.test POST /v1/conversations)
      if [[ "$got" == "403 " ]]; then pass "preflight from an origin without an app: 403, no allow-origin"; else fail "preflight from https://evil.stack.test: '$got'"; fi
      got=$(lpre "$shop" DELETE "/v1/conversations/$wconv")
      if [[ "$got" == "403 " ]]; then pass "preflight for a method the route does not take: 403"; else fail "preflight DELETE from $shop: '$got'"; fi
      first="${SYNTHWERK_CORS_ORIGINS:-http://localhost:3000,http://localhost:5173}"
      first="${first%%,*}"
      got=$(lpre "$first" POST /v1/conversations)
      if [[ "$got" == "204 $first" ]]; then pass "preflight from the first-party origin $first: 204"; else fail "preflight from $first: '$got'"; fi
      # Only llm answers here: a second allow-origin from the edge would make the browser refuse it.
      n=$(curl -s -o /dev/null -D - --max-time 10 -X OPTIONS -H "Origin: $first" -H 'Access-Control-Request-Method: POST' \
        "$EDGE/llm/v1/conversations" | grep -ic '^access-control-allow-origin:' || true)
      if [[ "$n" == 1 ]]; then pass "one allow-origin header on the widget route preflight"; else fail "allow-origin headers on the widget route preflight: $n"; fi
      got=$(lpre "$shop" GET /v1/ai-settings)
      if [[ "$got" != *" $shop" ]]; then pass "other llm routes keep edge-cors: no allow-origin for $shop"; else fail "AI settings preflight from $shop: '$got'"; fi
      acao=$(curl -s -o /dev/null -D - --max-time 10 "${wauth[@]}" -H "Origin: $shop" "$EDGE/llm/v1/conversations/$wconv" |
        tr -d '\r' | awk -F': ' 'tolower($1) == "access-control-allow-origin" { print $2 }')
      if [[ "$acao" == "$shop" ]]; then pass "widget read from $shop answers with allow-origin $shop"; else fail "widget read allow-origin: '$acao'"; fi
      expect_status "identity internal routes are not on the edge: 404" 404 "$EDGE/identity/internal/v1/widget-origins?origin=https%3A%2F%2Fshop.stack.test"
    fi
  fi

  echo "# vision behind the edge (profile vision; synthwerk#36, #44, #76, #77)"
  if [[ -z "$(docker compose ps -q vision 2>/dev/null)" ]]; then
    echo "skip: vision is not running (docker compose --profile vision up --build --wait)"
  elif [[ -z "${wtok:-}" || -z "${shop:-}" ]]; then
    fail "vision: no widget token to test with (see the widget routes above)"
  else
    VISION="$EDGE/vision"
    # A 64 x 64 PNG gradient, made with the Python standard library only.
    img=$(mktemp)
    python3 -c 'import struct, sys, zlib
w = h = 64
raw = b"".join(b"\x00" + bytes(v for x in range(w) for v in (x * 4, y * 4, 128)) for y in range(h))
chunk = lambda t, d: struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))
sys.stdout.buffer.write(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))' >"$img"
    form=(-F "image=@$img;type=image/png")
    vready=$(curl -s --max-time 10 "$VISION/readyz" || true)
    if [[ "$vready" == *'"name":"model","status":"ok"'* ]]; then pass "vision /readyz on the edge: model loaded"; else fail "vision /readyz: ${vready:0:200}"; fi
    expect_status "classification without a token: 401" 401 -H "Origin: $shop" "${form[@]}" "$VISION/v1/classifications"
    expect_status "classification with a forged widget token: 401" 401 -H "Authorization: Bearer ${wtok%.*}.AAAA" \
      -H "Origin: $shop" "${form[@]}" "$VISION/v1/classifications"
    # A user token of the test issuer (RS256, no origin claim) is not a widget token.
    expect_status "classification with a user token: 401" 401 -H "Authorization: Bearer $tok_owner" \
      -H "Origin: $shop" "${form[@]}" "$VISION/v1/classifications"
    expect_status "widget token from another origin: 403" 403 -H "Authorization: Bearer $wtok" \
      -H 'Origin: https://evil.stack.test' "${form[@]}" "$VISION/v1/classifications"
    out=$(curl -s --max-time 30 -w '\n%{http_code}' -H "Authorization: Bearer $wtok" -H "Origin: $shop" \
      "${form[@]}" "$VISION/v1/classifications" || true)
    if [[ "${out##*$'\n'}" == 200 && "$out" == *'"primary":'* ]]; then
      pass "widget token from $shop: classification 200 through edge and WAF ($(grep -oE '"model":\{"name":"[^"]*"' <<<"$out" | cut -d'"' -f6))"
    else
      fail "classification with the widget token: ${out:0:200}"
    fi

    echo "# vision answers CORS per app origin; the edge keeps WAF and body limit (infra#24)"
    # vpre <origin> <path>: "<status> <Access-Control-Allow-Origin>" of a browser preflight.
    vpre() {
      curl -s -o /dev/null -D - --max-time 10 -X OPTIONS -H "Origin: $1" -H 'Access-Control-Request-Method: POST' \
        -H 'Access-Control-Request-Headers: authorization,content-type' "$VISION$2" |
        tr -d '\r' | awk -F': ' 'NR == 1 { split($0, a, " "); st = a[2] } tolower($1) == "access-control-allow-origin" { o = $2 } END { print st " " o }'
    }
    for path in /v1/classifications /v1/images; do
      got=$(vpre "$shop" "$path")
      if [[ "$got" == "204 $shop" ]]; then pass "vision preflight from the app origin $shop, POST $path: 204 with allow-origin"; else fail "vision preflight from $shop, $path: '$got'"; fi
    done
    got=$(vpre https://evil.stack.test /v1/classifications)
    if [[ "$got" == "403 " ]]; then pass "vision preflight from an origin without an app: 403, no allow-origin"; else fail "vision preflight from https://evil.stack.test: '$got'"; fi
    n=$(curl -s -o /dev/null -D - --max-time 10 -X OPTIONS -H "Origin: $shop" -H 'Access-Control-Request-Method: POST' \
      "$VISION/v1/classifications" | grep -ic '^access-control-allow-origin:' || true)
    if [[ "$n" == 1 ]]; then pass "one allow-origin header on the vision preflight"; else fail "allow-origin headers on the vision preflight: $n"; fi
    acao=$(curl -s -o /dev/null -D - --max-time 30 -H "Authorization: Bearer $wtok" -H "Origin: $shop" "${form[@]}" \
      "$VISION/v1/classifications" | tr -d '\r' | awk -F': ' 'tolower($1) == "access-control-allow-origin" { print $2 }')
    if [[ "$acao" == "$shop" ]]; then pass "vision classification from $shop answers with allow-origin $shop"; else fail "vision classification allow-origin: '$acao'"; fi
    vbig=$(mktemp)
    head -c 1100000 /dev/zero >"$vbig"
    expect_status "vision upload over 1 MiB gets 413 at the edge" 413 -H "Authorization: Bearer $wtok" -H "Origin: $shop" \
      -F "image=@$vbig;type=image/png" "$VISION/v1/images"
    rm -f "$vbig"

    # Uploads land under the org of the token, in the configured backend, within its quota.
    backend=$(setting SYNTHWERK_VISION_STORAGE_BACKEND local)
    quota=$(setting SYNTHWERK_VISION_UPLOAD_QUOTA_FILES 1000)
    upload() {
      curl -s -o /dev/null -w '%{http_code}' --max-time 30 -H "Authorization: Bearer $wtok" -H "Origin: $shop" \
        "${form[@]}" "$VISION/v1/images" || true
    }
    code=$(upload)
    if [[ "$code" == 201 ]]; then pass "widget token: upload 201 ($backend backend)"; else fail "upload with the widget token: $code"; fi
    stored=1
    if [[ "$quota" =~ ^[0-9]+$ ]] && ((quota <= 5)); then
      while ((stored < quota)); do
        code=$(upload)
        [[ "$code" == 201 ]] || break
        stored=$((stored + 1))
      done
      code=$(upload)
      if ((stored == quota)) && [[ "$code" == 507 ]]; then pass "upload past the file quota of the org ($quota): 507"; else fail "file quota $quota: $stored stored, then $code (want 507)"; fi
    else
      echo "skip: file quota $quota is too large to fill (set SYNTHWERK_VISION_UPLOAD_QUOTA_FILES to 5 or less)"
    fi
    if [[ "$backend" == s3 ]]; then
      if [[ "$vready" == *'"name":"storage","status":"ok"'* ]]; then pass "vision /readyz: upload bucket reachable"; else fail "vision storage check: ${vready:0:200}"; fi
      bucket=$(setting SYNTHWERK_VISION_S3_BUCKET vision-uploads)
      # Listed from the vision container: it is on the network of the emulator.
      keys=$(docker compose exec -T vision python -c "import urllib.request as r
print(r.urlopen('http://objectstore:5000/$bucket?list-type=2&prefix=$zorg/', timeout=10).read().decode())" 2>/dev/null \
        | { grep -oE '<Key>[^<]+</Key>' || true; } | grep -c . || true)
    else
      keys=$(docker compose exec -T vision sh -c "find /data/uploads/$zorg -type f -name '*.png' | wc -l" 2>/dev/null | tr -d ' \r' || true)
    fi
    if [[ "$keys" == "$stored" ]]; then pass "$stored upload(s) stored under org $zorg ($backend)"; else fail "stored objects under org $zorg: '$keys', want $stored ($backend)"; fi

    # The label admin takes the service token, inside the stack only (synthwerk#44).
    expect_status "label admin is not on the edge: 404" 404 -H "Authorization: Bearer $wtok" "$VISION/v1/orgs/$zorg/labels"
    expect_status "runtime labels are not on the edge: 404" 404 "$VISION/v1/labels"
    # admin_status <token expression>: status of GET /v1/orgs/<org>/labels from inside vision.
    admin_status() {
      docker compose exec -T vision sh -c "python -c \"import sys, urllib.request as r, urllib.error as e
req = r.Request('http://127.0.0.1:8000/v1/orgs/$zorg/labels', headers={'Authorization': 'Bearer ' + sys.argv[1]})
try: print(r.urlopen(req, timeout=10).status)
except e.HTTPError as x: print(x.code)\" \"$1\"" 2>/dev/null | tr -d '\r' || true
    }
    code=$(admin_status '$(cat /secrets/vision.token)')
    if [[ "$code" == 200 ]]; then pass "vision label admin with the generated token: 200"; else fail "vision label admin with its token: $code"; fi
    code=$(admin_status wrong-token)
    if [[ "$code" == 401 ]]; then pass "vision label admin with a wrong token: 401"; else fail "vision label admin with a wrong token: $code"; fi
    rm -f "$img"
  fi

  echo "# own-data export (synthwerk#41)"
  export_doc=$(curl -s --max-time 15 -H "Authorization: Bearer $tok_owner" -w '\n%{http_code}' "$EDGE/identity/v1/me/export" || true)
  if [[ "${export_doc##*$'\n'}" == 404 ]]; then
    echo "skip: the identity image has no export route (synthwerk#41)"
  elif [[ "$export_doc" == *'"complete":true'* && "$export_doc" == *'"service":"llm","status":"ok"'* ]]; then
    pass "export holds the llm part and is complete"
  else
    fail "export: ${export_doc:0:240}"
  fi

  leak=$(isql "SELECT count(*) FROM identity.synthwerk_outbox WHERE event::text LIKE '%example.test%'")
  if [[ "$leak" == 0 ]]; then pass "no email in identity events"; else fail "identity events hold an email"; fi

  echo "# account delete with real Zitadel tokens and the ID token step-up (synthwerk#41)"
  # identity trusts the stack test issuer above. For this check it trusts Zitadel like on dev:
  # the issuer inside the stack (alias on zitadel, Zitadel's own port 8080), the key set from
  # discovery, and the project id as audience. The shell values win over .env. Restored below.
  if SYNTHWERK_IDENTITY_OIDC_ISSUER="http://$auth_domain:8080" SYNTHWERK_IDENTITY_OIDC_AUDIENCE="$project" \
    SYNTHWERK_IDENTITY_JWKS_URL="" docker compose up -d --wait --no-deps identity >/dev/null 2>&1; then
    # A throwaway user signs in with password and TOTP and the studio step-up (prompt=login,
    # max_age=0), then calls DELETE /v1/me without and with its fresh ID token.
    out=$(docker compose run --rm --no-deps zitadel-bootstrap delete-check 2>&1 || true)
    status_of() { grep "$1" <<<"$out" | grep -o '"status":[0-9]*' | cut -d: -f2 | head -n 1; }
    code=$(status_of 'without ID token')
    if [[ "$code" == 403 && "$out" == *'"code":"recent_mfa_required"'* ]]; then pass "delete without X-Synthwerk-Id-Token: 403 recent_mfa_required"; else fail "delete without ID token: status '${code:-none}' $(grep -o '"err":"[^"]*"' <<<"$out" || true)"; fi
    code=$(status_of 'with the fresh ID token')
    if [[ "$code" == 202 ]]; then pass "delete with a fresh step-up ID token (aud = studio client id from the mounted file): 202"; else fail "delete with the ID token: status '${code:-none}' $(grep -o '"err":"[^"]*"' <<<"$out" || true)"; fi
    gone=$(grep '"msg":"delete-check ok"' <<<"$out" | grep -oE '"user_id":"[0-9]+"' | cut -d'"' -f4 || true)
    if [[ -n "$gone" ]]; then
      # The remover runs every 30 s and deletes the Zitadel user as identity-sync.
      user=""
      for _ in $(seq 1 30); do
        user=$(zapi GET "/v2/users/$gone" -)
        [[ "$user" == *'"code":5'* || "$user" == *NotFound* || "$user" == *"not found"* ]] && break
        sleep 3
      done
      if [[ "$user" == *'"code":5'* || "$user" == *NotFound* || "$user" == *"not found"* ]]; then pass "identity removed the deleted user from Zitadel"; else fail "Zitadel user $gone still there: ${user:0:160}"; fi
    fi
  else
    fail "identity did not start with the Zitadel issuer"
  fi
  if docker compose up -d --wait --no-deps identity >/dev/null 2>&1; then pass "identity back on the stack test issuer"; else fail "identity did not come back on the stack test issuer"; fi
else
  echo "skip: identity does not trust the stack test issuer (run tests/stack/issuer.sh setup before compose up)"
fi

echo "# studio (profile studio)"
if [[ -n "$(docker compose ps -q studio 2>/dev/null)" ]]; then
  STUDIO="http://127.0.0.1:${SYNTHWERK_STUDIO_PORT:-3001}"
  expect_status "studio home page" 200 "$STUDIO/"
  expect_status "studio health without a session: 401" 401 "$STUDIO/api/health/status"
  expect_status "studio apps without a session: 401" 401 "$STUDIO/api/apps"
  # The login route redirects to Zitadel only when the server reads the issuer (alias on zitadel).
  loc=$(curl -s -o /dev/null -w '%{redirect_url}' --max-time 10 "$STUDIO/api/auth/login" || true)
  if [[ "$loc" == "${SYNTHWERK_ZITADEL_PUBLIC_URL:-$AUTH}/oauth/v2/authorize?"* ]]; then pass "studio login redirects to Zitadel"; else echo "info: studio login redirect '${loc%%\?*}' (sign-in needs the edge on port 8080, see compose.yaml)"; fi
  expect_status "studio labels without a session: 401" 401 "$STUDIO/api/labels"
  # The label BFF calls vision with NUXT_VISION_URL and the token file studio/start.mjs reads.
  # Same call from the studio container: proves the network path and the shared token.
  if [[ -n "$(docker compose ps -q vision 2>/dev/null)" ]]; then
    code=$(docker compose exec -T studio node -e "const t = require('node:fs').readFileSync(process.env.VISION_ADMIN_TOKEN_FILE, 'utf8').trim()
fetch(process.env.NUXT_VISION_URL + '/v1/orgs/stack-org/labels', { headers: { authorization: 'Bearer ' + t } })
  .then((r) => console.log(r.status), () => console.log('unreachable'))" 2>/dev/null | tr -d '\r' || true)
    if [[ "$code" == 200 ]]; then pass "studio reaches vision label admin with its token: 200"; else fail "studio to vision label admin: '$code'"; fi
  else
    echo "skip: vision is not running, so studio has no label admin to reach"
  fi

  echo "# studio page builder database (synthwerk#107)"
  # studio/start.mjs builds NUXT_BUILDER_DATABASE_URL from the password file of studio-db-secret
  # and connects with it: the role and the database must both be "studio".
  out=$(docker compose exec -T studio node /app/start.mjs builder-db-check 2>&1 | tr -d '\r' || true)
  if [[ "$out" == *'"role":"studio","db":"studio","can_create":true'* ]]; then pass "studio connects to its own database as role studio and may create tables"; else fail "studio builder database: ${out:0:200}"; fi
  # The password lives in the volume only: read it from the studio container, never print it.
  studio_pw=$(docker compose exec -T studio cat /studio-db/studio.password 2>/dev/null | tr -d '\r\n' || true)
  if [[ -n "$studio_pw" ]] && ! grep -qF -- "$studio_pw" .env compose.yaml; then pass "studio database password is in the volume, not in .env or compose.yaml"; else fail "studio database password missing or in a file of the repo"; fi
  out=$(docker compose exec -T -e PGPASSWORD="$studio_pw" database psql -h 127.0.0.1 -U studio -d "${SYNTHWERK_POSTGRES_DB:-synthwerk}" -tAc 'SELECT 1' 2>&1 || true)
  if [[ "$out" == *"permission denied"* ]]; then pass "role studio cannot connect to the synthwerk database"; else fail "role studio reaches the synthwerk database: ${out:0:120}"; fi
  unset studio_pw
  expect_status "builder without a session: 401" 401 "$STUDIO/api/builder/pages"
  # A signed-in owner: owner.demo signs in through the studio code flow (password and TOTP).
  # Without a database URL the builder answers such a session 503 builder_not_configured.
  # The builder confirms the role in identity with the Zitadel token, so for this check
  # identity trusts Zitadel like on dev (as for the account delete above). Restored below.
  sproject=$(docker compose exec -T studio node -e "console.log(JSON.parse(require('node:fs').readFileSync('/studio/studio-client.json', 'utf8')).project_id ?? '')" 2>/dev/null | tr -d '\r' || true)
  sdomain=$(setting SYNTHWERK_ZITADEL_EXTERNAL_DOMAIN auth.localhost)
  if [[ -n "$sproject" ]] && SYNTHWERK_IDENTITY_OIDC_ISSUER="http://$sdomain:8080" SYNTHWERK_IDENTITY_OIDC_AUDIENCE="$sproject" \
    SYNTHWERK_IDENTITY_JWKS_URL="" docker compose up -d --wait --no-deps identity >/dev/null 2>&1; then
    out=$(docker compose run --rm --no-deps -e SYNTHWERK_STUDIO_URL=http://studio:3000 zitadel-bootstrap builder-check 2>&1 || true)
  else
    out="identity did not start with the Zitadel issuer (project '${sproject:-none}')"
  fi
  if docker compose up -d --wait --no-deps identity >/dev/null 2>&1; then pass "identity back on its own settings after the builder check"; else fail "identity did not come back after the builder check"; fi
  bstatus=$(grep '"builder-check: studio session' <<<"$out" | grep -o '"builder_status":[0-9]*' | cut -d: -f2 | head -n 1 || true)
  bcode=$(grep '"builder-check: studio session' <<<"$out" | grep -o '"code":"[^"]*"' | cut -d'"' -f4 | head -n 1 || true)
  if [[ "$out" == *'"msg":"builder-check ok"'* ]]; then
    pass "builder with a valid owner session: $bstatus${bcode:+ $bcode} (not 503)"
  else
    fail "builder-check: $(grep -o '"err":"[^"]*"' <<<"$out" | head -n 1 || echo "${out:0:160}") status '${bstatus:-none}' code '${bcode:-none}'"
  fi
  # Studio migrates on the first builder call that passes the identity check.
  if [[ "$bstatus" == 200 ]]; then
    tables=$(docker compose exec -T database psql -U "${SYNTHWERK_POSTGRES_USER:-synthwerk}" -d studio -tAc \
      "SELECT count(*) FROM pg_tables WHERE schemaname = 'public' AND tableowner = 'studio' AND tablename IN ('builder_pages', 'builder_page_versions', 'builder_events')" 2>/dev/null | tr -d '\r' || true)
    if [[ "$tables" == 3 ]]; then pass "studio migrated its database: 3 builder tables owned by studio"; else fail "builder tables in database studio: '${tables:-none}'"; fi
  else
    echo "info: identity did not confirm the owner (status ${bstatus:-none}), so studio ran no migration yet"
  fi
else
  echo "skip: studio is not running (docker compose --profile studio up --build --wait)"
fi

echo "# mascot: public answers with sources, per-client rate limit, no egress (synthwerk#48)"
MASCOT="$EDGE/mascot"
expect_status "mascot /healthz on the edge" 200 "$MASCOT/healthz"
mready=$(curl -s --max-time 10 "$MASCOT/readyz" || true)
if [[ "$mready" == *'"name":"model","status":"ok"'* && "$mready" == *'"name":"index","status":"ok"'* ]]; then pass "mascot /readyz: model and index ok"; else fail "mascot /readyz: ${mready:0:200}"; fi
expect_status "mascot routes other than answers and health are not on the edge" 404 "$MASCOT/openapi.json"
# ask <question>: POST /mascot/v1/answers through the edge; prints the body, then the status.
ask() {
  curl -s --max-time 30 -X POST -H 'Content-Type: application/json' \
    --data "{\"question\":\"$1\"}" -w '\n%{http_code}' "$MASCOT/v1/answers" || true
}
asked=0
for q in "Welcher Anbieter verschickt E-Mails?" "Which email provider sends the invites?"; do
  out=$(ask "$q")
  asked=$((asked + 1))
  if [[ "${out##*$'\n'}" == 200 && "$out" == *'"found":true'* && "$out" == *'"path":"docs/infrastructure.md"'* \
    && "$out" == *'"url":"https://github.com/VelimirMueller/synthwerk/blob/'* ]]; then
    pass "mascot answers '$q' with a cited passage of docs/infrastructure.md"
  else
    fail "mascot answer to '$q': ${out:0:240}"
  fi
done
# The mascot allows 6 questions per client a minute. The edge sets X-Forwarded-For to the
# client address and the mascot trusts it from the edge only: the 7th question gets 429.
codes=""
while ((asked < 6)); do
  codes+="$(ask "Was ist Synthwerk?" | tail -n 1) "
  asked=$((asked + 1))
done
headers=$(curl -s -o /dev/null -D - --max-time 30 -X POST -H 'Content-Type: application/json' \
  --data '{"question":"Was ist Synthwerk?"}' "$MASCOT/v1/answers" | tr -d '\r' || true)
code7=$(head -n 1 <<<"$headers" | awk '{print $2}')
if [[ "$codes" == "200 200 200 200 " && "$code7" == 429 ]] && grep -qi '^retry-after: [0-9]' <<<"$headers"; then
  pass "questions 1-6 from one client: 200; the 7th in the minute: 429 with Retry-After"
else
  fail "mascot rate limit: questions 3-6 '$codes', 7th '$code7'"
fi
# A forged X-Forwarded-For does not make a new client: the edge drops it.
expect_status "7th question with a forged X-Forwarded-For: still 429" 429 -X POST -H 'Content-Type: application/json' \
  -H 'X-Forwarded-For: 198.51.100.7' --data '{"question":"Was ist Synthwerk?"}' "$MASCOT/v1/answers"
# Another client (a container on the edge network) still gets an answer: the limit counts
# real client addresses, not the edge address.
edge_net=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{println $k}}{{end}}' "$(docker compose ps -q edge)" | grep '_edge$' || true)
code=$(docker run --rm --network "$edge_net" curlimages/curl:8.17.0 -s -o /dev/null -w '%{http_code}' --max-time 30 \
  -X POST -H 'Content-Type: application/json' --data '{"question":"Was ist Synthwerk?"}' http://edge:8000/mascot/v1/answers 2>/dev/null || true)
if [[ "$code" == 200 ]]; then pass "a second client gets 200 while the first is limited"; else fail "second client: '$code' (want 200)"; fi

echo "# mascot CORS: the public site origins only"
# mascot_cors <origin>: the Access-Control-Allow-Origin of a preflight on /v1/answers, or empty.
mascot_cors() {
  curl -s -o /dev/null -D - --max-time 10 -X OPTIONS -H "Origin: $1" -H 'Access-Control-Request-Method: POST' \
    -H 'Access-Control-Request-Headers: content-type' "$MASCOT/v1/answers" \
    | tr -d '\r' | awk -F': ' 'tolower($1) == "access-control-allow-origin" { print $2 }'
}
site=$(setting SYNTHWERK_MASCOT_CORS_ORIGINS '["http://localhost:3000","http://localhost:3001"]' | grep -oE 'https?://[^"]+' | tail -n 1)
if [[ -n "$site" && "$(mascot_cors "$site")" == "$site" ]]; then pass "mascot preflight from the public site $site: allowed"; else fail "mascot preflight from '$site' has no allow-origin"; fi
if [[ -z "$(mascot_cors https://evil.example)" ]]; then pass "mascot preflight from a foreign origin: no allow-origin"; else fail "mascot allows a foreign origin"; fi

echo "# mascot isolation: no route out, only the edge on its network"
mascot_id=$(docker compose ps -q mascot)
mascot_nets=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{println $k}}{{end}}' "$mascot_id" | grep . || true)
if [[ "$mascot_nets" == *_mascot && $(grep -c . <<<"$mascot_nets") == 1 ]]; then pass "mascot is on one network: $mascot_nets"; else fail "mascot networks: $(tr '\n' ' ' <<<"$mascot_nets")"; fi
internal=$(docker network inspect -f '{{.Internal}}' "$mascot_nets" 2>/dev/null || true)
if [[ "$internal" == true ]]; then pass "network $mascot_nets is internal"; else fail "network $mascot_nets internal: '$internal'"; fi
members=$(docker network inspect -f '{{range .Containers}}{{println .Name}}{{end}}' "$mascot_nets" 2>/dev/null | grep . | sed -E 's/^.*-(edge|mascot)-[0-9]+$/\1/' | sort | tr '\n' ' ' || true)
if [[ "$members" == "edge mascot " ]]; then pass "only the edge and the mascot are on $mascot_nets"; else fail "members of $mascot_nets: '$members'"; fi
# From inside the container: no default route, no DNS for outside or stack names, no TCP out.
# The edge (172.31.251.2:8000) is the control: the same probe must reach it.
probe=$(docker compose exec -T mascot python -c '
import socket
def dns(h):
    try:
        socket.getaddrinfo(h, 443)
        return "resolved"
    except OSError:
        return "fail"
def tcp(ip, port):
    s = socket.socket()
    s.settimeout(3)
    try:
        s.connect((ip, port))
        return "connected"
    except OSError:
        return "fail"
    finally:
        s.close()
routes = [l.split()[1] for l in open("/proc/net/route").read().splitlines()[1:]]
print("route default", "yes" if "00000000" in routes else "no")
for h in ("example.com", "github.com", "database", "bus", "telemetry", "identity"):
    print("dns", h, dns(h))
for ip, port in (("1.1.1.1", 443), ("8.8.8.8", 53), ("140.82.112.3", 443), ("172.31.251.1", 80)):
    print("tcp", ip, port, tcp(ip, port))
print("tcp edge", tcp("172.31.251.2", 8000))
' 2>&1 | tr -d '\r' || true)
if grep -qx 'route default no' <<<"$probe"; then pass "mascot has no default route"; else fail "mascot routes: $(grep '^route' <<<"$probe" || echo "${probe:0:200}")"; fi
if grep -qx 'tcp edge connected' <<<"$probe"; then pass "control: the probe reaches the edge"; else fail "probe cannot reach the edge: ${probe:0:200}"; fi
leaks=$(grep -E '^(dns .* resolved|tcp [0-9.]+ [0-9]+ connected)$' <<<"$probe" || true)
dns_checked=$(grep -c '^dns ' <<<"$probe" || true)
tcp_checked=$(grep -cE '^tcp [0-9.]+ [0-9]+ ' <<<"$probe" || true)
if [[ -z "$leaks" && "$dns_checked" == 6 && "$tcp_checked" == 4 ]]; then
  pass "mascot cannot resolve outside or stack names (6) and cannot connect out (4 addresses)"
else
  fail "mascot egress: ${leaks:-checks dns=$dns_checked tcp=$tcp_checked} ${probe:0:200}"
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

echo "# no full client IP in stored spans (#3)"
# tempo <curl args...>: GET on the Tempo API inside the telemetry container.
tempo() { docker compose exec -T telemetry curl -s --max-time 5 "$@" 2>/dev/null || true; }
# span_ips <trace JSON>: every client or peer address value in the trace, one per line.
span_ips() {
  { grep -oE '"key": ?"(client\.address|network\.peer\.address|http\.client_ip|net\.sock\.peer\.addr|net\.peer\.ip)", ?"value": ?\{"stringValue": ?"[^"]*"' <<<"$1" || true; } \
    | sed -E 's/.*"stringValue": ?"([^"]*)"$/\1/'
}
# full_ips <values>: the values that are not an IPv4 /24 (a.b.c.0). Prints a count only.
full_ips() { { grep -cvE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.0$' <<<"$1" || true; } | head -n 1; }
# A span with a known address (documentation range, RFC 5737/3849) through OTLP HTTP.
probe_trace=$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')
probe_span=$(od -An -tx1 -N8 /dev/urandom | tr -d ' \n')
now_ns="$(date +%s)000000000"
probe_body='{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"stack-test-probe"}}]},"scopeSpans":[{"spans":[{"traceId":"'$probe_trace'","spanId":"'$probe_span'","name":"probe","kind":2,"startTimeUnixNano":"'$now_ns'","endTimeUnixNano":"'$now_ns'","attributes":[{"key":"client.address","value":{"stringValue":"203.0.113.57"}},{"key":"network.peer.address","value":{"stringValue":"2001:db8::57"}}]}]}]}]}'
expect_status "OTLP span with a client IP is accepted" 200 -H 'Content-Type: application/json' \
  --data "$probe_body" "http://127.0.0.1:${SYNTHWERK_TELEMETRY_OTLP_HTTP_PORT:-4318}/v1/traces"
probe=""
for _ in $(seq 1 30); do
  probe=$(tempo "http://127.0.0.1:3200/api/traces/$probe_trace")
  [[ "$probe" == *stack-test-probe* ]] && break
  sleep 2
done
ips=$(span_ips "$probe")
if [[ "$probe" != *'"name":"probe"'* ]]; then
  fail "probe span (trace $probe_trace) not in Tempo within 60 s"
elif [[ "$ips" == "203.0.113.0" && "$probe" != *203.0.113.57* && "$probe" != *2001:db8::57* ]]; then pass "stored probe span: IPv4 truncated to /24, IPv6 dropped"; else fail "stored probe span addresses: '${ips//$'\n'/ }', want only 203.0.113.0"; fi
# A real request through the edge: no span of its trace holds a full client IP.
# $canary is "canary" plus digits: safe in the path and in the TraceQL string.
ip_path="/stub/ip-check-$canary"
expect_status "request for the edge span check" 200 "$EDGE$ip_path"
edge_trace=""
for _ in $(seq 1 30); do
  edge_trace=$(tempo -G --data-urlencode "q={ resource.service.name = \"synthwerk-edge\" && span.url.path = \"$ip_path\" }" \
    --data-urlencode limit=1 http://127.0.0.1:3200/api/search | { grep -oE '"traceID": ?"[0-9a-f]+"' || true; } | head -n 1 | cut -d'"' -f4)
  [[ -n "$edge_trace" ]] && break
  sleep 2
done
if [[ -n "$edge_trace" ]]; then
  ips=$(span_ips "$(tempo "http://127.0.0.1:3200/api/traces/$edge_trace")")
  n=$(full_ips "$ips")
  # Values are not printed: a full one would be the IP of the test runner.
  if [[ -n "$ips" && "$n" == 0 ]]; then pass "edge trace in Tempo: $(wc -l <<<"$ips" | tr -d ' ') client address(es), all truncated to /24"; else fail "edge trace in Tempo: ${n:-?} full client address(es) of $(grep -c . <<<"$ips" || true)"; fi
else
  fail "no edge trace for $ip_path in Tempo within 60 s"
fi

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
# Pulse checks the token on every /v1 route since synthwerk#40 (operator, owner or admin).
# Older images ignore the header. Without the stack issuer the stream goes without a token.
pulse_auth=()
if tests/stack/issuer.sh active; then
  tok_operator=$(tests/stack/issuer.sh mint stack-operator stack-platform operator)
  pulse_auth=(-H "Authorization: Bearer $tok_operator")
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$EDGE/pulse/v1/metrics" || true)
  if [[ "$code" == 404 ]]; then
    echo "skip: the pulse image has no metrics routes (synthwerk#40)"
  else
    expect_status "pulse metrics without a token: 401" 401 "$EDGE/pulse/v1/metrics"
    expect_status "pulse metrics as a member: 403" 403 -H "Authorization: Bearer $(tests/stack/issuer.sh mint stack-member stack-platform member)" "$EDGE/pulse/v1/metrics"
    expect_status "pulse health stream without a token: 401" 401 --max-time 3 "$EDGE/pulse/v1/health/stream"
    # Edge numbers come from Prometheus (traefik_service_*): the requests above are traffic.
    services=""
    for _ in $(seq 1 30); do
      services=$(curl -s --max-time 10 "${pulse_auth[@]}" "$EDGE/pulse/v1/metrics" | { grep -oE '"service": ?"[^"]+"' || true; } | wc -l | tr -d ' ')
      ((services > 0)) && break
      sleep 2
    done
    if ((services > 0)); then pass "pulse metrics as operator: $services edge services from Prometheus"; else fail "pulse metrics as operator: no edge service from Prometheus within 60 s"; fi
  fi
fi
stream_log=$(mktemp)
curl -sN --max-time 180 "${pulse_auth[@]}" "$EDGE/pulse/v1/health/stream" >"$stream_log" 2>/dev/null &
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
