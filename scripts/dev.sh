#!/usr/bin/env bash
# One entry point for the local stack.
#
#   scripts/dev.sh up [--ollama]    write .env if needed, build and start every service, print the URLs
#   scripts/dev.sh check            stack test + pulse status per service
#   scripts/dev.sh urls             print every local URL
#   scripts/dev.sh status           docker compose ps
#   scripts/dev.sh logs [service]   follow the logs
#   scripts/dev.sh down [--volumes] stop the stack (--volumes also deletes all data)
#
# The script never prints a secret value.
set -euo pipefail
cd "$(dirname "$0")/.."

# envval <key> <default>: value of <key> in .env, or <default>.
envval() {
  local v=""
  [[ -f .env ]] && v=$(grep -E "^$1=" .env | tail -n 1 | cut -d= -f2- || true)
  printf '%s' "${v:-$2}"
}

urls() {
  local edge auth grafana mail
  edge="http://localhost:$(envval SYNTHWERK_EDGE_HTTP_PORT 8080)"
  auth="http://$(envval SYNTHWERK_ZITADEL_EXTERNAL_DOMAIN auth.localhost):$(envval SYNTHWERK_ZITADEL_EXTERNAL_PORT 8080)"
  grafana="http://localhost:$(envval SYNTHWERK_TELEMETRY_UI_PORT 3000)"
  mail="http://localhost:$(envval SYNTHWERK_MAILPIT_UI_PORT 8025)"
  cat <<EOF
# synthwerk local URLs (127.0.0.1 only)
edge         $edge
stub         $edge/stub
pulse        $edge/pulse/v1/health
pulse live   $edge/pulse/v1/health/stream
identity     $edge/identity/
llm          $edge/llm/
zitadel      $auth/ui/console
login        $auth/ui/v2/login
oidc         $auth/.well-known/openid-configuration
grafana      $grafana
mailpit      $mail
otlp         grpc localhost:$(envval SYNTHWERK_TELEMETRY_OTLP_GRPC_PORT 4317), http localhost:$(envval SYNTHWERK_TELEMETRY_OTLP_HTTP_PORT 4318)
postgres     docker compose exec database psql -U $(envval SYNTHWERK_POSTGRES_USER synthwerk) -d $(envval SYNTHWERK_POSTGRES_DB synthwerk)
nats         no host port; use a nats-box container on the compose network
EOF
}

pulse_summary() {
  local body
  body=$(curl -s --max-time 5 "http://127.0.0.1:$(envval SYNTHWERK_EDGE_HTTP_PORT 8080)/pulse/v1/health" || true)
  if [[ -z "$body" ]]; then
    echo "pulse: no answer"
    return 1
  fi
  if command -v jq >/dev/null; then
    printf '%s' "$body" | jq -r '.targets[] | "\(.status)\t\(.target)"' | column -t
  else
    printf '%s\n' "$body"
  fi
}

cmd=${1:-help}
[[ $# -gt 0 ]] && shift
case "$cmd" in
  up)
    profiles=()
    [[ "${1:-}" == "--ollama" ]] && profiles=(--profile ollama)
    scripts/init-env.sh
    docker compose ${profiles[@]+"${profiles[@]}"} up --build --wait --wait-timeout 300
    echo
    urls
    ;;
  check)
    # Show the pulse view also when the stack test fails, then exit with its result.
    rc=0
    tests/stack/stack_test.sh || rc=$?
    echo
    echo "# pulse"
    pulse_summary || true
    exit "$rc"
    ;;
  urls) urls ;;
  status) docker compose ps --all ;;
  logs) docker compose logs -f --tail 100 "$@" ;;
  down)
    if [[ "${1:-}" == "--volumes" ]]; then docker compose down --volumes; else docker compose down; fi
    ;;
  *)
    sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
    [[ "$cmd" == help || "$cmd" == -h || "$cmd" == --help ]]
    ;;
esac
