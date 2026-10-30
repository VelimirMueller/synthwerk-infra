#!/usr/bin/env bash
# Point identity, llm and pulse at the audience of real Zitadel tokens: the id of the
# project synthwerk-api. Zitadel access tokens carry aud [client id, project id], never
# synthwerk-api, so the compose default fits only the stack test issuer (tests/stack/issuer.sh).
# The project id is made per Zitadel volume, so it cannot be a compose default.
#
# Usage: scripts/zitadel-audience.sh   (after "docker compose up --wait"; writes three lines
#        to .env and recreates identity, llm and pulse). Not with the stack test issuer.
set -euo pipefail
cd "$(dirname "$0")/.."

if tests/stack/issuer.sh active; then
  echo "zitadel-audience: .env points the services at the stack test issuer (tests/stack/issuer.sh); remove those lines first" >&2
  exit 1
fi
# zitadel-bootstrap writes the project id to the volume zitadel-hooks (mode 0444).
pid=$(docker run --rm -v synthwerk_zitadel-hooks:/h:ro --entrypoint cat curlimages/curl:8.17.0 /h/project-id 2>/dev/null || true)
if [[ ! "$pid" =~ ^[0-9]+$ ]]; then
  echo "zitadel-audience: no project id in the volume zitadel-hooks yet (run docker compose up --wait first)" >&2
  exit 1
fi

touch .env
# One pass: drop the keys, then append them (same rule as issuer.sh).
grep -v -E '^SYNTHWERK_(IDENTITY|LLM|PULSE)_OIDC_AUDIENCE=' .env >.env.tmp || true
[[ -s .env.tmp && -n "$(tail -c 1 .env.tmp)" ]] && printf '\n' >>.env.tmp
printf '%s\n' \
  "SYNTHWERK_IDENTITY_OIDC_AUDIENCE=$pid" \
  "SYNTHWERK_LLM_OIDC_AUDIENCE=$pid" \
  "SYNTHWERK_PULSE_OIDC_AUDIENCE=$pid" >>.env.tmp
chmod 600 .env.tmp
mv .env.tmp .env
# up, not restart: restart keeps the old environment.
docker compose up -d --wait --no-deps identity llm pulse
echo "zitadel-audience: identity, llm and pulse take Zitadel tokens with audience $pid (project synthwerk-api)"
