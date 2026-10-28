#!/usr/bin/env bash
# Local token issuer for the stack test (synthwerk#32): an RSA key, its JWKS served
# by the stub at http://stub:8080/issuer/jwks.json, and tokens signed with openssl.
# llm and identity trust it only when .env points them at it (setup writes those
# lines), never by default. The private key stays in tests/stack/.issuer-key.pem (git-ignored,
# outside the served folder).
#
#   tests/stack/issuer.sh setup            key + JWKS, llm and identity env lines in .env (before compose up)
#   tests/stack/issuer.sh mint <sub> <org> [role,...]
#                                          print a token valid for 5 minutes; roles granted in <org>
#   tests/stack/issuer.sh active           exit 0 when .env points llm at this issuer
set -euo pipefail
cd "$(dirname "$0")/../.."

ISSUER=http://stack-test-issuer
AUDIENCE=synthwerk-api
KID=stack-test-1
KEY=tests/stack/.issuer-key.pem
JWKS=tests/stack/issuer/jwks.json

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

setup() {
  umask 077
  [[ -f "$KEY" ]] || openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$KEY" 2>/dev/null
  local n
  n=$(openssl rsa -in "$KEY" -noout -modulus | cut -d= -f2 | xxd -r -p | b64url)
  umask 022
  printf '{"keys":[{"kty":"RSA","kid":"%s","alg":"RS256","use":"sig","n":"%s","e":"AQAB"}]}\n' "$KID" "$n" >"$JWKS"
  chmod 644 "$JWKS"
  touch .env
  # One pass: drop the eight keys, then append them. A last line without a newline
  # would otherwise merge with the first appended key.
  grep -v -E '^SYNTHWERK_(LLM_(OIDC_ISSUER|OIDC_AUDIENCE|JWKS_URL|PROVIDER|FAKE_DELAY)|IDENTITY_(OIDC_ISSUER|OIDC_AUDIENCE|JWKS_URL))=' .env >.env.tmp || true
  [[ -s .env.tmp && -n "$(tail -c 1 .env.tmp)" ]] && printf '\n' >>.env.tmp
  printf '%s\n' \
    "SYNTHWERK_LLM_OIDC_ISSUER=$ISSUER" \
    "SYNTHWERK_LLM_OIDC_AUDIENCE=$AUDIENCE" \
    "SYNTHWERK_LLM_JWKS_URL=http://stub:8080/issuer/jwks.json" \
    "SYNTHWERK_LLM_PROVIDER=fake" \
    "SYNTHWERK_LLM_FAKE_DELAY=300ms" \
    "SYNTHWERK_IDENTITY_OIDC_ISSUER=$ISSUER" \
    "SYNTHWERK_IDENTITY_OIDC_AUDIENCE=$AUDIENCE" \
    "SYNTHWERK_IDENTITY_JWKS_URL=http://stub:8080/issuer/jwks.json" >>.env.tmp
  mv .env.tmp .env
  echo "issuer ready: llm and identity trust $ISSUER (llm: fake provider)"
}

mint() {
  local sub=$1 org=$2 roles=${3:-} now head body sig claim="" r
  now=$(date +%s)
  # Zitadel roles claim: {"<role>":{"<org>":"<org>.stack.test"}}.
  if [[ -n "$roles" ]]; then
    for r in ${roles//,/ }; do claim+="${claim:+,}\"$r\":{\"$org\":\"$org.stack.test\"}"; done
    claim=",\"urn:zitadel:iam:org:project:roles\":{$claim}"
  fi
  head=$(printf '{"alg":"RS256","typ":"JWT","kid":"%s"}' "$KID" | b64url)
  body=$(printf '{"iss":"%s","aud":["%s"],"sub":"%s","urn:zitadel:iam:user:resourceowner:id":"%s","client_id":"stack-test","iat":%d,"nbf":%d,"exp":%d%s}' \
    "$ISSUER" "$AUDIENCE" "$sub" "$org" "$now" "$now" $((now + 300)) "$claim" | b64url)
  sig=$(printf '%s.%s' "$head" "$body" | openssl dgst -sha256 -sign "$KEY" | b64url)
  printf '%s.%s.%s\n' "$head" "$body" "$sig"
}

case "${1:-}" in
  setup) setup ;;
  mint) mint "${2:?sub}" "${3:?org}" "${4:-}" ;;
  active) grep -q "^SYNTHWERK_LLM_OIDC_ISSUER=$ISSUER$" .env 2>/dev/null ;;
  *) echo "usage: $0 setup | mint <sub> <org> [role,...] | active" >&2; exit 2 ;;
esac
