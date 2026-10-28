#!/usr/bin/env bash
# Local token issuer for the stack test (synthwerk#32): an RSA key, its JWKS served
# by the stub at http://stub:8080/issuer/jwks.json, and tokens signed with openssl.
# llm trusts it only when .env points llm at it (setup writes those lines), never
# by default. The private key stays in tests/stack/.issuer-key.pem (git-ignored,
# outside the served folder).
#
#   tests/stack/issuer.sh setup            key + JWKS, llm env lines in .env (before compose up)
#   tests/stack/issuer.sh mint <sub> <org> print a token valid for 5 minutes
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
  # One pass: drop the five keys, then append them. A last line without a newline
  # would otherwise merge with the first appended key.
  grep -v -E '^SYNTHWERK_LLM_(OIDC_ISSUER|OIDC_AUDIENCE|JWKS_URL|PROVIDER|FAKE_DELAY)=' .env >.env.tmp || true
  [[ -s .env.tmp && -n "$(tail -c 1 .env.tmp)" ]] && printf '\n' >>.env.tmp
  printf '%s\n' \
    "SYNTHWERK_LLM_OIDC_ISSUER=$ISSUER" \
    "SYNTHWERK_LLM_OIDC_AUDIENCE=$AUDIENCE" \
    "SYNTHWERK_LLM_JWKS_URL=http://stub:8080/issuer/jwks.json" \
    "SYNTHWERK_LLM_PROVIDER=fake" \
    "SYNTHWERK_LLM_FAKE_DELAY=300ms" >>.env.tmp
  mv .env.tmp .env
  echo "issuer ready: llm trusts $ISSUER (fake provider)"
}

mint() {
  local sub=$1 org=$2 now head body sig
  now=$(date +%s)
  head=$(printf '{"alg":"RS256","typ":"JWT","kid":"%s"}' "$KID" | b64url)
  body=$(printf '{"iss":"%s","aud":["%s"],"sub":"%s","urn:zitadel:iam:user:resourceowner:id":"%s","client_id":"stack-test","iat":%d,"nbf":%d,"exp":%d}' \
    "$ISSUER" "$AUDIENCE" "$sub" "$org" "$now" "$now" $((now + 300)) | b64url)
  sig=$(printf '%s.%s' "$head" "$body" | openssl dgst -sha256 -sign "$KEY" | b64url)
  printf '%s.%s.%s\n' "$head" "$body" "$sig"
}

case "${1:-}" in
  setup) setup ;;
  mint) mint "${2:?sub}" "${3:?org}" ;;
  active) grep -q "^SYNTHWERK_LLM_OIDC_ISSUER=$ISSUER$" .env 2>/dev/null ;;
  *) echo "usage: $0 setup | mint <sub> <org> | active" >&2; exit 2 ;;
esac
