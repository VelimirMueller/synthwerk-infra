#!/usr/bin/env bash
# Write .env from .env.example. Every empty *_PASSWORD gets a random dev-only value.
# An existing .env stays as it is. The script never prints a password.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ -f .env ]]; then
  echo ".env exists. Delete it to generate new values."
  exit 0
fi

umask 077
while IFS= read -r line || [[ -n "$line" ]]; do
  if [[ "$line" =~ ^(SYNTHWERK_[A-Z0-9_]*_PASSWORD)=$ ]]; then
    printf '%s=%s\n' "${BASH_REMATCH[1]}" "$(openssl rand -hex 24)"
  else
    printf '%s\n' "$line"
  fi
done < .env.example > .env
echo "Wrote .env with generated dev passwords."
