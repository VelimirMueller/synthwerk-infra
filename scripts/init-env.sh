#!/usr/bin/env bash
# Write .env from .env.example. Every empty *_PASSWORD and *_SECRET gets a random
# dev-only value, every empty *_MASTERKEY one with exactly 32 characters.
# An existing .env keeps its values: keys missing there are appended.
# The script never prints a value.
set -euo pipefail
cd "$(dirname "$0")/.."

# fill <line>: print the line, with a generated value for an empty secret key.
fill() {
  local line=$1
  if [[ "$line" =~ ^(SYNTHWERK_[A-Z0-9_]*_MASTERKEY)=$ ]]; then
    printf '%s=%s\n' "${BASH_REMATCH[1]}" "$(openssl rand -hex 16)"
  elif [[ "$line" =~ ^(SYNTHWERK_[A-Z0-9_]*_(PASSWORD|SECRET))=$ ]]; then
    printf '%s=%s\n' "${BASH_REMATCH[1]}" "$(openssl rand -hex 24)"
  else
    printf '%s\n' "$line"
  fi
}

umask 077
if [[ ! -f .env ]]; then
  while IFS= read -r line || [[ -n "$line" ]]; do
    fill "${line%$'\r'}"
  done < .env.example > .env
  echo "Wrote .env with generated dev passwords."
  exit 0
fi

added=0
# A last line without a newline would swallow the first appended key.
[[ -s .env && -n "$(tail -c 1 .env)" ]] && printf '\n' >> .env
while IFS= read -r line || [[ -n "$line" ]]; do
  line=${line%$'\r'}
  [[ "$line" =~ ^(SYNTHWERK_[A-Z0-9_]*)= ]] || continue
  grep -q "^${BASH_REMATCH[1]}=" .env && continue
  ((added == 0)) && printf '\n# Added by scripts/init-env.sh\n' >> .env
  fill "$line" >> .env
  added=$((added + 1))
done < .env.example
if ((added > 0)); then
  echo ".env exists. Appended $added missing key(s)."
else
  echo ".env exists and has every key. Delete it to generate new values."
fi
